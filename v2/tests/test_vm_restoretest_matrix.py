"""VM-only end-to-end coverage for percentage and per-slice restore tests."""

# ruff: noqa: S101 - pytest uses assert for test expectations.

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from configparser import ConfigParser
from pathlib import Path
from types import SimpleNamespace

import pytest

import dar_backup.dar_backup as db
from dar_backup.command_runner import CommandRunner
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import inspect_archive_slices

pytestmark = [pytest.mark.integration, pytest.mark.slow]

_EXPECTED_FILE_COUNT = 1_000
_EXPECTED_MINIMUM_BYTES = 5 * 1024
_EXPECTED_MAXIMUM_BYTES = 5 * 1024 * 1024
_SLICE_SIZE = "500M"


def _required_vm_dataset() -> tuple[Path, Path, str]:
    """Return and validate the full-matrix dataset environment.

    Returns:
        Dataset directory, manifest path, and transferred archive SHA-256.

    Raises:
        ValueError: If VM dataset environment values are incomplete or invalid.
    """
    dataset_text = os.environ.get("DAR_BACKUP_VM_DATASET_DIR")
    manifest_text = os.environ.get("DAR_BACKUP_VM_DATASET_MANIFEST")
    archive_sha256 = os.environ.get("DAR_BACKUP_VM_DATASET_SHA256")
    if dataset_text is None and manifest_text is None and archive_sha256 is None:
        pytest.skip("large restore-test dataset is provided only by the full VM matrix")
    if not dataset_text or not manifest_text or not archive_sha256:
        raise ValueError("VM restore-test dataset environment is incomplete")
    if re.fullmatch(r"[0-9a-f]{64}", archive_sha256) is None:
        raise ValueError("VM restore-test dataset digest is invalid")
    dataset_dir = Path(dataset_text)
    manifest_path = Path(manifest_text)
    if not dataset_dir.is_dir() or not manifest_path.is_file():
        raise ValueError("VM restore-test dataset paths do not exist")
    return dataset_dir, manifest_path, archive_sha256


def _load_dataset_manifest(dataset_dir: Path, manifest_path: Path) -> dict[str, object]:
    """Load and reconcile the transferred dataset manifest with the filesystem.

    Args:
        dataset_dir: Extracted payload directory.
        manifest_path: Extracted JSON manifest.

    Returns:
        Validated manifest object.

    Raises:
        ValueError: If the manifest or extracted payload does not match the contract.
    """
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read VM restore-test dataset manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValueError("VM restore-test dataset manifest must be an object")  # noqa: TRY004 - invalid external input.
    expected = {
        "format_version": 1,
        "file_count": _EXPECTED_FILE_COUNT,
        "minimum_bytes": _EXPECTED_MINIMUM_BYTES,
        "maximum_bytes": _EXPECTED_MAXIMUM_BYTES,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise ValueError(f"VM restore-test dataset manifest has invalid {key}")
    records = manifest.get("files")
    if not isinstance(records, list) or len(records) != _EXPECTED_FILE_COUNT:
        raise ValueError("VM restore-test dataset manifest has invalid file records")
    payload_files = sorted(path for path in dataset_dir.iterdir() if path.is_file())
    if len(payload_files) != _EXPECTED_FILE_COUNT:
        raise ValueError(
            f"VM restore-test dataset contains {len(payload_files)} files, expected {_EXPECTED_FILE_COUNT}"
        )
    actual_total = sum(path.stat().st_size for path in payload_files)
    if manifest.get("total_bytes") != actual_total:
        raise ValueError("VM restore-test dataset total size does not match its manifest")
    if any(not _EXPECTED_MINIMUM_BYTES <= path.stat().st_size <= _EXPECTED_MAXIMUM_BYTES for path in payload_files):
        raise ValueError("VM restore-test dataset contains an out-of-range file")
    expected_sizes: dict[str, int] = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(  # noqa: TRY004 - invalid external input.
                f"VM restore-test dataset file record {index} is invalid"
            )
        path = record.get("path")
        size_bytes = record.get("size_bytes")
        digest = record.get("sha256")
        if not isinstance(path, str) or not path.startswith("restoretest-dataset/"):
            raise ValueError(f"VM restore-test dataset file record {index} has an invalid path")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool):
            raise ValueError(  # noqa: TRY004 - invalid external input.
                f"VM restore-test dataset file record {index} has an invalid size"
            )
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError(f"VM restore-test dataset file record {index} has an invalid digest")
        filename = Path(path).name
        if filename in expected_sizes:
            raise ValueError(f"VM restore-test dataset manifest duplicates {filename}")
        expected_sizes[filename] = size_bytes
    actual_sizes = {path.name: path.stat().st_size for path in payload_files}
    if actual_sizes != expected_sizes:
        raise ValueError("VM restore-test dataset files do not match manifest paths and sizes")
    return manifest


def _write_test_configuration(
    root: Path,
    dataset_dir: Path,
    *,
    restore_dir: Path,
    percentage: float,
    maximum_files: int,
    cover_slices: bool,
) -> tuple[Path, Path, Path]:
    """Write one complete configuration and backup definition.

    Args:
        root: Test-owned configuration and output root.
        dataset_dir: Read-only VM dataset directory.
        restore_dir: Restore destination for this verification mode.
        percentage: Configured restore-test percentage.
        maximum_files: Percentage sample cap.
        cover_slices: Whether to add files needed for data-slice coverage.

    Returns:
        Configuration, definition, and darrc paths.

    Raises:
        OSError: If a required file or directory cannot be created.
    """
    backup_dir = root / "backups"
    definition_dir = root / "backup.d"
    backup_dir.mkdir(parents=True, exist_ok=True)
    definition_dir.mkdir(parents=True, exist_ok=True)
    restore_dir.mkdir(parents=True, exist_ok=True)

    config = ConfigParser()
    config["MISC"] = {
        "LOGFILE_LOCATION": str(root / "dar-backup.log"),
        "MAX_SIZE_VERIFICATION_MB": "5",
        "MIN_SIZE_VERIFICATION_MB": "0",
        "NO_FILES_VERIFICATION": "5",
        "RESTORETEST_PERCENT": str(percentage),
        "RESTORETEST_MAX_FILES": str(maximum_files),
        "RESTORETEST_COVER_SLICES": "true" if cover_slices else "false",
        "COMMAND_TIMEOUT_SECS": "7200",
        "RESTORE_OWNERSHIP": "no",
    }
    config["DIRECTORIES"] = {
        "BACKUP_DIR": str(backup_dir),
        "BACKUP.D_DIR": str(definition_dir),
        "DATA_DIR": str(dataset_dir),
        "TEST_RESTORE_DIR": str(restore_dir),
    }
    config["AGE"] = {"DIFF_AGE": "30", "INCR_AGE": "15"}
    config["PAR2"] = {"ERROR_CORRECTION_PERCENT": "5", "ENABLED": "false"}
    config_path = root / "dar-backup.conf"
    with config_path.open("w", encoding="utf-8") as config_file:
        config.write(config_file)

    definition_path = definition_dir / "vm-large-restoretest"
    definition_path.write_text(
        f"-R {dataset_dir.parent}\n-s {_SLICE_SIZE}\n-z1\n-am\n-g {dataset_dir.name}\n",
        encoding="utf-8",
    )
    darrc_path = root / ".darrc"
    darrc_path.write_text(
        "restore-options:\n"
        "--comparison-field=ignore-owner\n"
        "compress-exclusion:\n"
        "verbose:\n",
        encoding="utf-8",
    )
    return config_path, definition_path, darrc_path


def _run_direct_dar_creation(
    archive_path: Path,
    definition_path: Path,
    darrc_path: Path,
) -> subprocess.CompletedProcess[str]:
    """Run the DAR creation command used by dar-backup for a tiny fixture.

    Args:
        archive_path: Output archive base path without a slice suffix.
        definition_path: DAR backup definition to load.
        darrc_path: DAR configuration containing requested targets.

    Returns:
        Completed DAR process with captured text output.

    Raises:
        RuntimeError: If DAR is unavailable in the test environment.
        OSError: If the archive output directory cannot be created.
    """
    dar_executable = shutil.which("dar")
    if dar_executable is None:
        raise RuntimeError("DAR executable is unavailable")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    return subprocess.run(  # noqa: S603 - installed DAR with test-owned arguments.
        [
            dar_executable,
            "-c",
            str(archive_path),
            "-N",
            "-B",
            str(darrc_path),
            "-B",
            str(definition_path),
            "-Q",
            "compress-exclusion",
            "verbose",
        ],
        capture_output=True,
        check=False,
        text=True,
    )


def test_vm_darrc_required_targets_allow_archive_creation(tmp_path: Path) -> None:
    """The generated VM DAR configuration must satisfy dar-backup's targets.

    Args:
        tmp_path: Isolated pytest directory.

    Returns:
        None.
    """
    dataset_dir = tmp_path / "input" / "restoretest-dataset"
    dataset_dir.mkdir(parents=True)
    (dataset_dir / "payload.bin").write_bytes(b"payload")
    _, definition_path, darrc_path = _write_test_configuration(
        tmp_path / "configuration",
        dataset_dir,
        restore_dir=tmp_path / "restore",
        percentage=10.0,
        maximum_files=1,
        cover_slices=False,
    )

    completed = _run_direct_dar_creation(
        tmp_path / "archive" / "positive",
        definition_path,
        darrc_path,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (tmp_path / "archive" / "positive.1.dar").is_file()


def test_vm_darrc_missing_targets_rejects_archive_creation(tmp_path: Path) -> None:
    """DAR must reject the incomplete target configuration that regressed.

    Args:
        tmp_path: Isolated pytest directory.

    Returns:
        None.
    """
    dataset_dir = tmp_path / "input" / "restoretest-dataset"
    dataset_dir.mkdir(parents=True)
    (dataset_dir / "payload.bin").write_bytes(b"payload")
    _, definition_path, darrc_path = _write_test_configuration(
        tmp_path / "configuration",
        dataset_dir,
        restore_dir=tmp_path / "restore",
        percentage=10.0,
        maximum_files=1,
        cover_slices=False,
    )
    darrc_path.write_text(
        "restore-options:\n--comparison-field=ignore-owner\n",
        encoding="utf-8",
    )

    completed = _run_direct_dar_creation(
        tmp_path / "archive" / "negative",
        definition_path,
        darrc_path,
    )

    assert completed.returncode != 0
    assert "compress-exclusion" in completed.stdout + completed.stderr
    assert not (tmp_path / "archive" / "negative.1.dar").exists()


def _find_full_archive(backup_dir: Path) -> Path:
    """Return the unique VM test FULL archive base path.

    Args:
        backup_dir: Directory populated by dar-backup.

    Returns:
        Archive path without its slice suffix.

    Raises:
        RuntimeError: If exactly one first slice is not present.
    """
    first_slices = sorted(backup_dir.glob("vm-large-restoretest_FULL_*.1.dar"))
    if len(first_slices) != 1:
        raise RuntimeError(f"Expected one VM FULL archive, found {len(first_slices)}")
    return Path(str(first_slices[0])[: -len(".1.dar")])


def test_vm_large_percentage_and_slice_restoretests(tmp_path: Path) -> None:
    """Create one VM-local archive and exercise both advanced restore modes.

    Args:
        tmp_path: Isolated directory on the VM's native filesystem.

    Returns:
        None.
    """
    dataset_dir, manifest_path, archive_sha256 = _required_vm_dataset()
    manifest = _load_dataset_manifest(dataset_dir, manifest_path)
    dar_backup_executable = shutil.which("dar-backup")
    if dar_backup_executable is None:
        raise RuntimeError("Installed dar-backup executable is unavailable")
    percentage_restore_dir = tmp_path / "restore-percentage"
    config_path, definition_path, darrc_path = _write_test_configuration(
        tmp_path,
        dataset_dir,
        restore_dir=percentage_restore_dir,
        percentage=10.0,
        maximum_files=100,
        cover_slices=False,
    )

    completed = subprocess.run(  # noqa: S603 - installed project CLI with test-owned arguments.
        [
            dar_backup_executable,
            "--full-backup",
            "-d",
            "vm-large-restoretest",
            "--config-file",
            str(config_path),
            "--darrc",
            str(darrc_path),
            "--verbose",
            "--log-level",
            "debug",
            "--log-stdout",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=7200,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "Restore-test sampling: eligible=1000 configured=10% calculated=100 capped=100" in output
    assert "Restore-test selection complete: selected=100 batch-restored=100" in output
    artifact_dir_text = os.environ.get("DAR_BACKUP_VM_ARTIFACT_DIR")
    artifact_dir = Path(artifact_dir_text) if artifact_dir_text else None
    if artifact_dir is not None:
        if not artifact_dir.is_dir():
            raise ValueError(f"VM artifact directory does not exist: {artifact_dir}")
        (artifact_dir / "large-vm-percentage-command.log").write_text(
            output,
            encoding="utf-8",
        )
        shutil.copyfile(
            manifest_path,
            artifact_dir / "large-vm-dataset-manifest.json",
        )

    archive_path = _find_full_archive(tmp_path / "backups")
    inventory = inspect_archive_slices(str(archive_path))
    assert inventory.is_contiguous_from_one is True
    assert len(inventory.slice_numbers) >= 5

    slice_restore_dir = tmp_path / "restore-slices"
    shutil.rmtree(percentage_restore_dir)
    config_path, definition_path, darrc_path = _write_test_configuration(
        tmp_path,
        dataset_dir,
        restore_dir=slice_restore_dir,
        percentage=1.0,
        maximum_files=10,
        cover_slices=True,
    )
    config = ConfigSettings(str(config_path))
    args = SimpleNamespace(verbose=True, do_not_compare=False, darrc=str(darrc_path))
    test_logger = logging.getLogger("vm_large_restoretest")
    command_logger = logging.getLogger("vm_large_restoretest.command_output")
    previous_logger = db.logger
    previous_runner = db.runner
    try:
        db.logger = test_logger
        db.runner = CommandRunner(logger=test_logger, command_logger=command_logger)
        result = db.verify(
            args,
            str(archive_path),
            str(definition_path),
            config,
        )
    finally:
        db.logger = previous_logger
        db.runner = previous_runner

    assert result.passed is True
    assert result.restore_test_passed is True
    assert result.files_verified >= 10
    assert len(result.predicted_slice_numbers) >= 4
    assert result.predicted_slice_numbers == result.extracted_slice_numbers
    assert result.predicted_slice_numbers == result.verified_slice_numbers
    assert all(item.content_matched is True for item in result.file_evidence)
    assert all(item.metadata_matched is True for item in result.file_evidence)

    if artifact_dir is not None:
        evidence = {
            "dataset_archive_sha256": archive_sha256,
            "dataset_file_count": manifest["file_count"],
            "dataset_total_bytes": manifest["total_bytes"],
            "physical_slice_numbers": list(inventory.slice_numbers),
            "percentage_files_verified": 100,
            "coverage_files_verified": result.files_verified,
            "predicted_slice_numbers": list(result.predicted_slice_numbers),
            "extracted_slice_numbers": list(result.extracted_slice_numbers),
            "verified_slice_numbers": list(result.verified_slice_numbers),
        }
        artifact_path = artifact_dir / "large-vm-restoretest.json"
        artifact_path.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
