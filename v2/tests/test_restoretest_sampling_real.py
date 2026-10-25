"""Real-DAR coverage for opt-in percentage and slice-aware restore tests."""

import logging
import json
import os
import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator

import pytest

import dar_backup.dar_backup as db
from dar_backup.command_runner import CommandRunner
from dar_backup.restoretest_catalog import RestoreTestCatalogIndex
from dar_backup.restoretest_catalog import parse_slicing_listing_evidence
from dar_backup.restoretest_catalog import parse_slicing_listing_line
from dar_backup.util import BackupError
from dar_backup.util import inspect_archive_slices


pytestmark = [pytest.mark.integration, pytest.mark.slow]


def _require_dar() -> str:
    """Return the DAR executable or skip when the integration dependency is absent.

    Returns:
        Absolute path to the DAR executable.
    """
    dar_path = shutil.which("dar")
    if dar_path is None:
        pytest.skip("dar is required for real restore-test sampling coverage")
    return dar_path


def _create_archive(
    source_dir: Path,
    archive_path: Path,
    slice_size: str = "2K",
    reference_archive: Path | None = None,
) -> None:
    """Create a small real multi-slice DAR archive.

    Args:
        source_dir: Directory whose contents should be archived.
        archive_path: Output archive path without a slice suffix.
        slice_size: DAR slice-size argument.
        reference_archive: Optional archive base used for DIFF/INCR comparison.

    Returns:
        None.

    Raises:
        RuntimeError: If DAR cannot create the archive.
    """
    command = [
        _require_dar(),
        "-c",
        str(archive_path),
        "-R",
        str(source_dir),
        "-s",
        slice_size,
        "-Q",
    ]
    if reference_archive is not None:
        command.extend(["-A", str(reference_archive)])
    completed = subprocess.run(  # noqa: S603 -- fixed executable and test-owned paths
        command,
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"DAR archive creation failed: {completed.stderr}")


def _create_isolated_catalogue(
    reference_archive: Path,
    archive_path: Path,
    slice_size: str = "2K",
) -> None:
    """Create a real isolated catalogue with no independently saved payload.

    Args:
        reference_archive: Source archive whose catalogue DAR should isolate.
        archive_path: Output isolated archive path without a slice suffix.
        slice_size: DAR slice-size argument.

    Returns:
        None.

    Raises:
        RuntimeError: If DAR cannot isolate the catalogue.
    """
    completed = subprocess.run(  # noqa: S603 -- fixed executable and test-owned paths
        [
            _require_dar(),
            "-C",
            str(archive_path),
            "-A",
            str(reference_archive),
            "-s",
            slice_size,
            "-Q",
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"DAR catalogue isolation failed: {completed.stderr}")


def _create_batch_failure_dar_wrapper(
    wrapper_dir: Path,
    real_dar: str,
    invocation_log: Path,
) -> None:
    """Create a DAR wrapper that rejects only multi-selection extraction.

    Args:
        wrapper_dir: Directory in which to create an executable named ``dar``.
        real_dar: Absolute path to the real DAR executable.
        invocation_log: JSON-lines destination for every wrapper invocation.

    Returns:
        None.

    Raises:
        ValueError: If an input path is invalid.
        OSError: If the wrapper cannot be written or made executable.
    """
    if not wrapper_dir.is_dir():
        raise ValueError(f"Wrapper directory does not exist: {wrapper_dir}")
    if not Path(real_dar).is_file():
        raise ValueError(f"Real DAR executable does not exist: {real_dar}")
    if invocation_log.exists():
        raise ValueError(f"Invocation log already exists: {invocation_log}")

    wrapper_path = wrapper_dir / "dar"
    wrapper_path.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "import os\n"
        "import sys\n"
        f"real_dar = {json.dumps(real_dar)}\n"
        f"invocation_log = {json.dumps(str(invocation_log))}\n"
        "arguments = sys.argv[1:]\n"
        "with open(invocation_log, 'a', encoding='utf-8') as log_file:\n"
        "    log_file.write(json.dumps(arguments) + '\\n')\n"
        "if '-x' in arguments and arguments.count('-g') > 1:\n"
        "    print('deliberate multi-file extraction failure', file=sys.stderr)\n"
        "    raise SystemExit(7)\n"
        "os.execv(real_dar, [real_dar, *arguments])\n",
        encoding="utf-8",
    )
    wrapper_path.chmod(0o755)


@contextmanager
def _temporary_path_prefix(directory: Path) -> Iterator[None]:
    """Temporarily prepend one existing directory to ``PATH``.

    Args:
        directory: Directory containing test-owned executable wrappers.

    Yields:
        Control while the modified ``PATH`` is active.

    Raises:
        ValueError: If ``directory`` does not exist.
    """
    if not directory.is_dir():
        raise ValueError(f"PATH prefix directory does not exist: {directory}")
    previous_path = os.environ.get("PATH")
    current_path = previous_path or os.defpath
    os.environ["PATH"] = f"{directory}{os.pathsep}{current_path}"
    try:
        yield
    finally:
        if previous_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = previous_path


def _preserve_vm_catalogue_artifacts(archive_path: Path, label: str) -> None:
    """Preserve raw DAR interfaces when the VM runner requests evidence.

    Args:
        archive_path: Archive base path without a slice suffix.
        label: Stable fixture label used in artifact filenames.

    Returns:
        None.

    Raises:
        RuntimeError: If DAR cannot produce either requested representation.
        ValueError: If the artifact directory or label is invalid.
    """
    artifact_dir_text = os.environ.get("DAR_BACKUP_VM_ARTIFACT_DIR")
    if artifact_dir_text is None:
        return
    artifact_dir = Path(artifact_dir_text)
    if not artifact_dir.is_dir():
        raise ValueError(f"VM artifact directory does not exist: {artifact_dir}")
    if not re.fullmatch(r"[a-z0-9-]+", label):
        raise ValueError(f"Invalid VM artifact label: {label!r}")

    version_result = subprocess.run(  # noqa: S603 -- resolved DAR executable
        [_require_dar(), "-V"],
        capture_output=True,
        check=False,
        text=True,
    )
    (artifact_dir / f"{label}-dar-version.txt").write_text(
        version_result.stdout + version_result.stderr,
        encoding="utf-8",
    )
    for representation, format_name, saved_only in (
        ("xml", "xml", False),
        ("slicing", "slicing", True),
    ):
        command = [
            _require_dar(),
            "-l",
            str(archive_path),
            "--noconf",
            "-am",
        ]
        if saved_only:
            command.append("-as")
        command.extend([f"-T{format_name}", "-Q"])
        completed = subprocess.run(  # noqa: S603 -- resolved DAR executable
            command,
            capture_output=True,
            check=False,
            text=True,
        )
        (artifact_dir / f"{label}-{representation}.txt").write_text(
            completed.stdout,
            encoding="utf-8",
        )
        (artifact_dir / f"{label}-{representation}-stderr.txt").write_text(
            completed.stderr,
            encoding="utf-8",
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"DAR {representation} artifact command failed: {completed.stderr}"
            )
        if representation == "slicing":
            row_evidence: list[dict[str, object]] = []
            for line_number, line in enumerate(completed.stdout.splitlines(), start=1):
                parsed_evidence = parse_slicing_listing_evidence(line)
                if parsed_evidence is None:
                    continue
                payload_mapping = parse_slicing_listing_line(line)
                row_evidence.append(
                    {
                        "line_number": line_number,
                        "path": parsed_evidence.path,
                        "data_state": parsed_evidence.data_state,
                        "ea_state": parsed_evidence.ea_state,
                        "fsa_state": parsed_evidence.fsa_state,
                        "permission": parsed_evidence.permission,
                        "reported_slice_spec": parsed_evidence.slice_spec,
                        "later_saved_markers": parsed_evidence.later_saved_markers,
                        "payload_slice_numbers": (
                            sorted(payload_mapping[1])
                            if payload_mapping is not None
                            else []
                        ),
                    }
                )
            (artifact_dir / f"{label}-slicing-records.json").write_text(
                json.dumps(row_evidence, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )


def _verification_inputs(
    tmp_path: Path,
    source_dir: Path,
    archive_path: Path,
    *,
    max_size_mb: int,
    percentage: float | None,
) -> tuple[SimpleNamespace, SimpleNamespace, Path]:
    """Build CLI/config inputs for a direct call to ``verify``.

    Args:
        tmp_path: Isolated test directory.
        source_dir: Archived source root.
        archive_path: Archive path without a slice suffix.
        max_size_mb: Largest file eligible for restore testing.
        percentage: Optional percentage sampling value.

    Returns:
        CLI arguments, configuration namespace, and backup definition path.
    """
    restore_dir = tmp_path / "restore"
    restore_dir.mkdir()
    darrc = tmp_path / ".darrc"
    darrc.write_text("restore-options:\n", encoding="utf-8")
    backup_definition = tmp_path / "definition.dcf"
    backup_definition.write_text(f"-R {source_dir}\n-s 2K\n", encoding="utf-8")

    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=str(darrc))
    config = SimpleNamespace(
        test_restore_dir=str(restore_dir),
        command_timeout_secs=30,
        backup_dir=str(archive_path.parent),
        min_size_verification_mb=0,
        max_size_verification_mb=max_size_mb,
        no_files_verification=1,
        restoretest_exclude_prefixes=[],
        restoretest_exclude_suffixes=[],
        restoretest_exclude_regex=None,
        restoretest_percent=percentage,
        restoretest_max_files=10,
        restoretest_cover_slices=True,
        restore_ownership=False,
    )
    return args, config, backup_definition


def _run_verify_with_real_runner(
    args: SimpleNamespace,
    config: SimpleNamespace,
    archive_path: Path,
    backup_definition: Path,
    artifact_label: str | None = None,
) -> db.VerifyResult:
    """Run verification with real commands while restoring module globals.

    Args:
        args: CLI argument namespace.
        config: Restore-test configuration namespace.
        archive_path: Archive path without a slice suffix.
        backup_definition: DAR backup definition containing the source root.
        artifact_label: Optional VM artifact label for raw command output.

    Returns:
        Verification result returned by ``verify``.
    """
    previous_runner = db.runner
    previous_logger = db.logger
    test_logger = logging.getLogger("restoretest_sampling_real")
    command_logger = logging.getLogger("restoretest_sampling_real.command_output")
    previous_command_logger_level = command_logger.level
    artifact_handler: logging.FileHandler | None = None
    try:
        if artifact_label is not None:
            if not re.fullmatch(r"[a-z0-9-]+", artifact_label):
                raise ValueError(f"Invalid VM artifact label: {artifact_label!r}")
            artifact_dir_text = os.environ.get("DAR_BACKUP_VM_ARTIFACT_DIR")
            if artifact_dir_text is not None:
                artifact_dir = Path(artifact_dir_text)
                if not artifact_dir.is_dir():
                    raise ValueError(
                        f"VM artifact directory does not exist: {artifact_dir}"
                    )
                artifact_handler = logging.FileHandler(
                    artifact_dir / f"{artifact_label}-dar-command-output.log",
                    encoding="utf-8",
                )
                artifact_handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
                command_logger.addHandler(artifact_handler)
                command_logger.setLevel(logging.DEBUG)
        db.logger = test_logger
        db.runner = CommandRunner(logger=test_logger, command_logger=command_logger)
        return db.verify(args, str(archive_path), str(backup_definition), config)
    finally:
        db.runner = previous_runner
        db.logger = previous_logger
        if artifact_handler is not None:
            command_logger.removeHandler(artifact_handler)
            artifact_handler.close()
        command_logger.setLevel(previous_command_logger_level)


def _preserve_vm_verification_evidence(
    result: db.VerifyResult,
    label: str,
) -> None:
    """Write exact selected-file and slice evidence for VM review.

    Args:
        result: Completed restore-test verification result.
        label: Stable artifact label used in the JSON filename.

    Returns:
        None.

    Raises:
        ValueError: If the artifact directory or label is invalid.
    """
    artifact_dir_text = os.environ.get("DAR_BACKUP_VM_ARTIFACT_DIR")
    if artifact_dir_text is None:
        return
    artifact_dir = Path(artifact_dir_text)
    if not artifact_dir.is_dir():
        raise ValueError(f"VM artifact directory does not exist: {artifact_dir}")
    if not re.fullmatch(r"[a-z0-9-]+", label):
        raise ValueError(f"Invalid VM artifact label: {label!r}")

    evidence = {
        "passed": result.passed,
        "restore_test_passed": result.restore_test_passed,
        "files_verified": result.files_verified,
        "predicted_slice_numbers": list(result.predicted_slice_numbers),
        "extracted_slice_numbers": list(result.extracted_slice_numbers),
        "verified_slice_numbers": list(result.verified_slice_numbers),
        "files": [
            {
                "path": item.path,
                "predicted_slice_numbers": list(item.predicted_slice_numbers),
                "extraction_attempted": item.extraction_attempted,
                "extraction_succeeded": item.extraction_succeeded,
                "target_present": item.target_present,
                "content_matched": item.content_matched,
                "metadata_matched": item.metadata_matched,
            }
            for item in result.file_evidence
        ],
    }
    (artifact_dir / f"{label}-verification.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_verify_percentage_and_slice_coverage_restores_real_multislice_archive(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Batch-restore and compare all percentage-selected files across real slices.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
        caplog: Pytest log capture fixture.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "first.bin").write_bytes(os.urandom(3 * 1024))
    (source_dir / "second file.bin").write_bytes(os.urandom(4 * 1024))
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path)
    args, config, backup_definition = _verification_inputs(
        tmp_path,
        source_dir,
        archive_path,
        max_size_mb=20,
        percentage=100.0,
    )

    with caplog.at_level(logging.ERROR):
        result = _run_verify_with_real_runner(
            args,
            config,
            archive_path,
            backup_definition,
            artifact_label="full-basic-verify",
        )
    _preserve_vm_verification_evidence(result, "full-basic-verify")

    assert result.passed is True
    assert result.restore_test_passed is True
    assert result.files_verified == 2
    assert result.predicted_slices > 0
    assert result.extracted_slices == result.predicted_slices
    assert result.verified_slices == result.predicted_slices
    assert result.predicted_slice_numbers == result.extracted_slice_numbers
    assert result.predicted_slice_numbers == result.verified_slice_numbers
    assert len(result.file_evidence) == 2
    assert all(item.extraction_attempted for item in result.file_evidence)
    assert all(item.extraction_succeeded for item in result.file_evidence)
    assert all(item.target_present for item in result.file_evidence)
    assert all(item.content_matched is True for item in result.file_evidence)
    assert all(item.metadata_matched is True for item in result.file_evidence)
    assert not any(
        "could not cover data-bearing slice(s)" in record.getMessage()
        for record in caplog.records
    )
    assert (Path(config.test_restore_dir) / "first.bin").read_bytes() == (source_dir / "first.bin").read_bytes()
    assert (Path(config.test_restore_dir) / "second file.bin").read_bytes() == (source_dir / "second file.bin").read_bytes()


def test_verify_failed_batch_falls_back_to_successful_individual_restores(
    tmp_path: Path,
) -> None:
    """Recover from a failed batch by extracting every selection individually.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "first.bin").write_bytes(os.urandom(3 * 1024))
    (source_dir / "second.bin").write_bytes(os.urandom(4 * 1024))
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path)
    args, config, backup_definition = _verification_inputs(
        tmp_path,
        source_dir,
        archive_path,
        max_size_mb=20,
        percentage=100.0,
    )
    wrapper_dir = tmp_path / "wrapper-bin"
    wrapper_dir.mkdir()
    invocation_log = tmp_path / "dar-invocations.jsonl"
    _create_batch_failure_dar_wrapper(
        wrapper_dir,
        _require_dar(),
        invocation_log,
    )

    with _temporary_path_prefix(wrapper_dir):
        result = _run_verify_with_real_runner(
            args,
            config,
            archive_path,
            backup_definition,
        )

    invocations = [
        json.loads(line)
        for line in invocation_log.read_text(encoding="utf-8").splitlines()
    ]
    extraction_invocations = [arguments for arguments in invocations if "-x" in arguments]
    batch_invocations = [
        arguments for arguments in extraction_invocations if arguments.count("-g") > 1
    ]
    individual_invocations = [
        arguments for arguments in extraction_invocations if arguments.count("-g") == 1
    ]

    assert len(batch_invocations) == 1
    assert len(individual_invocations) == 2
    assert result.passed is True
    assert result.restore_test_passed is True
    assert result.files_verified == 2
    assert result.predicted_slice_numbers == result.extracted_slice_numbers
    assert result.predicted_slice_numbers == result.verified_slice_numbers
    assert all(item.extraction_attempted for item in result.file_evidence)
    assert all(item.extraction_succeeded for item in result.file_evidence)
    assert all(item.target_present for item in result.file_evidence)
    assert all(item.content_matched is True for item in result.file_evidence)
    assert all(item.metadata_matched is True for item in result.file_evidence)


def test_verify_slice_coverage_rejects_slice_with_only_oversized_file(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fail rather than claim full coverage when filters exclude a data slice.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
        caplog: Pytest log capture fixture.

    Returns:
        None.

    Raises:
        AssertionError: If verification silently accepts incomplete slice coverage.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "eligible.bin").write_bytes(os.urandom(1024))
    (source_dir / "oversized.bin").write_bytes(os.urandom(2 * 1024 * 1024))
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path, slice_size="1M")
    args, config, backup_definition = _verification_inputs(
        tmp_path,
        source_dir,
        archive_path,
        max_size_mb=1,
        percentage=None,
    )

    with caplog.at_level(logging.ERROR):
        with pytest.raises(BackupError, match="could not cover data-bearing slice") as exc_info:
            _run_verify_with_real_runner(args, config, archive_path, backup_definition)

    message = str(exc_info.value)
    assert "MIN_SIZE_VERIFICATION_MB=0" in message
    assert "MAX_SIZE_VERIFICATION_MB=1" in message
    assert "inclusive size range" in message
    assert "RESTORETEST_EXCLUDE_*" in message
    assert any(
        record.levelno == logging.ERROR and record.getMessage() == message
        for record in caplog.records
    )


def test_verify_missing_interior_slice_cannot_report_coverage(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fail archive integrity before extraction when an interior slice is absent.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
        caplog: Pytest log capture fixture.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "payload.bin").write_bytes(os.urandom(16 * 1024))
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path)
    inventory = inspect_archive_slices(str(archive_path))
    assert len(inventory.slice_numbers) >= 3
    (tmp_path / "archive.2.dar").unlink()
    args, config, backup_definition = _verification_inputs(
        tmp_path,
        source_dir,
        archive_path,
        max_size_mb=20,
        percentage=100.0,
    )

    with caplog.at_level(
        logging.DEBUG,
        logger="restoretest_sampling_real.command_output",
    ):
        with pytest.raises(BackupError):
            _run_verify_with_real_runner(
                args,
                config,
                archive_path,
                backup_definition,
            )

    command_lines = [
        record.message for record in caplog.records if "Executing command:" in record.message
    ]
    assert any("dar -t" in line for line in command_lines)
    assert all("dar -x" not in line for line in command_lines)


def test_verify_corrupt_slice_cannot_report_coverage(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fail archive integrity before extraction when a slice is truncated.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
        caplog: Pytest log capture fixture.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "payload.bin").write_bytes(os.urandom(16 * 1024))
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path)
    slice_path = tmp_path / "archive.1.dar"
    slice_bytes = slice_path.read_bytes()
    assert len(slice_bytes) > 100
    slice_path.write_bytes(slice_bytes[:50])
    args, config, backup_definition = _verification_inputs(
        tmp_path,
        source_dir,
        archive_path,
        max_size_mb=20,
        percentage=100.0,
    )

    with caplog.at_level(
        logging.DEBUG,
        logger="restoretest_sampling_real.command_output",
    ):
        with pytest.raises(BackupError):
            _run_verify_with_real_runner(
                args,
                config,
                archive_path,
                backup_definition,
            )

    command_lines = [
        record.message for record in caplog.records if "Executing command:" in record.message
    ]
    assert any("dar -t" in line for line in command_lines)
    assert all("dar -x" not in line for line in command_lines)


def test_verify_percentage_batch_detects_source_content_mismatch(tmp_path: Path) -> None:
    """Compare batch-restored bytes and fail when the live source has changed.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source_file = source_dir / "changing.bin"
    source_file.write_bytes(b"original archive bytes")
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path)
    source_file.write_bytes(b"different live bytes!")
    args, config, backup_definition = _verification_inputs(
        tmp_path,
        source_dir,
        archive_path,
        max_size_mb=20,
        percentage=100.0,
    )

    result = _run_verify_with_real_runner(args, config, archive_path, backup_definition)

    assert result.passed is False
    assert result.restore_test_passed is False
    assert result.files_verified == 1
    assert result.predicted_slices > 0
    assert result.extracted_slices == result.predicted_slices
    assert result.verified_slices == 0
    assert len(result.file_evidence) == 1
    assert result.file_evidence[0].extraction_succeeded is True
    assert result.file_evidence[0].target_present is True
    assert result.file_evidence[0].content_matched is False
    assert result.file_evidence[0].metadata_matched is None


def test_verify_percentage_batch_detects_source_metadata_mismatch(
    tmp_path: Path,
) -> None:
    """Exclude extracted slices from verified coverage on metadata mismatch.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source_file = source_dir / "permissions.bin"
    source_file.write_bytes(b"content remains unchanged")
    source_file.chmod(0o640)
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path)
    source_file.chmod(0o600)
    args, config, backup_definition = _verification_inputs(
        tmp_path,
        source_dir,
        archive_path,
        max_size_mb=20,
        percentage=100.0,
    )

    result = _run_verify_with_real_runner(args, config, archive_path, backup_definition)

    assert result.passed is False
    assert result.restore_test_passed is False
    assert result.files_verified == 1
    assert result.predicted_slices > 0
    assert result.extracted_slice_numbers == result.predicted_slice_numbers
    assert result.verified_slice_numbers == ()
    assert len(result.file_evidence) == 1
    evidence = result.file_evidence[0]
    assert evidence.extraction_attempted is True
    assert evidence.extraction_succeeded is True
    assert evidence.target_present is True
    assert evidence.content_matched is True
    assert evidence.metadata_matched is False


def test_verify_legacy_configuration_uses_only_individual_restore_path(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Keep old configurations away from slicing and batched extraction.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
        caplog: Pytest log capture fixture.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "first.bin").write_bytes(os.urandom(1024))
    (source_dir / "second.bin").write_bytes(os.urandom(1024))
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path)
    args, config, backup_definition = _verification_inputs(
        tmp_path,
        source_dir,
        archive_path,
        max_size_mb=20,
        percentage=None,
    )
    del config.restoretest_percent
    del config.restoretest_max_files
    del config.restoretest_cover_slices
    config.no_files_verification = 2

    with caplog.at_level(logging.DEBUG, logger="restoretest_sampling_real"):
        result = _run_verify_with_real_runner(args, config, archive_path, backup_definition)

    # CommandRunner emits the command at both INFO and DEBUG when both logger
    # roles share the test logger.  Deduplicate those records before asserting
    # how many subprocesses were actually invoked.
    command_lines = sorted(
        {record.message for record in caplog.records if "Executing command:" in record.message}
    )
    restore_lines = [line for line in command_lines if "dar -x" in line]
    assert result.files_verified == 2
    assert len(restore_lines) == 2
    assert all(line.count(" -g ") == 1 for line in restore_lines)
    assert all("-Tslicing" not in line for line in command_lines)


def test_verify_percentage_without_coverage_does_not_use_slicing(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Keep percentage-only sampling independent of slicing text compatibility.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
        caplog: Pytest log capture fixture.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "first.bin").write_bytes(os.urandom(1024))
    (source_dir / "second.bin").write_bytes(os.urandom(1024))
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path)
    args, config, backup_definition = _verification_inputs(
        tmp_path,
        source_dir,
        archive_path,
        max_size_mb=20,
        percentage=50.0,
    )
    config.restoretest_cover_slices = False

    with caplog.at_level(logging.DEBUG, logger="restoretest_sampling_real"):
        result = _run_verify_with_real_runner(args, config, archive_path, backup_definition)

    command_lines = {
        record.message for record in caplog.records if "Executing command:" in record.message
    }
    assert result.files_verified == 1
    assert all("-Tslicing" not in line for line in command_lines)


def test_catalog_index_reconciles_real_dar_xml_and_slicing(tmp_path: Path) -> None:
    """Reconcile independently generated XML and slicing views from real DAR.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "first.bin").write_bytes(os.urandom(3 * 1024))
    (source_dir / "second.bin").write_bytes(os.urandom(4 * 1024))
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path)
    _preserve_vm_catalogue_artifacts(archive_path, "full-basic")
    inventory = inspect_archive_slices(str(archive_path))
    test_logger = logging.getLogger("restoretest_sampling_real")
    command_runner = CommandRunner(logger=test_logger, command_logger=test_logger)

    with RestoreTestCatalogIndex(test_logger) as index:
        report = index.load_archive(
            str(archive_path),
            command_runner,
            frozenset(inventory.slice_numbers),
            timeout=30,
        )
        saved_files = list(index.iter_saved_files())

        artifact_dir_text = os.environ.get("DAR_BACKUP_VM_ARTIFACT_DIR")
        if artifact_dir_text is not None:
            parsed_evidence = {
                "dar_version": index.dar_version,
                "expected_saved_files": report.expected_saved_files,
                "mapped_saved_files": report.mapped_saved_files,
                "data_slices": sorted(report.data_slices),
                "non_data_slices": sorted(report.non_data_slices),
                "saved_paths": sorted(path for path, _size in saved_files),
                "slice_map": {
                    path: sorted(slices)
                    for path, slices in sorted(index.get_slice_map().items())
                },
            }
            (Path(artifact_dir_text) / "full-basic-parsed.json").write_text(
                json.dumps(parsed_evidence, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    assert report.expected_saved_files == 2
    assert report.mapped_saved_files == 2
    assert report.data_slices
    assert {path for path, _size in saved_files} == {"first.bin", "second.bin"}


def test_catalog_index_reconciles_spanning_zero_length_and_hardlink_files(
    tmp_path: Path,
) -> None:
    """Exercise real DAR boundary cases without version-specific branching.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "spanning.bin").write_bytes(os.urandom(8 * 1024))
    (source_dir / "empty.bin").touch()
    (source_dir / "odd & <name>.bin").write_bytes(b"special pathname")
    sparse_path = source_dir / "sparse.bin"
    with sparse_path.open("wb") as sparse_file:
        sparse_file.seek(64 * 1024)
        sparse_file.write(b"sparse tail")
    hardlink_source = source_dir / "hardlink-source.bin"
    hardlink_source.write_bytes(os.urandom(1024))
    os.link(hardlink_source, source_dir / "hardlink-alias.bin")
    archive_path = tmp_path / "archive"
    _create_archive(source_dir, archive_path)
    inventory = inspect_archive_slices(str(archive_path))
    test_logger = logging.getLogger("restoretest_sampling_real")
    command_runner = CommandRunner(logger=test_logger, command_logger=test_logger)

    with RestoreTestCatalogIndex(test_logger) as index:
        report = index.load_archive(
            str(archive_path),
            command_runner,
            frozenset(inventory.slice_numbers),
            timeout=30,
        )
        saved_files = list(index.iter_saved_files())
        slice_map = index.get_slice_map()

    expected_paths = {
        "empty.bin",
        "hardlink-alias.bin",
        "hardlink-source.bin",
        "odd & <name>.bin",
        "sparse.bin",
        "spanning.bin",
    }
    assert report.expected_saved_files == len(expected_paths)
    assert report.mapped_saved_files == len(expected_paths)
    assert {path for path, _size in saved_files} == expected_paths
    assert len(slice_map["spanning.bin"]) > 1


def test_catalog_index_classifies_isolated_catalogue_slice_as_non_data(
    tmp_path: Path,
) -> None:
    """Do not require a file restore from a physical catalogue-only slice.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "payload.bin").write_bytes(os.urandom(8 * 1024))
    full_archive = tmp_path / "full"
    _create_archive(source_dir, full_archive)
    isolated_archive = tmp_path / "isolated"
    _create_isolated_catalogue(full_archive, isolated_archive)
    _preserve_vm_catalogue_artifacts(isolated_archive, "isolated-catalogue")
    inventory = inspect_archive_slices(str(isolated_archive))
    test_logger = logging.getLogger("restoretest_sampling_real")
    command_runner = CommandRunner(logger=test_logger, command_logger=test_logger)

    with RestoreTestCatalogIndex(test_logger) as index:
        report = index.load_archive(
            str(isolated_archive),
            command_runner,
            frozenset(inventory.slice_numbers),
            timeout=30,
        )
        saved_files = list(index.iter_saved_files())

    assert report.expected_saved_files == 0
    assert report.mapped_saved_files == 0
    assert report.data_slices == frozenset()
    assert report.non_data_slices == frozenset(inventory.slice_numbers)
    assert saved_files == []


def test_catalog_index_reconciles_real_differential_and_incremental_states(
    tmp_path: Path,
) -> None:
    """Exclude referenced/deleted records from real DIFF/INCR reconciliation.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    unchanged = source_dir / "unchanged.bin"
    changed = source_dir / "changed.bin"
    deleted = source_dir / "deleted.bin"
    unchanged.write_bytes(b"unchanged")
    changed.write_bytes(b"full version")
    deleted.write_bytes(b"delete after full")
    full_archive = tmp_path / "full"
    _create_archive(source_dir, full_archive)

    changed.write_bytes(b"differential version with a new size")
    deleted.unlink()
    (source_dir / "differential-only.bin").write_bytes(b"new in differential")
    differential_archive = tmp_path / "differential"
    _create_archive(
        source_dir,
        differential_archive,
        reference_archive=full_archive,
    )

    (source_dir / "incremental-only.bin").write_bytes(b"new in incremental")
    incremental_archive = tmp_path / "incremental"
    _create_archive(
        source_dir,
        incremental_archive,
        reference_archive=differential_archive,
    )
    test_logger = logging.getLogger("restoretest_sampling_real")
    command_runner = CommandRunner(logger=test_logger, command_logger=test_logger)

    observed_saved_paths: dict[str, set[str]] = {}
    for label, archive_path in (
        ("differential", differential_archive),
        ("incremental", incremental_archive),
    ):
        inventory = inspect_archive_slices(str(archive_path))
        with RestoreTestCatalogIndex(test_logger) as index:
            report = index.load_archive(
                str(archive_path),
                command_runner,
                frozenset(inventory.slice_numbers),
                timeout=30,
            )
            observed_saved_paths[label] = {
                path for path, _size in index.iter_saved_files()
            }
        assert report.expected_saved_files == report.mapped_saved_files

    assert "changed.bin" in observed_saved_paths["differential"]
    assert "differential-only.bin" in observed_saved_paths["differential"]
    assert "unchanged.bin" not in observed_saved_paths["differential"]
    assert "deleted.bin" not in observed_saved_paths["differential"]
    assert observed_saved_paths["incremental"] == {"incremental-only.bin"}
