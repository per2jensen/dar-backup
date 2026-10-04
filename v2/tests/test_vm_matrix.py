"""Tests for the fresh Multipass VM compatibility controller."""

# ruff: noqa: S101 - pytest uses assert for test expectations.

from __future__ import annotations

import importlib.util
import json
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import pytest


pytestmark = pytest.mark.component


def _load_runner_module() -> ModuleType:
    """Load the standalone VM runner as a testable module.

    Returns:
        Loaded run_vm_matrix module.

    Raises:
        RuntimeError: If Python cannot construct a module spec.
    """
    runner_path = Path(__file__).parents[1] / "vm_test" / "run_vm_matrix.py"
    spec = importlib.util.spec_from_file_location("dar_backup_vm_matrix", runner_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load VM runner from {runner_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RUNNER = _load_runner_module()
PREPARE_CHECKOUT = Path(__file__).parents[1] / "vm_test" / "prepare_checkout.sh"
RUN_IN_GUEST = Path(__file__).parents[1] / "vm_test" / "run_in_guest.sh"


def _run_guest_result_writer(
    tmp_path: Path,
    manifest: str,
    guest_status: str,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Execute the production guest-result writer with a real manifest file.

    Args:
        tmp_path: Isolated pytest directory.
        manifest: Debian package manifest contents.
        guest_status: Guest test outcome passed to the result writer.

    Returns:
        Completed Python subprocess and expected result path.

    Raises:
        ValueError: If the manifest or guest status is empty.
        RuntimeError: If the embedded result writer cannot be located.
    """
    if not manifest:
        raise ValueError("Package manifest must not be empty")
    if not guest_status:
        raise ValueError("Guest status must not be empty")

    guest_script = RUN_IN_GUEST.read_text(encoding="utf-8")
    start_marker = "<<'PY'\n"
    end_marker = "\nPY\n}"
    before_writer, separator, after_start = guest_script.partition(start_marker)
    if not separator or "/usr/bin/python3 -" not in before_writer:
        raise RuntimeError("Cannot locate the guest-result writer start marker")
    writer_source, separator, _after_writer = after_start.partition(end_marker)
    if not separator:
        raise RuntimeError("Cannot locate the guest-result writer end marker")

    manifest_path = tmp_path / "dpkg-manifest.tsv"
    manifest_path.write_text(manifest, encoding="utf-8")
    result_path = tmp_path / "result.json"
    arguments = [
        sys.executable,
        "-",
        str(result_path),
        guest_status,
        "pytest and mypy passed",
        "0",
        "full",
        "a" * 40,
        "a" * 40,
        "2026-10-02T16:00:00Z",
        "2026-10-02T16:15:00Z",
        "Ubuntu 24.04.5 LTS",
        "6.8.0-test",
        "Python 3.12.3",
        "pytest 9.1.1",
        "dar version 2.7.13",
        "dar_manager version 1.9.0",
        "par2cmdline version 0.8.1",
        str(manifest_path),
    ]
    completed = subprocess.run(  # noqa: S603 - execute the repository-owned result writer.
        arguments,
        input=writer_source,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed, result_path


def _write_fake_multipass(
    directory: Path,
    guest_status: str,
    image_sha256: str = "b" * 64,
) -> Path:
    """Create a real subprocess executable implementing the used CLI surface.

    Args:
        directory: Isolated fake-command directory.
        guest_status: PASS or TEST_FAILED result emitted by the fake guest.
        image_sha256: Image digest returned by the fake info command.

    Returns:
        Executable fake Multipass path.
    """
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "guest-status.txt").write_text(guest_status + "\n", encoding="utf-8")
    (directory / "image-sha256.txt").write_text(image_sha256 + "\n", encoding="utf-8")
    executable = directory / "multipass"
    executable.write_text(
        r'''#!/usr/bin/env python3
import json
import os
import shutil
import stat
import sys
import tarfile
from pathlib import Path

root = Path(__file__).resolve().parent
state = root / "state"
state.mkdir(exist_ok=True)
args = sys.argv[1:]

def remote_path(value):
    instance, path = value.split(":", 1)
    return state / instance / path.lstrip("/")

if args[:3] == ["list", "--format", "json"]:
    instances = [{"name": path.name, "state": "Running"} for path in state.iterdir() if path.is_dir()]
    print(json.dumps({"list": instances}))
    raise SystemExit(0)

if args and args[0] == "launch":
    name = args[args.index("--name") + 1]
    (state / name / "home" / "ubuntu").mkdir(parents=True)
    print("\033[2K\033[0A\033[0ECreating instance")
    print("\033[2K\033[0A\033[0ELaunched instance")
    raise SystemExit(0)

if args and args[0] == "info":
    instance = args[-1]
    image_sha256 = (root / "image-sha256.txt").read_text(encoding="utf-8").strip()
    print(json.dumps({
        "errors": [],
        "info": {
            instance: {
                "image_hash": image_sha256,
                "image_release": "24.04 LTS",
            }
        },
    }))
    raise SystemExit(0)

if args and args[0] == "transfer":
    source, destination = args[1], args[2]
    if ":" in source:
        if destination != "-":
            print("host destinations must use stdout", file=sys.stderr)
            raise SystemExit(3)
        if not stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode):
            print("stdout transfer must use a pipe", file=sys.stderr)
            raise SystemExit(5)
        sys.stdout.buffer.write(remote_path(source).read_bytes())
    elif source == "-":
        if not stat.S_ISFIFO(os.fstat(sys.stdin.fileno()).st_mode):
            print("stdin transfer must use a pipe", file=sys.stderr)
            raise SystemExit(4)
        target = remote_path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(sys.stdin.buffer.read())
    else:
        print("host sources must use stdin", file=sys.stderr)
        raise SystemExit(3)
    raise SystemExit(0)

if args and args[0] == "exec":
    instance = args[1]
    command = args[3:]
    guest_home = state / instance / "home" / "ubuntu"
    if command and command[0] == "chmod":
        raise SystemExit(0)
    if command and command[0] == "tar":
        result_dir = guest_home / "results"
        with tarfile.open(guest_home / "results.tar.gz", "w:gz") as archive:
            for child in result_dir.rglob("*"):
                archive.add(child, arcname=child.relative_to(result_dir))
        raise SystemExit(0)

    status = (root / "guest-status.txt").read_text(encoding="utf-8").strip()
    result_dir = guest_home / "results"
    (result_dir / "pytest").mkdir(parents=True, exist_ok=True)
    if status == "PASS":
        exit_code = 0
        detail = "pytest and mypy passed"
    elif status == "TEST_FAILED":
        exit_code = 1
        detail = "pytest failed with status 1"
    else:
        exit_code = 2
        detail = "guest setup failed"
    (result_dir / "result.json").write_text(
        json.dumps({"status": status, "detail": detail, "exit_code": exit_code}),
        encoding="utf-8",
    )
    (result_dir / "guest-console.log").write_text(detail + "\n", encoding="utf-8")
    (result_dir / "pytest" / "pytest.txt").write_text(
        "all tests passed\n" if status == "PASS" else "FAILED test_example.py::test_failure\n",
        encoding="utf-8",
    )
    print(detail)
    raise SystemExit(exit_code)

if args and args[0] == "stop":
    raise SystemExit(0)

if args and args[0] == "delete":
    shutil.rmtree(state / args[-1])
    raise SystemExit(0)

print(f"unsupported fake multipass arguments: {args}", file=sys.stderr)
raise SystemExit(99)
''',
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


def _run_fake_image(
    tmp_path: Path,
    guest_status: str,
    image_sha256: str = "b" * 64,
) -> object:
    """Run one image through the controller using a fake external executable.

    Args:
        tmp_path: Isolated pytest directory.
        guest_status: Guest result to simulate.
        image_sha256: Image digest returned by the fake info command.

    Returns:
        Controller ImageRunResult.
    """
    fake_multipass = _write_fake_multipass(
        tmp_path / "fake-bin",
        guest_status,
        image_sha256,
    )
    archive_path = tmp_path / "source.tar"
    archive_path.write_bytes(b"source archive")
    guest_script = tmp_path / "run_in_guest.sh"
    guest_script.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    result_root = tmp_path / "results"
    result_root.mkdir()
    spec = RUNNER.ImageSpec(
        label="ubuntu-test",
        image="test-image",
        instance_name="dar-backup-test-fake",
        disk="1G",
        memory="1G",
        cpus=1,
    )
    return RUNNER.run_image(
        spec=spec,
        executor=RUNNER.CommandExecutor(str(fake_multipass)),
        archive_path=archive_path,
        guest_script=guest_script,
        mode="full",
        commit="a" * 40,
        result_root=result_root,
        keep_failed=False,
        keep_all=False,
    )


def _history_inputs(tmp_path: Path) -> tuple[object, object]:
    """Create one image specification and retrieved result for history tests.

    Args:
        tmp_path: Isolated pytest directory.

    Returns:
        A ``(spec, result)`` tuple with real JSON evidence files.
    """
    image_result_dir = tmp_path / "private-host-path" / "ubuntu-24.04"
    pytest_dir = image_result_dir / "pytest"
    pytest_dir.mkdir(parents=True)
    package_manifest = {
        "acl:amd64": "2.3.2-2",
        "dar:amd64": "2.7.13-2",
    }
    mypy_checks = {
        "python_version": "3.11",
        "platform": "linux",
        "enabled_error_codes": ["arg-type", "assignment"],
        "options": {
            "check_untyped_defs": False,
            "strict_optional": True,
        },
        "module_overrides": {
            "inputimeout": {
                "disable_error_code": [],
                "enable_error_code": [],
                "ignore_missing_imports": True,
            }
        },
    }
    (image_result_dir / "result.json").write_text(
        json.dumps(
            {
                "status": "PASS",
                "detail": "pytest and mypy passed",
                "exit_code": 0,
                "mode": "full",
                "application_commit": "a" * 40,
                "orchestration_commit": "a" * 40,
                "started_at": "2026-09-30T10:00:00Z",
                "finished_at": "2026-09-30T10:20:00Z",
                "os_release": "Ubuntu 24.04.5 LTS",
                "kernel": "6.8.0-test",
                "python": "Python 3.12.3",
                "pytest": "pytest 9.1.1",
                "dar": "dar version 2.7.13",
                "dar_manager": "dar_manager version 1.9.0",
                "par2": "par2cmdline version 0.8.1",
                "package_manifest": package_manifest,
                "package_manifest_sha256": RUNNER._package_manifest_sha256(
                    package_manifest
                ),
            }
        ),
        encoding="utf-8",
    )
    (pytest_dir / "mypy.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "passed",
                "version": "mypy 2.3.1 (compiled: yes)",
                "exit_code": 0,
                "target": "src/",
                "checks": mypy_checks,
                "checks_sha256": RUNNER._canonical_json_sha256(mypy_checks),
                "summary": {
                    "errors": 0,
                    "notes": 0,
                    "warnings": 0,
                    "files_with_errors": 0,
                    "diagnostics": 0,
                },
                "diagnostics": [],
                "stderr": "",
            }
        ),
        encoding="utf-8",
    )
    (pytest_dir / "dar-backup-1.1.12__pytest-full__test.json").write_text(
        json.dumps(
            {
                "duration": 1200.1254,
                "exitcode": 0,
                "summary": {
                    "passed": 1548,
                    "skipped": 2,
                    "total": 1550,
                    "collected": 1552,
                    "deselected": 2,
                },
                "tests": [
                    {
                        "nodeid": "tests/test_z.py::test_optional_binary",
                        "outcome": "skipped",
                        "setup": {
                            "outcome": "skipped",
                            "longrepr": (
                                "('/guest/tests/test_z.py', 12, "
                                "'Skipped: optional binary is unavailable')"
                            ),
                        },
                        "teardown": {"outcome": "passed"},
                    },
                    {
                        "nodeid": "tests/test_a.py::test_kernel_feature",
                        "outcome": "skipped",
                        "setup": {"outcome": "passed"},
                        "call": {
                            "outcome": "skipped",
                            "longrepr": (
                                "('/guest/tests/test_a.py', 34, "
                                "'Skipped: kernel feature is unavailable')"
                            ),
                        },
                        "teardown": {"outcome": "passed"},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    spec = RUNNER.ImageSpec(
        label="ubuntu-24.04",
        image="24.04",
        instance_name="dar-backup-test-2404",
        disk="30G",
        memory="4G",
        cpus=2,
    )
    result = RUNNER.ImageRunResult(
        label="ubuntu-24.04",
        status=RUNNER.PASS,
        guest_status=RUNNER.PASS,
        exit_code=0,
        result_directory=str(image_result_dir),
        instance_name="dar-backup-test-2404",
        instance_preserved=False,
        image_release="24.04 LTS",
        image_sha256="a" * 64,
        message="pytest and mypy passed",
    )
    return spec, result


def _history_record(tmp_path: Path, run_id: str = "run-1") -> dict[str, object]:
    """Build one valid VM history record.

    Args:
        tmp_path: Isolated pytest directory.
        run_id: Record identity.

    Returns:
        Valid schema-v2 history record.
    """
    spec, result = _history_inputs(tmp_path)
    return RUNNER.build_history_record(
        run_id=run_id,
        started_at="2026-09-30T10:00:00Z",
        finished_at="2026-09-30T10:20:01Z",
        mode="full",
        application_commit="a" * 40,
        orchestration_commit="a" * 40,
        specs=[spec],
        results=[result],
        completed=True,
        aborted_phase=None,
        exit_code=0,
    )


def test_run_image_passing_guest_returns_success_and_reports(tmp_path: Path) -> None:
    """A passing guest must return success with retrieved diagnostics."""
    result = _run_fake_image(tmp_path, "PASS")

    result_directory = Path(result.result_directory)
    assert result.status == RUNNER.PASS
    assert result.exit_code == 0
    assert result.image_release == "24.04 LTS"
    assert result.image_sha256 == "b" * 64
    assert RUNNER._overall_exit_code([result]) == 0
    assert (result_directory / "result.json").is_file()
    assert (result_directory / "pytest" / "pytest.txt").read_text(encoding="utf-8") == "all tests passed\n"
    assert not result.instance_preserved


def test_run_image_invalid_image_digest_returns_infrastructure_failure(
    tmp_path: Path,
) -> None:
    """A non-SHA-256 image identity must fail before guest tests start.

    Args:
        tmp_path: Isolated pytest directory.
    """
    result = _run_fake_image(tmp_path, "PASS", image_sha256="short-digest")

    assert result.status == RUNNER.INFRASTRUCTURE_FAILED
    assert result.image_release is None
    assert result.image_sha256 is None
    assert "image hash is not a full SHA-256" in result.message
    assert RUNNER._overall_exit_code([result]) == 2


def test_run_image_failing_guest_returns_failure_and_error_report(tmp_path: Path) -> None:
    """A pytest failure must signal failure while retaining its traceback report."""
    result = _run_fake_image(tmp_path, "TEST_FAILED")

    result_directory = Path(result.result_directory)
    pytest_output = (result_directory / "pytest" / "pytest.txt").read_text(encoding="utf-8")
    host_result = json.loads((result_directory / "host-result.json").read_text(encoding="utf-8"))
    assert result.status == RUNNER.TEST_FAILED
    assert result.exit_code == 1
    assert RUNNER._overall_exit_code([result]) == 1
    assert "FAILED test_example.py::test_failure" in pytest_output
    assert host_result["status"] == RUNNER.TEST_FAILED
    assert not result.instance_preserved


def test_run_image_setup_failure_returns_infrastructure_exit(tmp_path: Path) -> None:
    """A guest setup failure must use the infrastructure-failure contract."""
    result = _run_fake_image(tmp_path, "SETUP_FAILED")

    result_directory = Path(result.result_directory)
    assert result.status == RUNNER.INFRASTRUCTURE_FAILED
    assert result.guest_status == "SETUP_FAILED"
    assert result.exit_code == 2
    assert RUNNER._overall_exit_code([result]) == 2
    assert "guest setup failed" in (result_directory / "guest-console.log").read_text(encoding="utf-8")


def test_guest_result_writer_installed_package_preserves_pass_status(
    tmp_path: Path,
) -> None:
    """An installed-package status must not overwrite the guest test outcome.

    Args:
        tmp_path: Isolated pytest directory.
    """
    completed, result_path = _run_guest_result_writer(
        tmp_path,
        "acl\t2.3.2-2\tamd64\tii \nremoved\t1.0\tamd64\trc \n",
        RUNNER.PASS,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    assert payload["status"] == RUNNER.PASS
    assert payload["package_manifest"] == {"acl:amd64": "2.3.2-2"}


def test_guest_result_writer_malformed_package_manifest_fails(
    tmp_path: Path,
) -> None:
    """A malformed package manifest must fail without writing evidence.

    Args:
        tmp_path: Isolated pytest directory.
    """
    completed, result_path = _run_guest_result_writer(
        tmp_path,
        "acl\t2.3.2-2\tamd64\n",
        RUNNER.PASS,
    )

    assert completed.returncode != 0
    assert "malformed dpkg manifest line 1" in completed.stderr
    assert not result_path.exists()


def test_run_image_launch_progress_is_not_streamed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Multipass cursor animation must not corrupt the controller terminal."""
    result = _run_fake_image(tmp_path, "PASS")

    terminal_output = capsys.readouterr().out
    controller_log = Path(result.result_directory) / "controller-console.log"
    assert "Launching ubuntu-test (test-image) as dar-backup-test-fake..." in terminal_output
    assert "Launched: dar-backup-test-fake" in terminal_output
    assert "\033[2K" not in terminal_output
    assert "\033[2K" in controller_log.read_text(encoding="utf-8")


def test_command_executor_missing_input_file_raises_infrastructure_error(tmp_path: Path) -> None:
    """A missing streamed input must fail before Multipass starts."""
    fake_multipass = _write_fake_multipass(tmp_path / "fake-bin", "PASS")
    executor = RUNNER.CommandExecutor(str(fake_multipass))

    with pytest.raises(RUNNER.InfrastructureError, match="Command input is not a file"):
        executor.run(["transfer", "-", "test:/input"], input_path=tmp_path / "missing.tar")


def test_command_executor_failed_stdout_capture_preserves_destination(tmp_path: Path) -> None:
    """A failed streamed download must not replace an existing destination."""
    fake_multipass = _write_fake_multipass(tmp_path / "fake-bin", "PASS")
    executor = RUNNER.CommandExecutor(str(fake_multipass))
    destination = tmp_path / "result.tar.gz"
    destination.write_bytes(b"existing result")

    result = executor.run_with_stdout_file(["unsupported"], destination)

    assert result.returncode == 99
    assert "unsupported fake multipass arguments" in result.output
    assert destination.read_bytes() == b"existing result"
    assert list(tmp_path.glob(".result.tar.gz.*.tmp")) == []


def test_prepare_checkout_copies_root_readme_into_v2(tmp_path: Path) -> None:
    """Checkout preparation must replace the generated v2 README."""
    checkout_root = tmp_path / "dar-backup"
    project_dir = checkout_root / "v2"
    (project_dir / "tests").mkdir(parents=True)
    (checkout_root / "README.md").write_text("current root README\n", encoding="utf-8")
    (project_dir / "README.md").write_text("stale generated README\n", encoding="utf-8")
    (project_dir / "pyproject.toml").write_text("[build-system]\n", encoding="utf-8")

    result = subprocess.run(  # noqa: S603 - execute the repository-owned helper.
        ["/usr/bin/bash", str(PREPARE_CHECKOUT), str(checkout_root)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert (project_dir / "README.md").read_text(encoding="utf-8") == "current root README\n"


def test_prepare_checkout_missing_root_readme_fails(tmp_path: Path) -> None:
    """Checkout preparation must fail when the committed README is absent."""
    checkout_root = tmp_path / "dar-backup"
    project_dir = checkout_root / "v2"
    (project_dir / "tests").mkdir(parents=True)
    (project_dir / "pyproject.toml").write_text("[build-system]\n", encoding="utf-8")

    result = subprocess.run(  # noqa: S603 - execute the repository-owned helper.
        ["/usr/bin/bash", str(PREPARE_CHECKOUT), str(checkout_root)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "committed root README is missing or empty" in result.stderr


def test_history_record_contains_badge_evidence_without_private_paths(
    tmp_path: Path,
) -> None:
    """Tracked evidence must contain versions and counts but no host paths.

    Args:
        tmp_path: Isolated pytest directory.
    """
    record = _history_record(tmp_path)
    encoded = json.dumps(record)
    image = record["images"][0]

    assert record["schema_version"] == 2
    assert record["passed"] is True
    assert image["guest"]["dar"] == "dar version 2.7.13"
    assert image["guest"]["dar_manager"] == "dar_manager version 1.9.0"
    assert image["guest"]["package_manifest"] == {
        "acl:amd64": "2.3.2-2",
        "dar:amd64": "2.7.13-2",
    }
    assert image["guest"]["package_manifest_sha256"] == (
        RUNNER._package_manifest_sha256(image["guest"]["package_manifest"])
    )
    assert image["checks"]["mypy"]["status"] == "passed"
    assert image["checks"]["mypy"]["version"] == "mypy 2.3.1 (compiled: yes)"
    assert image["checks"]["mypy"]["checks"]["enabled_error_codes"] == [
        "arg-type",
        "assignment",
    ]
    assert image["checks"]["mypy"]["checks"]["module_overrides"]["inputimeout"] == {
        "disable_error_code": [],
        "enable_error_code": [],
        "ignore_missing_imports": True,
    }
    assert image["checks"]["mypy"]["summary"]["errors"] == 0
    assert image["image_release"] == "24.04 LTS"
    assert image["image_sha256"] == "a" * 64
    assert image["checks"]["pytest"]["summary"]["passed"] == 1548
    assert image["checks"]["pytest"]["duration_seconds"] == 1200.125
    assert image["checks"]["pytest"]["skips"] == [
        {
            "test": "tests/test_a.py::test_kernel_feature",
            "reason": "kernel feature is unavailable",
        },
        {
            "test": "tests/test_z.py::test_optional_binary",
            "reason": "optional binary is unavailable",
        },
    ]
    assert "private-host-path" not in encoded
    assert "/home/" not in encoded
    assert "/mnt/" not in encoded
    assert "dar-backup-test-2404" not in encoded


def test_history_record_skip_count_mismatch_raises(tmp_path: Path) -> None:
    """Every summarized skip must have corresponding named evidence.

    Args:
        tmp_path: Isolated pytest directory.
    """
    spec, result = _history_inputs(tmp_path)
    report_path = next(
        (Path(result.result_directory) / "pytest").glob(
            "dar-backup-*__pytest-*.json"
        )
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["tests"].pop()
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="skip detail count 1 does not match summary count 2"):
        RUNNER.build_history_record(
            run_id="run-missing-skip",
            started_at="2026-09-30T10:00:00Z",
            finished_at="2026-09-30T10:20:01Z",
            mode="full",
            application_commit="a" * 40,
            orchestration_commit="a" * 40,
            specs=[spec],
            results=[result],
            completed=True,
            aborted_phase=None,
            exit_code=0,
        )


def test_history_record_contains_pytest_failure_and_error_details(
    tmp_path: Path,
) -> None:
    """Failures from calls, setup, and collection must remain distinguishable.

    Args:
        tmp_path: Isolated pytest directory.
    """
    spec, result = _history_inputs(tmp_path)
    report_path = next(
        (Path(result.result_directory) / "pytest").glob(
            "dar-backup-*__pytest-*.json"
        )
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["exitcode"] = 1
    report["summary"]["passed"] -= 2
    report["summary"]["failed"] = 1
    report["summary"]["error"] = 1
    report["tests"].extend(
        [
            {
                "nodeid": "tests/test_backup.py::test_archive_created",
                "outcome": "failed",
                "setup": {"outcome": "passed"},
                "call": {
                    "outcome": "failed",
                    "crash": {
                        "path": "tests/test_backup.py",
                        "lineno": 42,
                        "message": "AssertionError: archive was not created",
                    },
                    "longrepr": "full traceback must not enter JSONL",
                },
                "teardown": {"outcome": "passed"},
            },
            {
                "nodeid": "tests/test_config.py::test_load_config",
                "outcome": "error",
                "setup": {
                    "outcome": "failed",
                    "crash": {
                        "path": "tests/conftest.py",
                        "lineno": 17,
                        "message": (
                            "FileNotFoundError: /tmp/pytest-of-ubuntu/pytest-44/"
                            "test_load_config0/fixture config is missing"
                        ),
                    },
                    "longrepr": "full setup traceback must not enter JSONL",
                },
                "teardown": {"outcome": "passed"},
            },
            {
                "nodeid": "tests/test_expected.py::test_known_problem",
                "outcome": "xfailed",
                "setup": {"outcome": "passed"},
                "call": {
                    "outcome": "failed",
                    "crash": {
                        "path": "tests/test_expected.py",
                        "lineno": 8,
                        "message": "AssertionError: expected failure",
                    },
                },
                "teardown": {"outcome": "passed"},
            },
        ]
    )
    report["collectors"] = [
        {
            "nodeid": "tests/test_import_error.py",
            "outcome": "failed",
            "result": [],
            "longrepr": (
                "tests/test_import_error.py:1: in <module>\n"
                "ImportError: optional test module could not be imported"
            ),
        }
    ]
    report_path.write_text(json.dumps(report), encoding="utf-8")
    result = replace(result, status=RUNNER.TEST_FAILED, guest_status=RUNNER.TEST_FAILED, exit_code=1)
    guest_path = Path(result.result_directory) / "result.json"
    guest = json.loads(guest_path.read_text(encoding="utf-8"))
    guest.update({"status": "TEST_FAILED", "exit_code": 1})
    guest_path.write_text(json.dumps(guest), encoding="utf-8")

    record = RUNNER.build_history_record(
        run_id="run-pytest-failures",
        started_at="2026-09-30T10:00:00Z",
        finished_at="2026-09-30T10:20:01Z",
        mode="full",
        application_commit="a" * 40,
        orchestration_commit="a" * 40,
        specs=[spec],
        results=[result],
        completed=True,
        aborted_phase=None,
        exit_code=1,
    )

    assert record["images"][0]["checks"]["pytest"]["failures"] == [
        {
            "test": "tests/test_backup.py::test_archive_created",
            "phase": "call",
            "kind": "failure",
            "message": "AssertionError: archive was not created",
        },
        {
            "test": "tests/test_config.py::test_load_config",
            "phase": "setup",
            "kind": "error",
            "message": (
                "FileNotFoundError: <pytest-tmp>/test_load_config0/"
                "fixture config is missing"
            ),
        },
        {
            "test": "tests/test_import_error.py",
            "phase": "collection",
            "kind": "collection_error",
            "message": "ImportError: optional test module could not be imported",
        },
    ]
    assert "full traceback" not in json.dumps(record)
    assert "test_known_problem" not in json.dumps(
        record["images"][0]["checks"]["pytest"]["failures"]
    )


def test_history_record_pytest_failure_count_mismatch_raises(tmp_path: Path) -> None:
    """Missing pytest failure details must fail evidence generation.

    Args:
        tmp_path: Isolated pytest directory.
    """
    spec, result = _history_inputs(tmp_path)
    report_path = next(
        (Path(result.result_directory) / "pytest").glob(
            "dar-backup-*__pytest-*.json"
        )
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["summary"]["failed"] = 1
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="failure detail count 0 does not match summary count 1",
    ):
        RUNNER.build_history_record(
            run_id="run-missing-pytest-failure",
            started_at="2026-09-30T10:00:00Z",
            finished_at="2026-09-30T10:20:01Z",
            mode="full",
            application_commit="a" * 40,
            orchestration_commit="a" * 40,
            specs=[spec],
            results=[result],
            completed=True,
            aborted_phase=None,
            exit_code=0,
        )


def test_history_record_modified_mypy_checks_raises(tmp_path: Path) -> None:
    """Mypy check configuration must match its canonical digest.

    Args:
        tmp_path: Isolated pytest directory.
    """
    spec, result = _history_inputs(tmp_path)
    report_path = Path(result.result_directory) / "pytest" / "mypy.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["checks"]["options"]["strict_optional"] = False
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="mypy checks SHA-256 mismatch"):
        RUNNER.build_history_record(
            run_id="run-modified-mypy-checks",
            started_at="2026-09-30T10:00:00Z",
            finished_at="2026-09-30T10:20:01Z",
            mode="full",
            application_commit="a" * 40,
            orchestration_commit="a" * 40,
            specs=[spec],
            results=[result],
            completed=True,
            aborted_phase=None,
            exit_code=0,
        )


def test_history_record_missing_mypy_report_raises(tmp_path: Path) -> None:
    """A completed guest result must include its mypy evidence artifact.

    Args:
        tmp_path: Isolated pytest directory.
    """
    spec, result = _history_inputs(tmp_path)
    report_path = Path(result.result_directory) / "pytest" / "mypy.json"
    report_path.unlink()

    with pytest.raises(ValueError, match="has no mypy evidence"):
        RUNNER.build_history_record(
            run_id="run-missing-mypy-report",
            started_at="2026-09-30T10:00:00Z",
            finished_at="2026-09-30T10:20:01Z",
            mode="full",
            application_commit="a" * 40,
            orchestration_commit="a" * 40,
            specs=[spec],
            results=[result],
            completed=True,
            aborted_phase=None,
            exit_code=0,
        )


def test_history_record_mypy_diagnostic_count_mismatch_raises(tmp_path: Path) -> None:
    """Mypy summary counts must agree with the diagnostic detail.

    Args:
        tmp_path: Isolated pytest directory.
    """
    spec, result = _history_inputs(tmp_path)
    report_path = Path(result.result_directory) / "pytest" / "mypy.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["summary"]["notes"] = 1
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="diagnostic counts do not match summary"):
        RUNNER.build_history_record(
            run_id="run-invalid-mypy-summary",
            started_at="2026-09-30T10:00:00Z",
            finished_at="2026-09-30T10:20:01Z",
            mode="full",
            application_commit="a" * 40,
            orchestration_commit="a" * 40,
            specs=[spec],
            results=[result],
            completed=True,
            aborted_phase=None,
            exit_code=0,
        )


def test_history_record_passing_image_without_digest_raises(tmp_path: Path) -> None:
    """Successful evidence must never omit immutable image provenance.

    Args:
        tmp_path: Isolated pytest directory.
    """
    spec, result = _history_inputs(tmp_path)
    result_without_provenance = replace(
        result,
        image_release=None,
        image_sha256=None,
    )

    with pytest.raises(ValueError, match="has no source-image provenance"):
        RUNNER.build_history_record(
            run_id="run-missing-image-digest",
            started_at="2026-09-30T10:00:00Z",
            finished_at="2026-09-30T10:20:01Z",
            mode="full",
            application_commit="a" * 40,
            orchestration_commit="a" * 40,
            specs=[spec],
            results=[result_without_provenance],
            completed=True,
            aborted_phase=None,
            exit_code=0,
        )


def test_history_record_modified_package_manifest_raises(tmp_path: Path) -> None:
    """A package version changed without a matching digest must fail closed.

    Args:
        tmp_path: Isolated pytest directory.
    """
    spec, result = _history_inputs(tmp_path)
    guest_path = Path(result.result_directory) / "result.json"
    guest = json.loads(guest_path.read_text(encoding="utf-8"))
    guest["package_manifest"]["dar:amd64"] = "unexpected-version"
    guest_path.write_text(json.dumps(guest), encoding="utf-8")

    with pytest.raises(ValueError, match="Package manifest SHA-256 mismatch"):
        RUNNER.build_history_record(
            run_id="run-modified-package-manifest",
            started_at="2026-09-30T10:00:00Z",
            finished_at="2026-09-30T10:20:01Z",
            mode="full",
            application_commit="a" * 40,
            orchestration_commit="a" * 40,
            specs=[spec],
            results=[result],
            completed=True,
            aborted_phase=None,
            exit_code=0,
        )


def test_history_record_completed_without_all_images_raises(
    tmp_path: Path,
) -> None:
    """A completed matrix cannot omit a configured image result.

    Args:
        tmp_path: Isolated pytest directory.
    """
    spec, _result = _history_inputs(tmp_path)

    with pytest.raises(ValueError, match="one result per image"):
        RUNNER.build_history_record(
            run_id="run-incomplete",
            started_at="2026-09-30T10:00:00Z",
            finished_at="2026-09-30T10:01:00Z",
            mode="full",
            application_commit="a" * 40,
            orchestration_commit="a" * 40,
            specs=[spec],
            results=[],
            completed=True,
            aborted_phase=None,
            exit_code=0,
        )


def test_history_record_guest_commit_mismatch_raises(tmp_path: Path) -> None:
    """Evidence from a different guest revision must fail closed.

    Args:
        tmp_path: Isolated pytest directory.
    """
    spec, result = _history_inputs(tmp_path)
    guest_path = Path(result.result_directory) / "result.json"
    guest = json.loads(guest_path.read_text(encoding="utf-8"))
    guest["application_commit"] = "b" * 40
    guest_path.write_text(json.dumps(guest), encoding="utf-8")

    with pytest.raises(ValueError, match="application_commit.*does not match"):
        RUNNER.build_history_record(
            run_id="run-mismatch",
            started_at="2026-09-30T10:00:00Z",
            finished_at="2026-09-30T10:20:01Z",
            mode="full",
            application_commit="a" * 40,
            orchestration_commit="a" * 40,
            specs=[spec],
            results=[result],
            completed=True,
            aborted_phase=None,
            exit_code=0,
        )


def test_append_jsonl_record_preserves_one_compact_object_per_line(
    tmp_path: Path,
) -> None:
    """Repeated durable appends must remain independent valid JSON records.

    Args:
        tmp_path: Isolated pytest directory.
    """
    history_path = tmp_path / "doc" / "test-report" / "vm-matrix-results.jsonl"
    first = _history_record(tmp_path / "first", run_id="run-1")
    second = _history_record(tmp_path / "second", run_id="run-2")

    RUNNER.append_jsonl_record(history_path, first)
    RUNNER.append_jsonl_record(history_path, second)

    lines = history_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["run_id"] for line in lines] == ["run-1", "run-2"]
    assert all("\n" not in line for line in lines)


def test_append_jsonl_record_malformed_history_is_not_modified(
    tmp_path: Path,
) -> None:
    """Malformed canonical evidence must fail closed without another append.

    Args:
        tmp_path: Isolated pytest directory.
    """
    history_path = tmp_path / "vm-matrix-results.jsonl"
    original = "{broken-json\n"
    history_path.write_text(original, encoding="utf-8")

    with pytest.raises(ValueError, match="Malformed JSONL history"):
        RUNNER.append_jsonl_record(history_path, _history_record(tmp_path / "run"))

    assert history_path.read_text(encoding="utf-8") == original


def test_append_jsonl_record_concurrent_writers_do_not_interleave(
    tmp_path: Path,
) -> None:
    """File locking must preserve every concurrently appended evidence record.

    Args:
        tmp_path: Isolated pytest directory.
    """
    history_path = tmp_path / "vm-matrix-results.jsonl"
    records = [
        _history_record(tmp_path / f"run-{index}", run_id=f"run-{index}")
        for index in range(20)
    ]

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(
            executor.map(
                lambda record: RUNNER.append_jsonl_record(history_path, record),
                records,
            )
        )

    stored = [
        json.loads(line)
        for line in history_path.read_text(encoding="utf-8").splitlines()
    ]
    assert {record["run_id"] for record in stored} == {
        record["run_id"] for record in records
    }


def test_render_vm_matrix_presentation_passing_full_record_returns_green_outputs(
    tmp_path: Path,
) -> None:
    """A passing full matrix must produce matching green public results.

    Args:
        tmp_path: Isolated pytest directory.
    """
    record = _history_record(tmp_path)

    badge = RUNNER.render_vm_matrix_badge(record)
    readme_block = RUNNER.render_vm_matrix_readme_block(record)

    assert badge == {
        "schemaVersion": 1,
        "label": "Ubuntu VM matrix",
        "message": "24.04 passing",
        "color": "brightgreen",
        "isError": False,
    }
    assert "**Latest full VM matrix:** PASS" in readme_block
    assert "| Ubuntu 24.04.5 LTS | 3.12.3 | 2.7.13 | 0.8.1 |" in readme_block
    assert "1548 passed, 2 skipped, 0 failed | PASS | PASS |" in readme_block
    assert "Each VM uses 2 vCPUs, 4G RAM, and a 30G virtual disk." in readme_block
    assert readme_block.count(RUNNER._README_RESULTS_BEGIN) == 1
    assert readme_block.count(RUNNER._README_RESULTS_END) == 1


def test_render_vm_matrix_presentation_failed_full_record_returns_red_outputs(
    tmp_path: Path,
) -> None:
    """A failed full matrix must replace a stale passing public status.

    Args:
        tmp_path: Isolated pytest directory.
    """
    record = _history_record(tmp_path)
    record["passed"] = False
    record["exit_code"] = 1
    image = record["images"][0]
    image["status"] = RUNNER.TEST_FAILED
    image["checks"]["pytest"]["summary"]["passed"] = 1547
    image["checks"]["pytest"]["summary"]["failed"] = 1

    badge = RUNNER.render_vm_matrix_badge(record)
    readme_block = RUNNER.render_vm_matrix_readme_block(record)

    assert badge["message"] == "24.04 tests failing"
    assert badge["color"] == "red"
    assert badge["isError"] is True
    assert "**Latest full VM matrix:** TEST FAILURE" in readme_block
    assert "1547 passed, 2 skipped, 1 failed" in readme_block
    assert "TEST FAILED" in readme_block


def test_render_vm_matrix_presentation_incomplete_record_returns_orange_status(
    tmp_path: Path,
) -> None:
    """An incomplete matrix must expose an infrastructure failure publicly.

    Args:
        tmp_path: Isolated pytest directory.
    """
    record = _history_record(tmp_path)
    record["completed"] = False
    record["passed"] = False
    record["exit_code"] = 2
    image = record["images"][0]
    image["status"] = RUNNER.INFRASTRUCTURE_FAILED
    image["guest"]["dar"] = "unavailable"
    image["guest"]["par2"] = "unavailable"
    image["checks"] = None

    badge = RUNNER.render_vm_matrix_badge(record)
    readme_block = RUNNER.render_vm_matrix_readme_block(record)

    assert badge["message"] == "matrix infrastructure failure"
    assert badge["color"] == "orange"
    assert "**Latest full VM matrix:** INFRASTRUCTURE FAILURE" in readme_block
    assert "| Ubuntu 24.04.5 LTS | 3.12.3 | not available | not available | not run | not run | INFRASTRUCTURE FAILED |" in readme_block


def test_publish_vm_matrix_presentation_valid_markers_updates_only_generated_block(
    tmp_path: Path,
) -> None:
    """Publishing must preserve all README content outside the marker pair.

    Args:
        tmp_path: Isolated pytest directory.
    """
    record = _history_record(tmp_path / "evidence")
    readme_path = tmp_path / "README.md"
    badge_path = tmp_path / "reports" / "vm-matrix-badge.json"
    readme_path.write_text(
        "# Before\n\n"
        f"{RUNNER._README_RESULTS_BEGIN}\nold results\n{RUNNER._README_RESULTS_END}\n\n"
        "# After\n",
        encoding="utf-8",
    )

    RUNNER.publish_vm_matrix_presentation(record, readme_path, badge_path)
    first_render = readme_path.read_text(encoding="utf-8")
    RUNNER.publish_vm_matrix_presentation(record, readme_path, badge_path)

    assert first_render.startswith("# Before\n\n")
    assert first_render.endswith("\n\n# After\n")
    assert readme_path.read_text(encoding="utf-8") == first_render
    assert json.loads(badge_path.read_text(encoding="utf-8"))["color"] == "brightgreen"
    assert stat.S_IMODE(badge_path.stat().st_mode) == 0o644


@pytest.mark.parametrize(
    "readme_content",
    [
        "# No markers\n",
        f"{RUNNER._README_RESULTS_END}\ncontent\n{RUNNER._README_RESULTS_BEGIN}\n",
        (
            f"{RUNNER._README_RESULTS_BEGIN}\nfirst\n{RUNNER._README_RESULTS_END}\n"
            f"{RUNNER._README_RESULTS_BEGIN}\nsecond\n{RUNNER._README_RESULTS_END}\n"
        ),
    ],
)
def test_publish_vm_matrix_presentation_invalid_markers_preserves_readme(
    tmp_path: Path,
    readme_content: str,
) -> None:
    """Invalid generated markers must fail without changing the README.

    Args:
        tmp_path: Isolated pytest directory.
        readme_content: Malformed README marker arrangement.
    """
    record = _history_record(tmp_path / "evidence")
    readme_path = tmp_path / "README.md"
    badge_path = tmp_path / "vm-matrix-badge.json"
    readme_path.write_text(readme_content, encoding="utf-8")

    with pytest.raises(ValueError, match="marker"):
        RUNNER.publish_vm_matrix_presentation(record, readme_path, badge_path)

    assert readme_path.read_text(encoding="utf-8") == readme_content
    assert not badge_path.exists()


def test_read_latest_full_history_record_newer_non_full_record_keeps_full_result(
    tmp_path: Path,
) -> None:
    """A newer smoke record must not replace the public full-suite result.

    Args:
        tmp_path: Isolated pytest directory.
    """
    history_path = tmp_path / "vm-matrix-results.jsonl"
    full_record = _history_record(tmp_path / "full", run_id="full-run")
    smoke_record = json.loads(json.dumps(full_record))
    smoke_record["run_id"] = "smoke-run"
    smoke_record["mode"] = "smoke"
    history_path.write_text(
        json.dumps(full_record) + "\n" + json.dumps(smoke_record) + "\n",
        encoding="utf-8",
    )

    latest = RUNNER.read_latest_full_history_record(history_path)

    assert latest["run_id"] == "full-run"


def test_main_refresh_presentation_valid_history_updates_outputs_without_vm(
    tmp_path: Path,
) -> None:
    """Presentation-only refresh must not require Multipass or SSD preflight.

    Args:
        tmp_path: Isolated pytest directory.
    """
    source_root = tmp_path / "checkout"
    history_path = source_root / "v2" / "doc" / "test-report" / "vm-matrix-results.jsonl"
    history_path.parent.mkdir(parents=True)
    record = _history_record(tmp_path / "evidence", run_id="refresh-run")
    history_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    readme_path = source_root / "README.md"
    readme_path.write_text(
        f"before\n{RUNNER._README_RESULTS_BEGIN}\nold\n{RUNNER._README_RESULTS_END}\nafter\n",
        encoding="utf-8",
    )

    exit_code = RUNNER.main(["--source", str(source_root), "--refresh-presentation"])

    assert exit_code == 0
    assert "Latest full VM matrix" in readme_path.read_text(encoding="utf-8")
    badge_path = source_root / "v2" / "doc" / "test-report" / "vm-matrix-badge.json"
    assert json.loads(badge_path.read_text(encoding="utf-8"))["message"] == "24.04 passing"
