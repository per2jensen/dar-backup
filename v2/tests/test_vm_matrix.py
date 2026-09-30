"""Tests for the fresh Multipass VM compatibility controller."""

# ruff: noqa: S101 - pytest uses assert for test expectations.

from __future__ import annotations

import importlib.util
import json
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
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


def _write_fake_multipass(directory: Path, guest_status: str) -> Path:
    """Create a real subprocess executable implementing the used CLI surface.

    Args:
        directory: Isolated fake-command directory.
        guest_status: PASS or TEST_FAILED result emitted by the fake guest.

    Returns:
        Executable fake Multipass path.
    """
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "guest-status.txt").write_text(guest_status + "\n", encoding="utf-8")
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


def _run_fake_image(tmp_path: Path, guest_status: str) -> object:
    """Run one image through the controller using a fake external executable.

    Args:
        tmp_path: Isolated pytest directory.
        guest_status: Guest result to simulate.

    Returns:
        Controller ImageRunResult.
    """
    fake_multipass = _write_fake_multipass(tmp_path / "fake-bin", guest_status)
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
                    "skipped": 5,
                    "total": 1553,
                    "collected": 1555,
                    "deselected": 2,
                },
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
        message="pytest and mypy passed",
    )
    return spec, result


def _history_record(tmp_path: Path, run_id: str = "run-1") -> dict[str, object]:
    """Build one valid VM history record.

    Args:
        tmp_path: Isolated pytest directory.
        run_id: Record identity.

    Returns:
        Valid schema-v1 history record.
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
    assert RUNNER._overall_exit_code([result]) == 0
    assert (result_directory / "result.json").is_file()
    assert (result_directory / "pytest" / "pytest.txt").read_text(encoding="utf-8") == "all tests passed\n"
    assert not result.instance_preserved


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

    assert record["schema_version"] == 1
    assert record["passed"] is True
    assert image["guest"]["dar"] == "dar version 2.7.13"
    assert image["guest"]["dar_manager"] == "dar_manager version 1.9.0"
    assert image["checks"]["mypy"] == "passed"
    assert image["checks"]["pytest"]["summary"]["passed"] == 1548
    assert image["checks"]["pytest"]["duration_seconds"] == 1200.125
    assert "private-host-path" not in encoded
    assert "/home/" not in encoded
    assert "/mnt/" not in encoded
    assert "dar-backup-test-2404" not in encoded


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
