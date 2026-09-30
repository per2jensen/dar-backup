"""Tests for the fresh Multipass VM compatibility controller."""

# ruff: noqa: S101 - pytest uses assert for test expectations.

from __future__ import annotations

import importlib.util
import json
import stat
import sys
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
import shutil
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
    raise SystemExit(0)

if args and args[0] == "transfer":
    source, destination = args[1], args[2]
    if ":" in source:
        shutil.copy2(remote_path(source), Path(destination))
    else:
        target = remote_path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(Path(source), target)
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
