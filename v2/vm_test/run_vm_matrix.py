#!/usr/bin/env python3
"""Run the dar-backup test suite in fresh Multipass Ubuntu instances."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence


PASS = "PASS"  # noqa: S105 - test outcome, not a credential.
TEST_FAILED = "TEST_FAILED"
INFRASTRUCTURE_FAILED = "INFRASTRUCTURE_FAILED"
_GUEST_STATUSES = {PASS, TEST_FAILED, "SETUP_FAILED"}
_SAFE_LABEL = re.compile(r"[a-z0-9][a-z0-9.-]*")
_SAFE_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")
_SAFE_INSTANCE = re.compile(r"dar-backup-test-[a-z0-9-]+")
_RESOURCE_SIZE = re.compile(r"[1-9][0-9]*[KMG]")


class InfrastructureError(RuntimeError):
    """Report a host, VM, transfer, or result-validation failure."""


@dataclass(frozen=True)
class ImageSpec:
    """Describe one Ubuntu image in the compatibility matrix.

    Attributes:
        label: Stable result-directory and summary label.
        image: Multipass image alias.
        instance_name: Dedicated Multipass instance name.
        disk: Virtual disk capacity passed to Multipass.
        memory: Guest memory passed to Multipass.
        cpus: Guest virtual CPU count.
    """

    label: str
    image: str
    instance_name: str
    disk: str
    memory: str
    cpus: int


@dataclass(frozen=True)
class MountInfo:
    """Describe the filesystem containing the configured SSD root.

    Attributes:
        target: Mounted filesystem target.
        source: Mounted filesystem source.
        filesystem: Filesystem type reported by findmnt.
        free_bytes: Available bytes on the filesystem.
    """

    target: str
    source: str
    filesystem: str
    free_bytes: int


@dataclass(frozen=True)
class CommandResult:
    """Contain a completed external command result.

    Attributes:
        returncode: Process exit status.
        output: Combined standard output and standard error.
    """

    returncode: int
    output: str


@dataclass(frozen=True)
class ImageRunResult:
    """Contain the host's final assessment of one guest run.

    Attributes:
        label: Image label from the matrix.
        status: PASS, TEST_FAILED, or INFRASTRUCTURE_FAILED.
        guest_status: Detailed status returned by the guest when available.
        exit_code: Guest process exit code when available.
        result_directory: Directory holding retrieved diagnostics.
        instance_name: Multipass instance name.
        instance_preserved: Whether the VM was intentionally retained.
        message: Concise result explanation.
    """

    label: str
    status: str
    guest_status: str | None
    exit_code: int | None
    result_directory: str
    instance_name: str
    instance_preserved: bool
    message: str


class CommandExecutor:
    """Execute Multipass commands with combined diagnostic logging.

    Args:
        executable: Multipass executable path or command name.
    """

    def __init__(self, executable: str = "multipass") -> None:
        """Initialize an executor.

        Args:
            executable: Multipass executable path or command name.

        Raises:
            ValueError: If executable is empty.
        """
        if not executable.strip():
            raise ValueError("Multipass executable must not be empty")
        self._executable = executable

    def run(
        self,
        arguments: Sequence[str],
        log_path: Path | None = None,
        stream: bool = False,
    ) -> CommandResult:
        """Run a Multipass command and optionally append its output to a log.

        Args:
            arguments: Command arguments after the executable.
            log_path: Optional combined-output log.
            stream: Whether to echo output while the process runs.

        Returns:
            Completed command status and combined output.

        Raises:
            InfrastructureError: If the executable cannot be started.
        """
        command = [self._executable, *arguments]
        _append_log(log_path, f"$ {shlex.join(command)}\n")

        try:
            process = subprocess.Popen(  # noqa: S603 - arguments are never passed through a shell.
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise InfrastructureError(f"Cannot start {self._executable}: {exc}") from exc

        output_lines: list[str] = []
        if process.stdout is None:
            process.kill()
            raise InfrastructureError(f"Cannot capture output from {self._executable}")

        for line in process.stdout:
            output_lines.append(line)
            _append_log(log_path, line)
            if stream:
                sys.stdout.write(line)
                sys.stdout.flush()

        returncode = process.wait()
        return CommandResult(returncode=returncode, output="".join(output_lines))


def _append_log(log_path: Path | None, content: str) -> None:
    """Append content to a diagnostic log when one is configured.

    Args:
        log_path: Optional log path.
        content: Text to append.

    Returns:
        None.
    """
    if log_path is None:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(content)


def _require_string(value: Any, field: str) -> str:
    """Validate and return a non-empty JSON string.

    Args:
        value: Parsed JSON value.
        field: Field name used in errors.

    Returns:
        Validated string.

    Raises:
        ValueError: If the value is not a non-empty string.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def load_image_specs(config_path: Path) -> list[ImageSpec]:
    """Load and validate the Ubuntu image matrix.

    Args:
        config_path: JSON configuration path.

    Returns:
        Validated image specifications.

    Raises:
        ValueError: If the configuration is malformed or unsafe.
        OSError: If the configuration cannot be read.
    """
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    images = raw.get("images") if isinstance(raw, dict) else None
    if not isinstance(images, list) or not images:
        raise ValueError("Image configuration must contain a non-empty 'images' list")

    specs: list[ImageSpec] = []
    labels: set[str] = set()
    names: set[str] = set()
    for index, image in enumerate(images):
        if not isinstance(image, dict):
            raise TypeError(f"images[{index}] must be an object")
        label = _require_string(image.get("label"), f"images[{index}].label")
        instance_name = _require_string(image.get("instance_name"), f"images[{index}].instance_name")
        image_alias = _require_string(image.get("image"), f"images[{index}].image")
        disk = _require_string(image.get("disk"), f"images[{index}].disk")
        memory = _require_string(image.get("memory"), f"images[{index}].memory")
        cpus = image.get("cpus")
        if not isinstance(cpus, int) or isinstance(cpus, bool) or cpus < 1:
            raise ValueError(f"images[{index}].cpus must be a positive integer")
        if _SAFE_LABEL.fullmatch(label) is None:
            raise ValueError(f"Refusing unsafe image label: {label!r}")
        if _SAFE_IMAGE.fullmatch(image_alias) is None:
            raise ValueError(f"Refusing unsafe Multipass image alias: {image_alias!r}")
        if _SAFE_INSTANCE.fullmatch(instance_name) is None:
            raise ValueError(f"Refusing unsafe instance name: {instance_name!r}")
        if _RESOURCE_SIZE.fullmatch(disk) is None or _RESOURCE_SIZE.fullmatch(memory) is None:
            raise ValueError(f"Invalid disk or memory size at images[{index}]")
        if label in labels or instance_name in names:
            raise ValueError(f"Duplicate image label or instance name at images[{index}]")
        labels.add(label)
        names.add(instance_name)
        specs.append(
            ImageSpec(
                label=label,
                image=image_alias,
                instance_name=instance_name,
                disk=disk,
                memory=memory,
                cpus=cpus,
            )
        )
    return specs


def validate_ssd_root(ssd_root: Path, minimum_free_gib: int) -> MountInfo:
    """Verify that runtime storage is a dedicated mounted filesystem.

    Args:
        ssd_root: Required SSD mount point.
        minimum_free_gib: Minimum available capacity in GiB.

    Returns:
        Validated mount information.

    Raises:
        InfrastructureError: If the path is unsafe, unmounted, or too full.
        ValueError: If minimum_free_gib is invalid.
    """
    if minimum_free_gib < 1:
        raise ValueError("minimum_free_gib must be at least 1")
    if not ssd_root.is_absolute():
        raise InfrastructureError(f"SSD root must be absolute: {ssd_root}")
    if not ssd_root.is_dir():
        raise InfrastructureError(f"SSD root does not exist or is not a directory: {ssd_root}")

    resolved_root = ssd_root.resolve()
    try:
        completed = subprocess.run(  # noqa: S603 - fixed read-only system command.
            ["/usr/bin/findmnt", "--noheadings", "--output", "TARGET,SOURCE,FSTYPE", "--target", str(resolved_root)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise InfrastructureError(f"Cannot inspect SSD mount with findmnt: {exc}") from exc
    if completed.returncode != 0:
        raise InfrastructureError(f"findmnt failed for {resolved_root}: {completed.stderr.strip()}")

    fields = completed.stdout.strip().split(maxsplit=2)
    if len(fields) != 3:
        raise InfrastructureError(f"Unexpected findmnt output for {resolved_root}: {completed.stdout!r}")
    mount_target, mount_source, filesystem = fields
    if Path(mount_target).resolve() != resolved_root:
        raise InfrastructureError(
            f"SSD root is not itself a mount point: {resolved_root} is stored on {mount_target}"
        )
    if os.stat(resolved_root).st_dev == os.stat("/").st_dev:
        raise InfrastructureError(f"SSD root uses the system root filesystem: {resolved_root}")

    free_bytes = shutil.disk_usage(resolved_root).free
    required_bytes = minimum_free_gib * 1024**3
    if free_bytes < required_bytes:
        raise InfrastructureError(
            f"SSD root has {free_bytes / 1024**3:.1f} GiB free; {minimum_free_gib} GiB is required"
        )

    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".dar-backup-write-test-", dir=resolved_root, delete=False) as handle:
            temporary_name = handle.name
            handle.write(b"storage preflight\n")
    except OSError as exc:
        raise InfrastructureError(f"SSD root is not writable: {resolved_root}: {exc}") from exc
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)

    return MountInfo(
        target=str(resolved_root),
        source=mount_source,
        filesystem=filesystem,
        free_bytes=free_bytes,
    )


def validate_multipass_storage(ssd_root: Path) -> Path:
    """Require the Multipass daemon to store all external data on the SSD.

    Args:
        ssd_root: Validated dedicated SSD mount point.

    Returns:
        Effective Multipass storage directory.

    Raises:
        InfrastructureError: If systemd or the storage directory disagrees.
    """
    expected_storage = (ssd_root / "multipass").resolve()
    if not expected_storage.is_dir():
        raise InfrastructureError(f"Multipass storage directory does not exist: {expected_storage}")
    if os.stat(expected_storage).st_dev != os.stat(ssd_root).st_dev:
        raise InfrastructureError(f"Multipass storage is not on the configured SSD: {expected_storage}")
    if expected_storage.stat().st_uid != 0:
        raise InfrastructureError(f"Multipass storage must be owned by root: {expected_storage}")

    try:
        completed = subprocess.run(  # noqa: S603 - fixed read-only system command.
            [
                "/usr/bin/systemctl",
                "show",
                "snap.multipass.multipassd.service",
                "--property=Environment",
                "--value",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise InfrastructureError(f"Cannot inspect the Multipass systemd service: {exc}") from exc
    if completed.returncode != 0:
        raise InfrastructureError(f"Cannot read Multipass service environment: {completed.stderr.strip()}")

    try:
        environment_entries = shlex.split(completed.stdout)
    except ValueError as exc:
        raise InfrastructureError(f"Cannot parse Multipass service environment: {exc}") from exc
    environment = dict(entry.split("=", 1) for entry in environment_entries if "=" in entry)
    configured_storage = environment.get("MULTIPASS_STORAGE")
    if configured_storage is None:
        raise InfrastructureError("Multipass service has no MULTIPASS_STORAGE setting")
    if Path(configured_storage).resolve() != expected_storage:
        raise InfrastructureError(
            f"Multipass stores data at {configured_storage}, expected {expected_storage}"
        )
    return expected_storage


def validate_git_checkout(source_root: Path) -> str:
    """Require a clean Git checkout and return its immutable commit.

    Args:
        source_root: dar-backup repository root.

    Returns:
        Full HEAD commit ID.

    Raises:
        InfrastructureError: If the checkout is invalid, dirty, or unreadable.
    """
    if not (source_root / "v2" / "pyproject.toml").is_file():
        raise InfrastructureError(f"Not a dar-backup checkout: {source_root}")

    status = _run_host_command(["git", "status", "--porcelain"], source_root)
    if status.returncode != 0:
        raise InfrastructureError(f"Cannot inspect Git checkout: {status.output.strip()}")
    if status.output.strip():
        raise InfrastructureError("dar-backup checkout must be clean before a VM test run")

    commit = _run_host_command(["git", "rev-parse", "HEAD"], source_root)
    if commit.returncode != 0 or not commit.output.strip():
        raise InfrastructureError(f"Cannot resolve dar-backup HEAD: {commit.output.strip()}")
    return commit.output.strip()


def _run_host_command(arguments: Sequence[str], cwd: Path) -> CommandResult:
    """Run a fixed-argument host command.

    Args:
        arguments: Executable and arguments.
        cwd: Command working directory.

    Returns:
        Combined command result.

    Raises:
        InfrastructureError: If the command cannot be started.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - arguments are never passed through a shell.
            list(arguments),
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise InfrastructureError(f"Cannot start {arguments[0]}: {exc}") from exc
    return CommandResult(completed.returncode, completed.stdout + completed.stderr)


def create_source_archive(source_root: Path, commit: str, archive_path: Path) -> None:
    """Create a tar archive containing source and tests from one commit.

    Args:
        source_root: Clean dar-backup repository root.
        commit: Immutable Git commit ID.
        archive_path: Destination tar path on SSD storage.

    Returns:
        None.

    Raises:
        InfrastructureError: If Git cannot create a non-empty archive.
    """
    if not commit.strip():
        raise ValueError("commit must not be empty")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    result = _run_host_command(
        [
            "git",
            "archive",
            "--format=tar",
            f"--output={archive_path}",
            "--prefix=dar-backup/",
            commit,
        ],
        source_root,
    )
    if result.returncode != 0:
        raise InfrastructureError(f"Cannot create source archive: {result.output.strip()}")
    if not archive_path.is_file() or archive_path.stat().st_size == 0:
        raise InfrastructureError(f"Git created no source archive at {archive_path}")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write a JSON object.

    Args:
        path: Destination JSON path.
        payload: Serializable object.

    Returns:
        None.

    Raises:
        OSError: If the file cannot be written.
        TypeError: If payload is not JSON serializable.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            json.dump(payload, temporary, indent=2, sort_keys=True)
            temporary.write("\n")
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _list_instances(executor: CommandExecutor, log_path: Path) -> dict[str, str]:
    """Return existing Multipass instance names and states.

    Args:
        executor: Multipass command executor.
        log_path: Controller diagnostic log.

    Returns:
        Existing instance names mapped to their states.

    Raises:
        InfrastructureError: If Multipass cannot list or describe instances.
    """
    result = executor.run(["list", "--format", "json"], log_path)
    if result.returncode != 0:
        raise InfrastructureError(f"multipass list failed: {result.output.strip()}")
    try:
        payload = json.loads(result.output)
        entries = payload["list"]
        if not isinstance(entries, list):
            raise TypeError("'list' is not an array")
        instances: dict[str, str] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise TypeError("instance list entry is not an object")
            name = _require_string(entry.get("name"), "multipass instance name")
            state = _require_string(entry.get("state"), f"state for Multipass instance {name}")
            instances[name] = state
        return instances
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise InfrastructureError(f"Cannot parse multipass list JSON: {exc}") from exc


def _remove_instance(
    executor: CommandExecutor,
    instance_name: str,
    instance_state: str,
    log_path: Path,
) -> None:
    """Delete and purge one validated test instance.

    Args:
        executor: Multipass command executor.
        instance_name: Dedicated test instance name.
        instance_state: Last state reported by Multipass.
        log_path: Controller diagnostic log.

    Returns:
        None.

    Raises:
        InfrastructureError: If the name is unsafe or deletion fails.
    """
    if _SAFE_INSTANCE.fullmatch(instance_name) is None:
        raise InfrastructureError(f"Refusing to delete unsafe instance name: {instance_name}")
    if not instance_state.strip():
        raise InfrastructureError(f"Missing state for test instance: {instance_name}")
    if instance_state.casefold() not in {"stopped", "deleted"}:
        stopped = executor.run(["stop", instance_name], log_path)
        if stopped.returncode != 0:
            raise InfrastructureError(f"Cannot stop test instance {instance_name}: {stopped.output.strip()}")
    result = executor.run(["delete", "--purge", instance_name], log_path)
    if result.returncode != 0:
        raise InfrastructureError(f"Cannot delete test instance {instance_name}: {result.output.strip()}")


def _extract_result_archive(archive_path: Path, destination: Path) -> None:
    """Safely extract the guest result archive.

    Args:
        archive_path: Retrieved gzip-compressed tar archive.
        destination: Per-image results directory.

    Returns:
        None.

    Raises:
        InfrastructureError: If the archive is invalid or contains unsafe paths.
    """
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive.getmembers():
                member_path = (destination_root / member.name).resolve()
                if not member_path.is_relative_to(destination_root):
                    raise InfrastructureError(f"Unsafe path in guest result archive: {member.name}")
                if member.issym() or member.islnk():
                    raise InfrastructureError(f"Links are not allowed in guest result archive: {member.name}")
            archive.extractall(destination_root)  # noqa: S202 - every member was validated above.
    except (OSError, tarfile.TarError) as exc:
        raise InfrastructureError(f"Cannot extract guest results: {exc}") from exc


def _read_guest_result(result_path: Path) -> tuple[str, str]:
    """Validate the guest result contract.

    Args:
        result_path: Extracted guest result JSON.

    Returns:
        Guest status and detail message.

    Raises:
        InfrastructureError: If the result is absent or malformed.
    """
    if not result_path.is_file():
        raise InfrastructureError(f"Guest returned no result file: {result_path}")
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InfrastructureError(f"Cannot read guest result: {exc}") from exc
    if not isinstance(payload, dict):
        raise InfrastructureError("Guest result must be a JSON object")
    status = payload.get("status")
    detail = payload.get("detail")
    if status not in _GUEST_STATUSES:
        raise InfrastructureError(f"Guest returned invalid status: {status!r}")
    if not isinstance(detail, str) or not detail.strip():
        raise InfrastructureError("Guest result contains no detail message")
    return status, detail


def run_image(
    spec: ImageSpec,
    executor: CommandExecutor,
    archive_path: Path,
    guest_script: Path,
    mode: str,
    commit: str,
    result_root: Path,
    keep_failed: bool,
    keep_all: bool,
) -> ImageRunResult:
    """Launch, test, collect, and clean up one fresh Ubuntu instance.

    Args:
        spec: Ubuntu image definition.
        executor: Multipass command executor.
        archive_path: Immutable application source archive.
        guest_script: Guest provisioning and test script.
        mode: pytest_report.sh mode.
        commit: Application and orchestration commit.
        result_root: Run-level result directory on the SSD.
        keep_failed: Preserve a failed instance for diagnosis.
        keep_all: Preserve every instance.

    Returns:
        Host assessment and diagnostic location.
    """
    image_result_dir = result_root / spec.label
    image_result_dir.mkdir(parents=True, exist_ok=False)
    controller_log = image_result_dir / "controller-console.log"
    instance_created = False
    guest_exit_code: int | None = None
    guest_status: str | None = None
    status = INFRASTRUCTURE_FAILED
    message = "VM test did not complete"

    try:
        existing = _list_instances(executor, controller_log)
        if spec.instance_name in existing:
            _append_log(controller_log, f"Removing stale test instance {spec.instance_name}\n")
            _remove_instance(executor, spec.instance_name, existing[spec.instance_name], controller_log)

        launch = executor.run(
            [
                "launch",
                spec.image,
                "--name",
                spec.instance_name,
                "--disk",
                spec.disk,
                "--memory",
                spec.memory,
                "--cpus",
                str(spec.cpus),
            ],
            controller_log,
            stream=True,
        )
        if launch.returncode != 0:
            raise InfrastructureError(f"VM launch failed with status {launch.returncode}")
        instance_created = True

        for source in (archive_path, guest_script):
            transfer = executor.run(
                ["transfer", str(source), f"{spec.instance_name}:/home/ubuntu/{source.name}"],
                controller_log,
            )
            if transfer.returncode != 0:
                raise InfrastructureError(f"Cannot transfer {source.name} to {spec.instance_name}")

        chmod = executor.run(
            ["exec", spec.instance_name, "--", "chmod", "0700", f"/home/ubuntu/{guest_script.name}"],
            controller_log,
        )
        if chmod.returncode != 0:
            raise InfrastructureError("Cannot make the guest runner executable")

        guest = executor.run(
            [
                "exec",
                spec.instance_name,
                "--",
                f"/home/ubuntu/{guest_script.name}",
                f"/home/ubuntu/{archive_path.name}",
                mode,
                "/home/ubuntu/results",
                commit,
                commit,
            ],
            controller_log,
            stream=True,
        )
        guest_exit_code = guest.returncode

        package = executor.run(
            [
                "exec",
                spec.instance_name,
                "--",
                "tar",
                "-czf",
                "/home/ubuntu/results.tar.gz",
                "-C",
                "/home/ubuntu/results",
                ".",
            ],
            controller_log,
        )
        if package.returncode != 0:
            raise InfrastructureError("Cannot package guest diagnostics")

        retrieved_archive = image_result_dir / "guest-results.tar.gz"
        retrieve = executor.run(
            ["transfer", f"{spec.instance_name}:/home/ubuntu/results.tar.gz", str(retrieved_archive)],
            controller_log,
        )
        if retrieve.returncode != 0:
            raise InfrastructureError("Cannot retrieve guest diagnostics")
        _extract_result_archive(retrieved_archive, image_result_dir)

        guest_status, detail = _read_guest_result(image_result_dir / "result.json")
        message = detail
        if guest_status == PASS and guest_exit_code == 0:
            status = PASS
        elif guest_status == TEST_FAILED and guest_exit_code == 1:
            status = TEST_FAILED
        elif guest_status == "SETUP_FAILED" and guest_exit_code == 2:
            status = INFRASTRUCTURE_FAILED
        else:
            raise InfrastructureError(
                f"Guest status/exit mismatch: status={guest_status}, exit={guest_exit_code}"
            )
    except InfrastructureError as exc:
        status = INFRASTRUCTURE_FAILED
        message = str(exc)
        _append_log(controller_log, f"ERROR: {exc}\n")

    preserve = instance_created and (keep_all or (keep_failed and status != PASS))
    if instance_created and not preserve:
        try:
            _remove_instance(executor, spec.instance_name, "Running", controller_log)
        except InfrastructureError as exc:
            status = INFRASTRUCTURE_FAILED
            message = f"{message}; cleanup failed: {exc}"
            preserve = True
            _append_log(controller_log, f"ERROR: {exc}\n")

    result = ImageRunResult(
        label=spec.label,
        status=status,
        guest_status=guest_status,
        exit_code=guest_exit_code,
        result_directory=str(image_result_dir),
        instance_name=spec.instance_name,
        instance_preserved=preserve,
        message=message,
    )
    write_json(image_result_dir / "host-result.json", asdict(result))
    return result


def _overall_exit_code(results: Sequence[ImageRunResult]) -> int:
    """Map matrix results to the public controller exit contract.

    Args:
        results: Per-image outcomes.

    Returns:
        Zero for success, one for test failures, or two for infrastructure failures.
    """
    if any(result.status == INFRASTRUCTURE_FAILED for result in results):
        return 2
    if any(result.status == TEST_FAILED for result in results):
        return 1
    return 0


def _print_summary(commit: str, result_root: Path, results: Sequence[ImageRunResult]) -> None:
    """Print a concise matrix summary.

    Args:
        commit: Tested application commit.
        result_root: Run-level diagnostic directory.
        results: Per-image outcomes.

    Returns:
        None.
    """
    print(f"\ndar-backup {commit[:12]}")
    for result in results:
        suffix = f" — {result.message}"
        if result.instance_preserved:
            suffix += f"; VM preserved: {result.instance_name}"
        print(f"{result.label}: {result.status}{suffix}")
    print(f"Reports: {result_root}")


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        arguments: Optional arguments excluding the program name.

    Returns:
        Parsed arguments.
    """
    script_directory = Path(__file__).resolve().parent
    repository_root = script_directory.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=repository_root, help="clean dar-backup checkout")
    parser.add_argument("--ssd-root", type=Path, default=Path("/mnt/vm-work"), help="dedicated SSD mount point")
    parser.add_argument("--mode", choices=("fast", "smoke", "integration", "full"), default="full")
    parser.add_argument("--minimum-free-gib", type=int, default=40)
    parser.add_argument("--keep-failed", action="store_true", help="retain failed VMs for interactive diagnosis")
    parser.add_argument("--keep-all", action="store_true", help="retain every VM")
    parser.add_argument("--multipass", default="multipass", help=argparse.SUPPRESS)
    parser.add_argument("--images", type=Path, default=script_directory / "images.json", help=argparse.SUPPRESS)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the configured fresh-VM test matrix.

    Args:
        arguments: Optional arguments excluding the program name.

    Returns:
        Zero for success, one for test failure, or two for infrastructure failure.
    """
    args = parse_args(arguments)
    try:
        source_root = args.source.resolve()
        ssd_root = args.ssd_root.resolve()
        mount_info = validate_ssd_root(ssd_root, args.minimum_free_gib)
        multipass_storage = validate_multipass_storage(ssd_root)
        commit = validate_git_checkout(source_root)
        specs = load_image_specs(args.images.resolve())

        run_id = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%SZ") + f"-{commit[:12]}"
        work_root = ssd_root / "dar-backup-vm-tests"
        staging_root = work_root / "staging" / run_id
        result_root = work_root / "results" / run_id
        staging_root.mkdir(parents=True, exist_ok=False)
        result_root.mkdir(parents=True, exist_ok=False)

        archive_path = staging_root / f"dar-backup-{commit[:12]}.tar"
        create_source_archive(source_root, commit, archive_path)
        guest_script = source_root / "v2" / "vm_test" / "run_in_guest.sh"
        if not guest_script.is_file():
            raise InfrastructureError(f"Guest runner is missing: {guest_script}")

        print(
            f"SSD: {mount_info.source} mounted at {mount_info.target} "
            f"({mount_info.free_bytes / 1024**3:.1f} GiB free)"
        )
        print(f"Source commit: {commit}")
        print(f"Results: {result_root}")

        executor = CommandExecutor(args.multipass)
        results = [
            run_image(
                spec=spec,
                executor=executor,
                archive_path=archive_path,
                guest_script=guest_script,
                mode=args.mode,
                commit=commit,
                result_root=result_root,
                keep_failed=args.keep_failed,
                keep_all=args.keep_all,
            )
            for spec in specs
        ]
        summary = {
            "application_commit": commit,
            "orchestration_commit": commit,
            "mode": args.mode,
            "ssd": asdict(mount_info),
            "multipass_storage": str(multipass_storage),
            "results": [asdict(result) for result in results],
        }
        write_json(result_root / "summary.json", summary)
        _print_summary(commit, result_root, results)
        return _overall_exit_code(results)
    except (InfrastructureError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
