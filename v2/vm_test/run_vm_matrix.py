#!/usr/bin/env python3
"""Run the dar-backup test suite in fresh Multipass Ubuntu instances."""

from __future__ import annotations

import argparse
import ast
import fcntl
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Sequence, cast


PASS = "PASS"  # noqa: S105 - test outcome, not a credential.
TEST_FAILED = "TEST_FAILED"
INFRASTRUCTURE_FAILED = "INFRASTRUCTURE_FAILED"
HISTORY_SCHEMA_VERSION = 2
_GUEST_STATUSES = {PASS, TEST_FAILED, "SETUP_FAILED"}
_SAFE_LABEL = re.compile(r"[a-z0-9][a-z0-9.-]*")
_SAFE_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")
_SAFE_INSTANCE = re.compile(r"dar-backup-test-[a-z0-9-]+")
_RESOURCE_SIZE = re.compile(r"[1-9][0-9]*[KMG]")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DEBIAN_PACKAGE_KEY = re.compile(r"[a-z0-9][a-z0-9+.-]*:[a-z0-9][a-z0-9-]*")
_MYPY_ERROR_CODE = re.compile(r"[a-z][a-z0-9-]*")
_GIT_COMMIT = re.compile(r"[0-9a-f]{40}")
# This parses pytest output; it does not create or trust a predictable temporary path.
_PYTEST_TEMP_ROOT = re.compile(r"/tmp/pytest-of-[^/\s'\"]+/pytest-[0-9]+")  # noqa: S108
_FAILURE_MESSAGE_LIMIT = 500
_README_RESULTS_BEGIN = "<!-- BEGIN GENERATED VM MATRIX RESULTS -->"
_README_RESULTS_END = "<!-- END GENERATED VM MATRIX RESULTS -->"
_DEFAULT_HISTORY_RELATIVE_PATH = Path("v2/doc/test-report/vm-matrix-results.jsonl")
_DEFAULT_BADGE_RELATIVE_PATH = Path("v2/doc/test-report/vm-matrix-badge.json")
_GITHUB_REPOSITORY_URL = "https://github.com/per2jensen/dar-backup"


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


def _stream_file_to_pipe(source: BinaryIO, destination: BinaryIO) -> None:
    """Copy one open file into a subprocess pipe and close the pipe.

    Args:
        source: Open binary source file.
        destination: Open binary subprocess standard-input pipe.

    Returns:
        None.

    Raises:
        OSError: If the source cannot be read or the pipe cannot be written.
    """
    try:
        shutil.copyfileobj(source, destination, length=1024 * 1024)
    finally:
        destination.close()


def _read_pipe_as_text(source: BinaryIO, log_path: Path | None) -> str:
    """Read, decode, and log all output from a subprocess pipe.

    Args:
        source: Open binary subprocess output pipe.
        log_path: Optional diagnostic log path.

    Returns:
        Decoded subprocess output.

    Raises:
        OSError: If the pipe or diagnostic log cannot be read or written.
    """
    output_lines: list[str] = []
    try:
        for raw_line in source:
            line = raw_line.decode("utf-8", errors="replace")
            output_lines.append(line)
            _append_log(log_path, line)
    finally:
        source.close()
    return "".join(output_lines)


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
        image_release: Multipass release label for the launched source image.
        image_sha256: Full SHA-256 of the launched source image.
        message: Concise result explanation.
    """

    label: str
    status: str
    guest_status: str | None
    exit_code: int | None
    result_directory: str
    instance_name: str
    instance_preserved: bool
    image_release: str | None
    image_sha256: str | None
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
        input_path: Path | None = None,
    ) -> CommandResult:
        """Run a Multipass command and optionally append its output to a log.

        Args:
            arguments: Command arguments after the executable.
            log_path: Optional combined-output log.
            stream: Whether to echo output while the process runs.
            input_path: Optional file for the command's standard input.

        Returns:
            Completed command status and combined output.

        Raises:
            InfrastructureError: If the input is invalid or the executable cannot be started.
        """
        if input_path is not None and not input_path.is_file():
            raise InfrastructureError(f"Command input is not a file: {input_path}")

        command = [self._executable, *arguments]
        input_suffix = f" < {shlex.quote(str(input_path))}" if input_path is not None else ""
        _append_log(log_path, f"$ {shlex.join(command)}{input_suffix}\n")

        input_file: BinaryIO | None = None
        if input_path is not None:
            try:
                input_file = input_path.open("rb")
            except OSError as exc:
                raise InfrastructureError(f"Cannot open command input {input_path}: {exc}") from exc

        try:
            process = subprocess.Popen(  # noqa: S603 - arguments are never passed through a shell.
                command,
                stdin=subprocess.PIPE if input_file is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            if input_file is not None:
                input_file.close()
            raise InfrastructureError(f"Cannot start {shlex.join(command)}: {exc}") from exc

        input_executor: ThreadPoolExecutor | None = None
        input_future: Future[None] | None = None
        if process.stdout is None:
            process.kill()
            process.wait()
            if input_file is not None:
                input_file.close()
            raise InfrastructureError(f"Cannot capture output from {self._executable}")

        if input_file is not None:
            if process.stdin is None:
                process.kill()
                process.wait()
                input_file.close()
                raise InfrastructureError(f"Cannot stream input to {self._executable}")
            input_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="multipass-input")
            input_future = input_executor.submit(_stream_file_to_pipe, input_file, cast(BinaryIO, process.stdin))

        output_lines: list[str] = []
        try:
            for raw_line in process.stdout:
                line = raw_line.decode("utf-8", errors="replace")
                output_lines.append(line)
                _append_log(log_path, line)
                if stream:
                    sys.stdout.write(line)
                    sys.stdout.flush()

            returncode = process.wait()
            if input_future is not None:
                try:
                    input_future.result()
                except OSError as exc:
                    if returncode == 0:
                        raise InfrastructureError(f"Cannot stream {input_path} to {self._executable}: {exc}") from exc
                    _append_log(log_path, f"Input stream stopped after command failure: {exc}\n")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if input_executor is not None:
                input_executor.shutdown(wait=True)
            if input_file is not None:
                input_file.close()
        return CommandResult(returncode=returncode, output="".join(output_lines))

    def run_with_stdout_file(
        self,
        arguments: Sequence[str],
        output_path: Path,
        log_path: Path | None = None,
    ) -> CommandResult:
        """Run a command and atomically capture its binary stdout in a file.

        Args:
            arguments: Command arguments after the executable.
            output_path: Destination for the command's standard output.
            log_path: Optional command and standard-error log.

        Returns:
            Completed command status and captured standard error.

        Raises:
            InfrastructureError: If the command or output file cannot be handled.
        """
        command = [self._executable, *arguments]
        _append_log(log_path, f"$ {shlex.join(command)} > {shlex.quote(str(output_path))}\n")

        temporary_path: Path | None = None
        process: subprocess.Popen[bytes] | None = None
        error_executor: ThreadPoolExecutor | None = None
        error_output = ""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{output_path.name}.",
                suffix=".tmp",
                dir=output_path.parent,
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                process = subprocess.Popen(  # noqa: S603 - arguments are never passed through a shell.
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if process.stdout is None or process.stderr is None:
                    process.kill()
                    process.wait()
                    raise InfrastructureError(f"Cannot capture output from {self._executable}")

                error_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="multipass-errors")
                error_future = error_executor.submit(
                    _read_pipe_as_text,
                    cast(BinaryIO, process.stderr),
                    log_path,
                )
                try:
                    shutil.copyfileobj(cast(BinaryIO, process.stdout), temporary, length=1024 * 1024)
                finally:
                    process.stdout.close()
                returncode = process.wait()
                error_output = error_future.result()
                error_executor.shutdown(wait=True)
                error_executor = None

            if returncode == 0:
                os.replace(temporary_path, output_path)
                temporary_path = None
        except OSError as exc:
            raise InfrastructureError(f"Cannot run {shlex.join(command)} into {output_path}: {exc}") from exc
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            if error_executor is not None:
                error_executor.shutdown(wait=True)
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

        return CommandResult(returncode=returncode, output=error_output)


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


def append_jsonl_record(path: Path, record: dict[str, Any]) -> None:
    """Append one validated, locked, and durable JSONL record.

    Existing non-empty lines are validated while the exclusive lock is held so
    a malformed tracked history cannot silently gain more records.

    Args:
        path: Tracked JSONL history path.
        record: JSON-serializable schema-versioned object.

    Returns:
        None.

    Raises:
        OSError: If the history cannot be created, read, written, or synchronized.
        TypeError: If the record is not JSON serializable.
        ValueError: If an argument or existing history record is invalid.
    """
    if path is None:
        raise ValueError("history path must not be None")
    if record is None:
        raise ValueError("history record must not be None")
    if record.get("schema_version") != HISTORY_SCHEMA_VERSION:
        raise ValueError(
            f"history record schema_version must be {HISTORY_SCHEMA_VERSION}"
        )

    encoded = json.dumps(
        record,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as history_file:
        fcntl.flock(history_file.fileno(), fcntl.LOCK_EX)
        try:
            history_file.seek(0)
            for line_number, line in enumerate(history_file, start=1):
                if not line.strip():
                    continue
                try:
                    existing = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Malformed JSONL history at {path}:{line_number}: {exc.msg}"
                    ) from exc
                if not isinstance(existing, dict):
                    raise TypeError(
                        f"JSONL history record at {path}:{line_number} must be an object"
                    )
                if not isinstance(existing.get("schema_version"), int):
                    raise TypeError(
                        f"JSONL history record at {path}:{line_number} has no integer schema_version"
                    )

            history_file.seek(0, os.SEEK_END)
            history_file.write(encoded)
            history_file.flush()
            os.fsync(history_file.fileno())
        finally:
            fcntl.flock(history_file.fileno(), fcntl.LOCK_UN)


def _presentation_images(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate public matrix metadata and return its image records.

    Args:
        record: Schema-v2 VM matrix history record.

    Returns:
        Validated image dictionaries in matrix order.

    Raises:
        TypeError: If a required field has the wrong type.
        ValueError: If the record cannot truthfully describe a full matrix run.
    """
    if record.get("schema_version") != HISTORY_SCHEMA_VERSION:
        raise ValueError(
            f"Presentation record schema_version must be {HISTORY_SCHEMA_VERSION}"
        )
    if record.get("mode") != "full":
        raise ValueError("Public VM matrix presentation requires a full-mode record")

    commit = record.get("application_commit")
    if not isinstance(commit, str) or _GIT_COMMIT.fullmatch(commit) is None:
        raise ValueError("Presentation record has no valid application commit")
    _require_string(record.get("run_id"), "run_id")
    _require_string(record.get("finished_at"), "finished_at")

    completed = record.get("completed")
    passed = record.get("passed")
    exit_code = record.get("exit_code")
    if not isinstance(completed, bool) or not isinstance(passed, bool):
        raise TypeError("Presentation record completed and passed fields must be booleans")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool) or exit_code not in {0, 1, 2}:
        raise ValueError("Presentation record exit_code must be 0, 1, or 2")
    if passed != (completed and exit_code == 0):
        raise ValueError("Presentation record passed status is inconsistent")

    raw_images = record.get("images")
    if not isinstance(raw_images, list) or not raw_images:
        raise ValueError("Presentation record must contain at least one image")

    images: list[dict[str, Any]] = []
    labels: set[str] = set()
    for index, raw_image in enumerate(raw_images):
        if not isinstance(raw_image, dict):
            raise TypeError(f"Presentation image {index} must be an object")
        label = _require_string(raw_image.get("label"), f"images[{index}].label")
        status = _require_string(raw_image.get("status"), f"images[{index}].status")
        if status not in {PASS, TEST_FAILED, INFRASTRUCTURE_FAILED}:
            raise ValueError(f"Presentation image {label!r} has invalid status {status!r}")
        if label in labels:
            raise ValueError(f"Presentation record contains duplicate image label {label!r}")
        labels.add(label)
        images.append(raw_image)

    if passed and any(image["status"] != PASS for image in images):
        raise ValueError("Passing presentation record contains a non-passing image")
    if passed:
        for image in images:
            label = image["label"]
            guest = image.get("guest")
            checks = image.get("checks")
            if not isinstance(guest, dict):
                raise TypeError(f"Passing presentation image {label!r} has no guest evidence")
            if not isinstance(checks, dict):
                raise TypeError(f"Passing presentation image {label!r} has no checks evidence")
            pytest_result = checks.get("pytest")
            if not isinstance(pytest_result, dict) or pytest_result.get("status") != "passed":
                raise ValueError(f"Passing presentation image {label!r} has no passing pytest result")
            if _mypy_presentation(checks, label) != "PASS":
                raise ValueError(f"Passing presentation image {label!r} has no passing mypy result")
    return images


def _display_version(value: object, prefix: str, field: str) -> str:
    """Extract a concise version following a required product prefix.

    Args:
        value: Recorded tool version.
        prefix: Required prefix before the concise version.
        field: Field name used in errors.

    Returns:
        Version text before optional comma-separated attribution.

    Raises:
        ValueError: If the value is missing or does not use the expected format.
    """
    text_value = _require_string(value, field)
    if not text_value.startswith(prefix):
        raise ValueError(f"{field} must start with {prefix!r}")
    version = text_value[len(prefix):].split(",", 1)[0].strip()
    if not version:
        raise ValueError(f"{field} contains no version after {prefix!r}")
    return version


def _optional_display_version(value: object, prefix: str) -> str:
    """Extract a version when failed-run evidence contains one.

    Args:
        value: Optional recorded tool version.
        prefix: Expected prefix before the concise version.

    Returns:
        Concise version text, or ``not available`` for incomplete evidence.
    """
    if not isinstance(value, str) or not value.startswith(prefix):
        return "not available"
    version = value[len(prefix):].split(",", 1)[0].strip()
    return version if version else "not available"


def _markdown_table_cell(value: object) -> str:
    """Escape one value for safe use in a Markdown table cell.

    Args:
        value: Value to render.

    Returns:
        Single-line Markdown table-cell text.
    """
    normalized = " ".join(str(value).splitlines()).strip()
    return normalized.replace("\\", "\\\\").replace("|", "\\|")


def _pytest_presentation(checks: object, label: str) -> str:
    """Render concise pytest counts for one image.

    Args:
        checks: Image checks object from public evidence.
        label: Image label used in errors.

    Returns:
        Human-readable pytest result counts, or ``not run``.

    Raises:
        TypeError: If recorded pytest evidence has invalid types.
        ValueError: If recorded pytest counts are negative.
    """
    if checks is None:
        return "not run"
    if not isinstance(checks, dict):
        raise TypeError(f"Checks for {label} must be an object")
    pytest_result = checks.get("pytest")
    if pytest_result is None:
        return "not run"
    if not isinstance(pytest_result, dict):
        raise TypeError(f"pytest evidence for {label} must be an object")
    summary = pytest_result.get("summary")
    if not isinstance(summary, dict):
        raise TypeError(f"pytest summary for {label} must be an object")

    counts: dict[str, int] = {}
    for field in ("passed", "skipped", "failed", "error", "errors"):
        value = summary.get(field, 0)
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"pytest {field} count for {label} must be an integer")
        if value < 0:
            raise ValueError(f"pytest {field} count for {label} must not be negative")
        counts[field] = value
    failure_count = counts["failed"] + counts["error"] + counts["errors"]
    return (
        f"{counts['passed']} passed, {counts['skipped']} skipped, "
        f"{failure_count} failed"
    )


def _mypy_presentation(checks: object, label: str) -> str:
    """Render the mypy status for one image.

    Args:
        checks: Image checks object from public evidence.
        label: Image label used in errors.

    Returns:
        Uppercase mypy status, or ``not run``.

    Raises:
        TypeError: If recorded mypy evidence has invalid types.
        ValueError: If the mypy status is empty.
    """
    if checks is None:
        return "not run"
    if not isinstance(checks, dict):
        raise TypeError(f"Checks for {label} must be an object")
    mypy_result = checks.get("mypy")
    if mypy_result is None:
        return "not run"
    if isinstance(mypy_result, str):
        status = _require_string(mypy_result, f"mypy status for {label}")
    else:
        if not isinstance(mypy_result, dict):
            raise TypeError(f"mypy evidence for {label} must be an object")
        status = _require_string(mypy_result.get("status"), f"mypy status for {label}")
    return {"passed": "PASS", "failed": "FAIL"}.get(status.casefold(), status.upper())


def _image_presentation_row(image: dict[str, Any]) -> str:
    """Render one Markdown table row from public image evidence.

    Args:
        image: Validated image evidence.

    Returns:
        Markdown table row.

    Raises:
        TypeError: If nested evidence has invalid types.
        ValueError: If required passing-image evidence is missing or malformed.
    """
    label = _require_string(image.get("label"), "image label")
    status = _require_string(image.get("status"), f"status for {label}")
    guest = image.get("guest")
    checks = image.get("checks")
    if guest is None:
        values = [label, "not available", "not available", "not available"]
    else:
        if not isinstance(guest, dict):
            raise TypeError(f"Guest evidence for {label} must be an object")
        if status == PASS:
            values = [
                _require_string(guest.get("os_release"), f"OS release for {label}"),
                _display_version(guest.get("python"), "Python ", f"Python version for {label}"),
                _display_version(guest.get("dar"), "dar version ", f"DAR version for {label}"),
                _display_version(guest.get("par2"), "par2cmdline version ", f"PAR2 version for {label}"),
            ]
        else:
            os_release = guest.get("os_release")
            values = [
                os_release.strip() if isinstance(os_release, str) and os_release.strip() else "not available",
                _optional_display_version(guest.get("python"), "Python "),
                _optional_display_version(guest.get("dar"), "dar version "),
                _optional_display_version(guest.get("par2"), "par2cmdline version "),
            ]
    values.extend(
        [
            _pytest_presentation(checks, label),
            _mypy_presentation(checks, label),
            status.replace("_", " "),
        ]
    )
    return "| " + " | ".join(_markdown_table_cell(value) for value in values) + " |"


def _matrix_resource_text(images: Sequence[dict[str, Any]]) -> str:
    """Describe shared VM resources when every matrix entry matches.

    Args:
        images: Validated matrix image records.

    Returns:
        Concise resource sentence, or a per-image fallback.

    Raises:
        TypeError: If resource evidence has invalid types.
        ValueError: If resource evidence is missing or invalid.
    """
    resources: list[tuple[int, str, str]] = []
    for image in images:
        label = _require_string(image.get("label"), "image label")
        raw_resources = image.get("resources")
        if not isinstance(raw_resources, dict):
            raise TypeError(f"Resources for {label} must be an object")
        cpus = raw_resources.get("cpus")
        memory = _require_string(raw_resources.get("memory"), f"memory for {label}")
        disk = _require_string(raw_resources.get("disk"), f"disk for {label}")
        if not isinstance(cpus, int) or isinstance(cpus, bool) or cpus < 1:
            raise ValueError(f"CPU count for {label} must be a positive integer")
        resources.append((cpus, memory, disk))

    if len(set(resources)) == 1:
        cpus, memory, disk = resources[0]
        return f"Each VM uses {cpus} vCPUs, {memory} RAM, and a {disk} virtual disk."
    return "VM resources are recorded per image in the detailed matrix history."


def render_vm_matrix_badge(record: dict[str, Any]) -> dict[str, Any]:
    """Build a Shields endpoint payload for the latest full VM matrix.

    Args:
        record: Schema-v2 full VM matrix history record.

    Returns:
        Shields endpoint JSON object.

    Raises:
        TypeError: If required evidence has invalid types.
        ValueError: If required evidence is missing or inconsistent.
    """
    images = _presentation_images(record)
    versions = [
        _require_string(image.get("label"), "image label").removeprefix("ubuntu-")
        for image in images
    ]
    version_text = " + ".join(versions)
    completed = record["completed"]
    exit_code = record["exit_code"]
    if record["passed"]:
        message = f"{version_text} passing"
        color = "brightgreen"
        is_error = False
    elif not completed or exit_code == 2:
        message = "matrix infrastructure failure"
        color = "orange"
        is_error = True
    else:
        message = f"{version_text} tests failing"
        color = "red"
        is_error = True
    return {
        "schemaVersion": 1,
        "label": "Ubuntu VM matrix",
        "message": message,
        "color": color,
        "isError": is_error,
    }


def render_vm_matrix_readme_block(record: dict[str, Any]) -> str:
    """Render the generated README section for one full matrix record.

    Args:
        record: Schema-v2 full VM matrix history record.

    Returns:
        Marker-delimited Markdown section ending in one newline.

    Raises:
        TypeError: If required evidence has invalid types.
        ValueError: If required evidence is missing or inconsistent.
    """
    images = _presentation_images(record)
    commit = _require_string(record.get("application_commit"), "application_commit")
    finished_at = _require_string(record.get("finished_at"), "finished_at")
    if record["passed"]:
        outcome = "PASS"
    elif not record["completed"] or record["exit_code"] == 2:
        outcome = "INFRASTRUCTURE FAILURE"
    else:
        outcome = "TEST FAILURE"
    rows = "\n".join(_image_presentation_row(image) for image in images)
    commit_url = f"{_GITHUB_REPOSITORY_URL}/commit/{commit}"
    return (
        f"{_README_RESULTS_BEGIN}\n\n"
        "## Tested on Ubuntu LTS VMs\n\n"
        "`dar-backup` is tested in fresh Ubuntu LTS Multipass VMs created from the\n"
        "standard Ubuntu images. Each VM installs the distribution's DAR, PAR2, and\n"
        "Python dependencies before running the full pytest suite and mypy.\n\n"
        f"**Latest full VM matrix:** {outcome} at `{finished_at}` for\n"
        f"[commit `{commit[:12]}`]({commit_url}).\n\n"
        "| Ubuntu | Python | DAR | PAR2 | pytest | mypy | Result |\n"
        "|---|---:|---:|---:|---|---|---|\n"
        f"{rows}\n\n"
        f"{_matrix_resource_text(images)}\n\n"
        "[VM test methodology](v2/vm_test/README.md) · "
        "[Detailed and historical results](v2/doc/test-report/vm-matrix-results.jsonl)\n\n"
        f"{_README_RESULTS_END}\n"
    )


def _replace_generated_readme_block(readme_path: Path, generated_block: str) -> None:
    """Replace exactly one generated VM matrix block in a README.

    Args:
        readme_path: Tracked root README path.
        generated_block: Complete marker-delimited replacement.

    Returns:
        None.

    Raises:
        OSError: If the README cannot be read or written.
        ValueError: If either the README or replacement markers are invalid.
    """
    if generated_block.count(_README_RESULTS_BEGIN) != 1 or generated_block.count(_README_RESULTS_END) != 1:
        raise ValueError("Generated README block must contain exactly one marker pair")
    original = readme_path.read_text(encoding="utf-8")
    if original.count(_README_RESULTS_BEGIN) != 1 or original.count(_README_RESULTS_END) != 1:
        raise ValueError(f"README must contain exactly one VM matrix marker pair: {readme_path}")
    start = original.index(_README_RESULTS_BEGIN)
    end = original.index(_README_RESULTS_END)
    if end < start:
        raise ValueError(f"README VM matrix markers are reversed: {readme_path}")
    end += len(_README_RESULTS_END)
    updated = original[:start] + generated_block.rstrip("\n") + original[end:]
    if updated == original:
        return

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=f".{readme_path.name}.",
            suffix=".tmp",
            dir=readme_path.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(updated)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_path, readme_path.stat().st_mode & 0o777)
        os.replace(temporary_path, readme_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _write_public_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write a world-readable tracked JSON artifact.

    Args:
        path: Destination JSON path.
        payload: Serializable JSON object.

    Returns:
        None.

    Raises:
        OSError: If the file cannot be written or its mode cannot be set.
        TypeError: If the payload is not JSON serializable.
    """
    existing_mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    write_json(path, payload)
    # NamedTemporaryFile starts private; tracked badge data must remain readable
    # by the local web server or any other account serving the checkout.
    os.chmod(path, existing_mode)


def publish_vm_matrix_presentation(
    record: dict[str, Any],
    readme_path: Path,
    badge_path: Path,
) -> None:
    """Publish a README block and badge from one validated matrix record.

    Args:
        record: Schema-v2 full VM matrix history record.
        readme_path: Root README containing the generated markers.
        badge_path: Tracked Shields endpoint JSON path.

    Returns:
        None.

    Raises:
        OSError: If an output cannot be read or written.
        TypeError: If matrix evidence has invalid types.
        ValueError: If evidence or README markers are invalid.
    """
    readme_block = render_vm_matrix_readme_block(record)
    badge = render_vm_matrix_badge(record)
    _replace_generated_readme_block(readme_path, readme_block)
    _write_public_json(badge_path, badge)


def read_latest_full_history_record(history_path: Path) -> dict[str, Any]:
    """Read the newest schema-v2 full matrix record from tracked history.

    Args:
        history_path: JSONL VM matrix history.

    Returns:
        Newest validated full-mode record.

    Raises:
        OSError: If history cannot be read.
        TypeError: If a history line is not a JSON object.
        ValueError: If history is malformed or has no publishable full record.
    """
    latest: dict[str, Any] | None = None
    for line_number, line in enumerate(history_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw_record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Malformed JSONL history at {history_path}:{line_number}: {exc.msg}"
            ) from exc
        if not isinstance(raw_record, dict):
            raise TypeError(f"JSONL history record at {history_path}:{line_number} must be an object")
        if raw_record.get("schema_version") == HISTORY_SCHEMA_VERSION and raw_record.get("mode") == "full":
            _presentation_images(raw_record)
            latest = raw_record
    if latest is None:
        raise ValueError(f"No schema-v{HISTORY_SCHEMA_VERSION} full matrix record found in {history_path}")
    return latest


def _read_optional_json_object(path: Path) -> dict[str, Any] | None:
    """Read an optional JSON object while rejecting malformed evidence.

    Args:
        path: JSON path that may be absent.

    Returns:
        Parsed object, or ``None`` when the path does not exist.

    Raises:
        OSError: If an existing file cannot be read.
        ValueError: If an existing file is not a JSON object.
    """
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON evidence {path}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise TypeError(f"JSON evidence must contain an object: {path}")
    return payload


def _optional_public_string(payload: dict[str, Any], key: str) -> str | None:
    """Return one optional non-empty string from a JSON object.

    Args:
        payload: Parsed JSON object.
        key: Field to read.

    Returns:
        The string value, or ``None`` when absent or empty.

    Raises:
        ValueError: If a present value is not a string.
    """
    value = payload.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise TypeError(f"Guest evidence field {key!r} must be a string")
    return value


def _canonical_json_sha256(payload: object) -> str:
    """Return the SHA-256 of compact, key-sorted UTF-8 JSON.

    Args:
        payload: JSON-serializable value.

    Returns:
        Lowercase SHA-256 digest.

    Raises:
        TypeError: If the value cannot be serialized as JSON.
        ValueError: If the value contains a non-finite number.
    """
    canonical = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _package_manifest_sha256(manifest: dict[str, str]) -> str:
    """Return the SHA-256 of one canonical Debian package manifest.

    Args:
        manifest: Installed package-and-architecture keys mapped to versions.

    Returns:
        Lowercase SHA-256 digest.
    """
    return _canonical_json_sha256(manifest)


def _package_manifest_evidence(
    guest: dict[str, Any],
    label: str,
    required: bool,
) -> tuple[dict[str, str] | None, str | None]:
    """Validate package manifest evidence returned by one guest.

    Args:
        guest: Parsed guest result object.
        label: Public image label used in diagnostic errors.
        required: Whether omission must fail evidence generation.

    Returns:
        Sorted installed-package mapping and its verified SHA-256, or two
        None values when optional evidence is absent.

    Raises:
        TypeError: If manifest fields have invalid JSON types.
        ValueError: If entries or the digest are invalid or inconsistent.
    """
    raw_manifest = guest.get("package_manifest")
    raw_sha256 = guest.get("package_manifest_sha256")
    if raw_manifest is None and raw_sha256 is None:
        if required:
            raise ValueError(f"Completed guest result has no package manifest for {label}")
        return None, None
    if not isinstance(raw_manifest, dict):
        raise TypeError(f"Package manifest is not an object for {label}")
    if not raw_manifest:
        raise ValueError(f"Package manifest is empty for {label}")
    if not isinstance(raw_sha256, str) or _SHA256.fullmatch(raw_sha256) is None:
        raise ValueError(f"Package manifest SHA-256 is invalid for {label}")

    manifest: dict[str, str] = {}
    for package_key, version in raw_manifest.items():
        if (
            not isinstance(package_key, str)
            or _DEBIAN_PACKAGE_KEY.fullmatch(package_key) is None
        ):
            raise ValueError(f"Invalid Debian package key {package_key!r} for {label}")
        if (
            not isinstance(version, str)
            or not version
            or any(character in version for character in "\r\n\t")
        ):
            raise ValueError(f"Invalid version for Debian package {package_key!r} in {label}")
        manifest[package_key] = version

    manifest = dict(sorted(manifest.items()))
    calculated_sha256 = _package_manifest_sha256(manifest)
    if calculated_sha256 != raw_sha256:
        raise ValueError(f"Package manifest SHA-256 mismatch for {label}")
    return manifest, raw_sha256


def _validate_mypy_checks(checks: object, label: str) -> dict[str, Any]:
    """Validate and normalize effective mypy check configuration.

    Args:
        checks: Parsed checks object from the mypy artifact.
        label: Public image label used in diagnostic errors.

    Returns:
        Validated checks object with deterministically ordered collections.

    Raises:
        TypeError: If checks contain invalid JSON types.
        ValueError: If checks contain invalid values or ordering.
    """
    if not isinstance(checks, dict):
        raise TypeError(f"mypy checks is not an object for {label}")

    python_version = _require_string(
        checks.get("python_version"),
        f"mypy Python version for {label}",
    )
    platform = _require_string(checks.get("platform"), f"mypy platform for {label}")
    raw_codes = checks.get("enabled_error_codes")
    if not isinstance(raw_codes, list):
        raise TypeError(f"mypy enabled_error_codes is not an array for {label}")
    if not raw_codes:
        raise ValueError(f"mypy enabled_error_codes is empty for {label}")
    if not all(
        isinstance(code, str) and _MYPY_ERROR_CODE.fullmatch(code) is not None
        for code in raw_codes
    ):
        raise ValueError(f"mypy enabled_error_codes contains an invalid code for {label}")
    codes = sorted(set(raw_codes))
    if len(codes) != len(raw_codes):
        raise ValueError(f"mypy enabled_error_codes contains duplicates for {label}")

    raw_options = checks.get("options")
    if not isinstance(raw_options, dict) or not raw_options:
        raise TypeError(f"mypy options is not a non-empty object for {label}")
    options: dict[str, bool | str] = {}
    for name, value in sorted(raw_options.items()):
        if not isinstance(name, str) or not name:
            raise ValueError(f"mypy option name is invalid for {label}")
        if not isinstance(value, (bool, str)):
            raise TypeError(f"mypy option {name!r} has an invalid type for {label}")
        options[name] = value

    raw_overrides = checks.get("module_overrides")
    if not isinstance(raw_overrides, dict):
        raise TypeError(f"mypy module_overrides is not an object for {label}")
    module_overrides: dict[str, dict[str, Any]] = {}
    for module, raw_values in sorted(raw_overrides.items()):
        if not isinstance(module, str) or not module:
            raise ValueError(f"mypy module override name is invalid for {label}")
        if not isinstance(raw_values, dict):
            raise TypeError(f"mypy module override {module!r} is not an object for {label}")
        values: dict[str, Any] = {}
        for name, value in sorted(raw_values.items()):
            if not isinstance(name, str) or not name:
                raise ValueError(f"mypy override option name is invalid for {label}")
            if isinstance(value, list):
                if not all(isinstance(item, str) for item in value):
                    raise TypeError(
                        f"mypy override option {name!r} has an invalid list for {label}"
                    )
                values[name] = sorted(value)
            elif isinstance(value, (bool, int, str)) or value is None:
                values[name] = value
            else:
                raise TypeError(
                    f"mypy override option {name!r} has an invalid type for {label}"
                )
        module_overrides[module] = values

    return {
        "python_version": python_version,
        "platform": platform,
        "enabled_error_codes": codes,
        "options": options,
        "module_overrides": module_overrides,
    }


def _mypy_evidence(
    image_result_dir: Path,
    label: str,
    required: bool,
) -> dict[str, Any] | None:
    """Extract validated mypy summary evidence from one guest artifact.

    Args:
        image_result_dir: Retrieved per-image result directory.
        label: Public image label used in diagnostic errors.
        required: Whether omission must fail evidence generation.

    Returns:
        Compact mypy evidence, or None when optional evidence is absent.

    Raises:
        OSError: If the report cannot be read.
        TypeError: If report fields have invalid types.
        ValueError: If report values or internal counts are inconsistent.
    """
    report_path = image_result_dir / "pytest" / "mypy.json"
    payload = _read_optional_json_object(report_path)
    if payload is None:
        if required:
            raise ValueError(f"Completed guest result has no mypy evidence for {label}")
        return None

    schema_version = payload.get("schema_version")
    if schema_version != 1:
        raise ValueError(f"Unsupported mypy report schema for {label}: {schema_version!r}")
    version = _require_string(payload.get("version"), f"mypy version for {label}")
    target = _require_string(payload.get("target"), f"mypy target for {label}")
    status = payload.get("status")
    if status not in {"passed", "failed", "error"}:
        raise ValueError(f"Invalid mypy status for {label}: {status!r}")
    exit_code = payload.get("exit_code")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool) or exit_code < 0:
        raise ValueError(f"Invalid mypy exit code for {label}")
    expected_status = "passed" if exit_code == 0 else "failed" if exit_code == 1 else "error"
    if status != expected_status:
        raise ValueError(f"mypy status and exit code disagree for {label}")

    checks = _validate_mypy_checks(payload.get("checks"), label)
    checks_sha256 = payload.get("checks_sha256")
    if not isinstance(checks_sha256, str) or _SHA256.fullmatch(checks_sha256) is None:
        raise ValueError(f"Invalid mypy checks SHA-256 for {label}")
    if _canonical_json_sha256(checks) != checks_sha256:
        raise ValueError(f"mypy checks SHA-256 mismatch for {label}")

    raw_summary = payload.get("summary")
    if not isinstance(raw_summary, dict):
        raise TypeError(f"mypy summary is not an object for {label}")
    summary: dict[str, int] = {}
    for field in ("errors", "notes", "warnings", "files_with_errors", "diagnostics"):
        value = raw_summary.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"Invalid mypy summary field {field!r} for {label}")
        summary[field] = value

    diagnostics = payload.get("diagnostics")
    if not isinstance(diagnostics, list):
        raise TypeError(f"mypy diagnostics is not an array for {label}")
    severity_counts = {"error": 0, "note": 0, "warning": 0}
    files_with_errors: set[str] = set()
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, dict):
            raise TypeError(f"mypy diagnostic is not an object for {label}")
        file_name = _require_string(diagnostic.get("file"), f"mypy diagnostic file for {label}")
        _require_string(diagnostic.get("message"), f"mypy diagnostic message for {label}")
        severity = _require_string(
            diagnostic.get("severity"),
            f"mypy diagnostic severity for {label}",
        ).casefold()
        if severity not in severity_counts:
            raise ValueError(f"mypy diagnostic has an unsupported severity for {label}")
        severity_counts[severity] += 1
        if severity == "error":
            files_with_errors.add(file_name)

    expected_summary = {
        "errors": severity_counts["error"],
        "notes": severity_counts["note"],
        "warnings": severity_counts["warning"],
        "files_with_errors": len(files_with_errors),
        "diagnostics": len(diagnostics),
    }
    if summary != expected_summary:
        raise ValueError(f"mypy diagnostic counts do not match summary for {label}")
    if status == "passed" and summary["errors"] != 0:
        raise ValueError(f"passing mypy report contains errors for {label}")
    if status == "failed" and summary["errors"] == 0:
        raise ValueError(f"failed mypy report contains no errors for {label}")

    return {
        "status": status,
        "version": version,
        "exit_code": exit_code,
        "target": target,
        "checks": checks,
        "checks_sha256": checks_sha256,
        "summary": summary,
    }


def _skip_reason(longrepr: object, nodeid: str, report_path: Path) -> str:
    """Extract a public skip reason from pytest-json-report phase evidence.

    Args:
        longrepr: Serialized pytest skip representation.
        nodeid: Pytest node ID used for diagnostic errors.
        report_path: Source report used for diagnostic errors.

    Returns:
        Non-empty skip reason without pytest's ``Skipped:`` prefix.

    Raises:
        TypeError: If the skip representation is not a string.
        ValueError: If the skip representation has no reason.
    """
    if not isinstance(longrepr, str):
        raise TypeError(f"pytest skip reason for {nodeid!r} is not a string in {report_path}")

    reason = longrepr
    try:
        parsed = ast.literal_eval(longrepr)
    except (SyntaxError, ValueError):
        parsed = None
    if (
        isinstance(parsed, tuple)
        and len(parsed) >= 3
        and isinstance(parsed[2], str)
    ):
        reason = parsed[2]

    prefix = "Skipped:"
    reason = reason.strip()
    if reason.startswith(prefix):
        reason = reason.removeprefix(prefix).strip()
    if not reason:
        raise ValueError(f"pytest skip reason for {nodeid!r} is empty in {report_path}")
    return reason


def _pytest_skips(payload: dict[str, Any], report_path: Path) -> list[dict[str, str]]:
    """Return sorted skipped test names and reasons from a pytest JSON report.

    Args:
        payload: Parsed pytest-json-report object.
        report_path: Source report used for diagnostic errors.

    Returns:
        Skip evidence sorted by pytest node ID and reason.

    Raises:
        TypeError: If test or phase evidence has an invalid type.
        ValueError: If skipped test evidence is incomplete.
    """
    tests = payload.get("tests")
    if not isinstance(tests, list):
        raise TypeError(f"pytest tests is not an array in {report_path}")

    skips: list[dict[str, str]] = []
    for test in tests:
        if not isinstance(test, dict):
            raise TypeError(f"pytest test entry is not an object in {report_path}")
        if test.get("outcome") != "skipped":
            continue

        nodeid = test.get("nodeid")
        if not isinstance(nodeid, str) or not nodeid.strip():
            raise ValueError(f"pytest skipped test has no nodeid in {report_path}")

        skip_phase: dict[str, Any] | None = None
        for phase_name in ("setup", "call", "teardown"):
            phase = test.get(phase_name)
            if phase is None:
                continue
            if not isinstance(phase, dict):
                raise TypeError(
                    f"pytest phase {phase_name!r} for {nodeid!r} is not an object "
                    f"in {report_path}"
                )
            if phase.get("outcome") == "skipped":
                skip_phase = phase
                break
        if skip_phase is None:
            raise ValueError(f"pytest skipped test {nodeid!r} has no skipped phase in {report_path}")

        skips.append(
            {
                "test": nodeid,
                "reason": _skip_reason(skip_phase.get("longrepr"), nodeid, report_path),
            }
        )

    return sorted(skips, key=lambda skip: (skip["test"], skip["reason"]))


def _concise_failure_message(value: object, context: str) -> str:
    """Normalize one pytest failure message for compact public evidence.

    Args:
        value: Raw crash message or long representation.
        context: Test or collector identity used in diagnostic errors.

    Returns:
        Single-line message, truncated deterministically when necessary.

    Raises:
        TypeError: If the message is not a string.
        ValueError: If the normalized message is empty.
    """
    if not isinstance(value, str):
        raise TypeError(f"pytest failure message for {context!r} is not a string")
    message = " ".join(value.split())
    message = _PYTEST_TEMP_ROOT.sub("<pytest-tmp>", message)
    if not message:
        raise ValueError(f"pytest failure message for {context!r} is empty")
    if len(message) > _FAILURE_MESSAGE_LIMIT:
        return message[: _FAILURE_MESSAGE_LIMIT - 1] + "…"
    return message


def _terminal_failure_message(value: object, context: str) -> str:
    """Extract the final non-empty line from a pytest long representation.

    Args:
        value: Raw pytest long representation.
        context: Test or collector identity used in diagnostic errors.

    Returns:
        Concise terminal exception line.

    Raises:
        TypeError: If the representation is not a string.
        ValueError: If the representation has no non-empty line.
    """
    if not isinstance(value, str):
        raise TypeError(f"pytest long representation for {context!r} is not a string")
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"pytest long representation for {context!r} is empty")
    return _concise_failure_message(lines[-1], context)


def _pytest_stage_message(stage: dict[str, Any], nodeid: str) -> str:
    """Extract a concise message from one failed pytest stage.

    Args:
        stage: pytest-json-report setup, call, or teardown object.
        nodeid: Pytest node ID used in diagnostic errors.

    Returns:
        Concise structured crash message or long-representation fallback.

    Raises:
        TypeError: If crash or message fields have invalid types.
        ValueError: If no usable message exists.
    """
    crash = stage.get("crash")
    if crash is not None:
        if not isinstance(crash, dict):
            raise TypeError(f"pytest crash for {nodeid!r} is not an object")
        message = crash.get("message")
        if message is not None:
            return _concise_failure_message(message, nodeid)
    return _terminal_failure_message(stage.get("longrepr"), nodeid)


def _pytest_failures(
    payload: dict[str, Any],
    report_path: Path,
    exit_code: int,
    summary: dict[str, int],
) -> list[dict[str, str]]:
    """Return deterministic pytest test, collection, and session failures.

    Args:
        payload: Parsed pytest-json-report object.
        report_path: Source report used for diagnostic errors.
        exit_code: Pytest process exit code.
        summary: Normalized pytest summary counts.

    Returns:
        Compact failure evidence sorted by test, phase, kind, and message.

    Raises:
        TypeError: If test, stage, or collector evidence has invalid types.
        ValueError: If failure details are incomplete or contradict summary counts.
    """
    tests = payload.get("tests")
    if not isinstance(tests, list):
        raise TypeError(f"pytest tests is not an array in {report_path}")

    failures: list[dict[str, str]] = []
    failed_tests = 0
    error_tests = 0
    for test in tests:
        if not isinstance(test, dict):
            raise TypeError(f"pytest test entry is not an object in {report_path}")
        outcome = test.get("outcome")
        if outcome not in {"failed", "error"}:
            continue
        nodeid = test.get("nodeid")
        if not isinstance(nodeid, str) or not nodeid.strip():
            raise ValueError(f"pytest failed test has no nodeid in {report_path}")

        if outcome == "failed":
            failed_tests += 1
        else:
            error_tests += 1

        found_failed_stage = False
        for phase_name in ("setup", "call", "teardown"):
            stage = test.get(phase_name)
            if stage is None:
                continue
            if not isinstance(stage, dict):
                raise TypeError(
                    f"pytest phase {phase_name!r} for {nodeid!r} is not an object "
                    f"in {report_path}"
                )
            if stage.get("outcome") != "failed":
                continue
            found_failed_stage = True
            kind = "failure" if outcome == "failed" and phase_name == "call" else "error"
            failures.append(
                {
                    "test": nodeid,
                    "phase": phase_name,
                    "kind": kind,
                    "message": _pytest_stage_message(stage, nodeid),
                }
            )
        if not found_failed_stage:
            raise ValueError(f"pytest failed test {nodeid!r} has no failed phase in {report_path}")

    expected_errors = max(summary["error"], summary["errors"])
    if summary["error"] and summary["errors"] and summary["error"] != summary["errors"]:
        raise ValueError(f"pytest error summary fields disagree in {report_path}")
    if failed_tests != summary["failed"]:
        raise ValueError(
            f"pytest failure detail count {failed_tests} does not match summary count "
            f"{summary['failed']} in {report_path}"
        )
    if error_tests != expected_errors:
        raise ValueError(
            f"pytest error detail count {error_tests} does not match summary count "
            f"{expected_errors} in {report_path}"
        )

    collectors = payload.get("collectors", [])
    if not isinstance(collectors, list):
        raise TypeError(f"pytest collectors is not an array in {report_path}")
    for collector in collectors:
        if not isinstance(collector, dict):
            raise TypeError(f"pytest collector entry is not an object in {report_path}")
        if collector.get("outcome") != "failed":
            continue
        raw_nodeid = collector.get("nodeid")
        if not isinstance(raw_nodeid, str):
            raise TypeError(f"pytest failed collector has an invalid nodeid in {report_path}")
        nodeid = raw_nodeid.strip() or "<collection>"
        failures.append(
            {
                "test": nodeid,
                "phase": "collection",
                "kind": "collection_error",
                "message": _terminal_failure_message(collector.get("longrepr"), nodeid),
            }
        )

    if exit_code != 0 and not failures:
        session_kinds = {
            1: "tests_failed",
            2: "interrupted",
            3: "internal_error",
            4: "usage_error",
            5: "no_tests_collected",
        }
        failures.append(
            {
                "test": "<session>",
                "phase": "session",
                "kind": session_kinds.get(exit_code, "unknown_exit"),
                "message": f"pytest exited with status {exit_code}",
            }
        )

    return sorted(
        failures,
        key=lambda failure: (
            failure["test"],
            failure["phase"],
            failure["kind"],
            failure["message"],
        ),
    )


def _pytest_evidence(image_result_dir: Path) -> dict[str, Any] | None:
    """Extract badge-safe pytest evidence from one retrieved JSON report.

    Args:
        image_result_dir: Retrieved per-image result directory.

    Returns:
        Normalized pytest evidence, or ``None`` when pytest did not produce a
        structured report.

    Raises:
        OSError: If a report cannot be read.
        TypeError: If report fields have invalid types.
        ValueError: If report count, structure, or values are invalid.
    """
    report_paths = sorted((image_result_dir / "pytest").glob("dar-backup-*__pytest-*.json"))
    if not report_paths:
        return None
    if len(report_paths) != 1:
        raise ValueError(
            f"Expected one pytest JSON report for {image_result_dir.name}, found {len(report_paths)}"
        )
    payload = _read_optional_json_object(report_paths[0])
    if payload is None:
        return None

    exit_code = payload.get("exitcode")
    duration = payload.get("duration")
    summary = payload.get("summary")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise TypeError(f"pytest exitcode is not an integer in {report_paths[0]}")
    if not isinstance(duration, (int, float)) or isinstance(duration, bool):
        raise TypeError(f"pytest duration is not numeric in {report_paths[0]}")
    if not math.isfinite(float(duration)) or duration < 0:
        raise ValueError(f"pytest duration is invalid in {report_paths[0]}")
    if not isinstance(summary, dict):
        raise TypeError(f"pytest summary is not an object in {report_paths[0]}")

    normalized_summary: dict[str, int] = {}
    for key in (
        "passed",
        "failed",
        "skipped",
        "error",
        "errors",
        "xfailed",
        "xpassed",
        "deselected",
        "collected",
        "total",
    ):
        value = summary.get(key, 0)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"pytest summary field {key!r} is invalid in {report_paths[0]}")
        normalized_summary[key] = value

    skips = _pytest_skips(payload, report_paths[0])
    if len(skips) != normalized_summary["skipped"]:
        raise ValueError(
            f"pytest skip detail count {len(skips)} does not match summary count "
            f"{normalized_summary['skipped']} in {report_paths[0]}"
        )
    failures = _pytest_failures(
        payload,
        report_paths[0],
        exit_code,
        normalized_summary,
    )

    return {
        "status": "passed" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "duration_seconds": round(float(duration), 3),
        "summary": normalized_summary,
        "skips": skips,
        "failures": failures,
    }


def _image_history_evidence(
    spec: ImageSpec,
    result: ImageRunResult,
    mode: str,
    application_commit: str,
    orchestration_commit: str,
) -> dict[str, Any]:
    """Build one public-safe image result for tracked history.

    Args:
        spec: Requested VM image and resources.
        result: Controller outcome for that image.
        mode: Expected pytest matrix mode.
        application_commit: Expected immutable application commit.
        orchestration_commit: Expected immutable tooling commit.

    Returns:
        JSON-serializable image evidence without host-local paths or identities.

    Raises:
        OSError: If retrieved evidence cannot be read.
        ValueError: If retrieved evidence is malformed.
    """
    image_result_dir = Path(result.result_directory)
    guest = _read_optional_json_object(image_result_dir / "result.json")
    pytest_result = _pytest_evidence(image_result_dir)
    mypy_result = _mypy_evidence(
        image_result_dir,
        spec.label,
        required=result.guest_status in {PASS, TEST_FAILED},
    )

    if (result.image_release is None) != (result.image_sha256 is None):
        raise ValueError(f"Incomplete source-image provenance for {spec.label}")
    if result.guest_status is not None and result.image_sha256 is None:
        raise ValueError(f"Completed guest result has no source-image provenance for {spec.label}")
    if result.image_release is not None and not result.image_release.strip():
        raise ValueError(f"Source-image release is empty for {spec.label}")
    if (
        result.image_sha256 is not None
        and _SHA256.fullmatch(result.image_sha256) is None
    ):
        raise ValueError(f"Source-image SHA-256 is invalid for {spec.label}")

    guest_evidence: dict[str, Any] | None = None
    if guest is not None:
        expected_guest_fields = {
            "status": result.guest_status,
            "exit_code": result.exit_code,
            "mode": mode,
            "application_commit": application_commit,
            "orchestration_commit": orchestration_commit,
        }
        for field, expected in expected_guest_fields.items():
            if guest.get(field) != expected:
                raise ValueError(
                    f"Guest evidence field {field!r} for {spec.label} does not match "
                    "the controller result"
                )
        package_manifest, package_manifest_sha256 = _package_manifest_evidence(
            guest,
            spec.label,
            required=result.guest_status in {PASS, TEST_FAILED},
        )
        guest_evidence = {
            key: _optional_public_string(guest, key)
            for key in (
                "started_at",
                "finished_at",
                "os_release",
                "kernel",
                "python",
                "pytest",
                "dar",
                "dar_manager",
                "par2",
            )
        }
        guest_evidence["package_manifest"] = package_manifest
        guest_evidence["package_manifest_sha256"] = package_manifest_sha256

    return {
        "label": spec.label,
        "image": spec.image,
        "image_release": result.image_release,
        "image_sha256": result.image_sha256,
        "resources": {
            "cpus": spec.cpus,
            "disk": spec.disk,
            "memory": spec.memory,
        },
        "status": result.status,
        "guest_status": result.guest_status,
        "exit_code": result.exit_code,
        "instance_preserved": result.instance_preserved,
        "checks": {
            "mypy": mypy_result,
            "pytest": pytest_result,
        },
        "guest": guest_evidence,
    }


def build_history_record(
    run_id: str,
    started_at: str,
    finished_at: str,
    mode: str,
    application_commit: str,
    orchestration_commit: str,
    specs: Sequence[ImageSpec],
    results: Sequence[ImageRunResult],
    completed: bool,
    aborted_phase: str | None,
    exit_code: int,
) -> dict[str, Any]:
    """Build and validate one public VM-matrix evidence record.

    Args:
        run_id: Stable UTC-time and commit identifier for the invocation.
        started_at: UTC ISO-8601 invocation start.
        finished_at: UTC ISO-8601 invocation finish.
        mode: Requested pytest matrix mode.
        application_commit: Immutable application source commit.
        orchestration_commit: Immutable VM tooling commit.
        specs: Requested VM image specifications.
        results: Completed per-image controller outcomes.
        completed: Whether every configured image was attempted.
        aborted_phase: Public-safe phase name when the matrix stopped early.
        exit_code: Final controller exit code before evidence persistence.

    Returns:
        JSON-serializable schema-v2 history record.

    Raises:
        ValueError: If required state is empty or inconsistent.
        OSError: If retrieved guest evidence cannot be read.
    """
    required_strings = {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "mode": mode,
        "application_commit": application_commit,
        "orchestration_commit": orchestration_commit,
    }
    for field, value in required_strings.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")
    if mode not in {"fast", "smoke", "integration", "full"}:
        raise ValueError(f"invalid history mode: {mode!r}")
    if exit_code not in {0, 1, 2}:
        raise ValueError(f"invalid matrix exit code: {exit_code}")
    if completed and len(results) != len(specs):
        raise ValueError("completed history requires one result per image")
    if len(results) > len(specs):
        raise ValueError("history contains more results than configured images")
    for index, result in enumerate(results):
        if result.label != specs[index].label:
            raise ValueError(
                f"result label {result.label!r} does not match image {specs[index].label!r}"
            )

    images = [
        _image_history_evidence(
            specs[index],
            result,
            mode,
            application_commit,
            orchestration_commit,
        )
        for index, result in enumerate(results)
    ]
    return {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "completed": completed,
        "aborted_phase": aborted_phase,
        "exit_code": exit_code,
        "passed": completed and exit_code == 0,
        "mode": mode,
        "application_commit": application_commit,
        "orchestration_commit": orchestration_commit,
        "images": images,
    }


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


def _instance_image_provenance(
    executor: CommandExecutor,
    instance_name: str,
    log_path: Path,
) -> tuple[str, str]:
    """Read and validate the immutable source-image identity for one instance.

    Args:
        executor: Multipass command executor.
        instance_name: Launched Multipass instance name.
        log_path: Controller diagnostic log.

    Returns:
        Multipass image release label and full lowercase SHA-256 digest.

    Raises:
        InfrastructureError: If Multipass cannot provide valid image metadata.
    """
    result = executor.run(["info", "--format", "json", instance_name], log_path)
    if result.returncode != 0:
        raise InfrastructureError(
            f"multipass info failed for {instance_name}: {result.output.strip()}"
        )

    try:
        payload = json.loads(result.output)
        errors = payload["errors"]
        info = payload["info"]
        if not isinstance(errors, list):
            raise TypeError("'errors' is not an array")
        if errors:
            raise ValueError(f"Multipass reported errors: {errors!r}")
        if not isinstance(info, dict):
            raise TypeError("'info' is not an object")
        instance = info[instance_name]
        if not isinstance(instance, dict):
            raise TypeError(f"info for {instance_name!r} is not an object")
        image_release = _require_string(
            instance.get("image_release"),
            f"image release for Multipass instance {instance_name}",
        )
        image_sha256 = _require_string(
            instance.get("image_hash"),
            f"image SHA-256 for Multipass instance {instance_name}",
        ).lower()
        if _SHA256.fullmatch(image_sha256) is None:
            raise ValueError(f"image hash is not a full SHA-256: {image_sha256!r}")
        return image_release, image_sha256
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise InfrastructureError(
            f"Cannot parse image provenance for Multipass instance {instance_name}: {exc}"
        ) from exc


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
    image_release: str | None = None
    image_sha256: str | None = None
    status = INFRASTRUCTURE_FAILED
    message = "VM test did not complete"

    try:
        existing = _list_instances(executor, controller_log)
        if spec.instance_name in existing:
            _append_log(controller_log, f"Removing stale test instance {spec.instance_name}\n")
            _remove_instance(executor, spec.instance_name, existing[spec.instance_name], controller_log)

        print(f"Launching {spec.label} ({spec.image}) as {spec.instance_name}...", flush=True)
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
        )
        if launch.returncode != 0:
            raise InfrastructureError(f"VM launch failed with status {launch.returncode}")
        instance_created = True
        print(f"Launched: {spec.instance_name}", flush=True)
        image_release, image_sha256 = _instance_image_provenance(
            executor,
            spec.instance_name,
            controller_log,
        )

        for source in (archive_path, guest_script):
            transfer = executor.run(
                ["transfer", "-", f"{spec.instance_name}:/home/ubuntu/{source.name}"],
                controller_log,
                input_path=source,
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
        retrieve = executor.run_with_stdout_file(
            ["transfer", f"{spec.instance_name}:/home/ubuntu/results.tar.gz", "-"],
            retrieved_archive,
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
        image_release=image_release,
        image_sha256=image_sha256,
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


def _utc_timestamp() -> str:
    """Return the current UTC time as a seconds-precision ISO-8601 string.

    Returns:
        UTC timestamp ending in ``Z``.
    """
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


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
    parser.add_argument(
        "--evidence-jsonl",
        type=Path,
        help=(
            "tracked VM history (default: SOURCE/v2/doc/test-report/"
            "vm-matrix-results.jsonl)"
        ),
    )
    parser.add_argument(
        "--refresh-presentation",
        action="store_true",
        help="regenerate the README matrix section and badge from tracked full-run history",
    )
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
    source_root = args.source.resolve()
    evidence_path = (
        args.evidence_jsonl.resolve()
        if args.evidence_jsonl is not None
        else source_root / _DEFAULT_HISTORY_RELATIVE_PATH
    )
    readme_path = source_root / "README.md"
    badge_path = source_root / _DEFAULT_BADGE_RELATIVE_PATH

    if args.refresh_presentation:
        # Repairing tracked presentation files does not need Multipass, a clean
        # checkout, or the dedicated runtime SSD.
        try:
            latest_record = read_latest_full_history_record(evidence_path)
            publish_vm_matrix_presentation(latest_record, readme_path, badge_path)
            print(f"Refreshed VM matrix presentation from {latest_record['run_id']}")
            return 0
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            print(f"ERROR: Cannot refresh VM matrix presentation: {exc}", file=sys.stderr)
            return 2

    started_at = _utc_timestamp()
    result_root: Path | None = None
    commit = ""
    run_id = ""
    specs: list[ImageSpec] = []
    results: list[ImageRunResult] = []
    completed = False
    aborted_phase: str | None = "preflight"
    exit_code = 2

    try:
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

        aborted_phase = "source_archive"
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
        for spec in specs:
            aborted_phase = f"image:{spec.label}"
            results.append(run_image(
                spec=spec,
                executor=executor,
                archive_path=archive_path,
                guest_script=guest_script,
                mode=args.mode,
                commit=commit,
                result_root=result_root,
                keep_failed=args.keep_failed,
                keep_all=args.keep_all,
            ))
        completed = True
        exit_code = _overall_exit_code(results)
        aborted_phase = "summary"
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
        aborted_phase = None
    except KeyboardInterrupt:
        print("ERROR: VM matrix interrupted", file=sys.stderr)
        exit_code = 2
    except (InfrastructureError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        exit_code = 2

    if result_root is None or not commit or not run_id or not specs:
        return exit_code

    finished_at = _utc_timestamp()
    local_evidence_path = result_root / "vm-matrix-result.json"
    history_record: dict[str, Any] | None = None
    try:
        history_record = build_history_record(
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            mode=args.mode,
            application_commit=commit,
            orchestration_commit=commit,
            specs=specs,
            results=results,
            completed=completed,
            aborted_phase=aborted_phase,
            exit_code=exit_code,
        )
        write_json(local_evidence_path, history_record)
        append_jsonl_record(evidence_path, history_record)
        print(f"Evidence: {evidence_path}")
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: Cannot persist VM matrix evidence: {exc}", file=sys.stderr)
        exit_code = 2
        history_record = None
        try:
            failed_record = build_history_record(
                run_id=run_id,
                started_at=started_at,
                finished_at=_utc_timestamp(),
                mode=args.mode,
                application_commit=commit,
                orchestration_commit=commit,
                specs=specs,
                results=results,
                completed=completed,
                aborted_phase="evidence",
                exit_code=exit_code,
            )
            write_json(local_evidence_path, failed_record)
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as local_exc:
            print(
                f"ERROR: Cannot preserve local VM matrix evidence: {local_exc}",
                file=sys.stderr,
            )

    # Publish only after immutable-source testing and durable evidence storage.
    # A partial suite cannot substantiate the README's full-suite claim.
    if history_record is not None and args.mode == "full":
        try:
            publish_vm_matrix_presentation(history_record, readme_path, badge_path)
            print(f"README VM matrix: {readme_path}")
            print(f"VM matrix badge: {badge_path}")
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            print(f"ERROR: Cannot publish VM matrix presentation: {exc}", file=sys.stderr)
            exit_code = 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
