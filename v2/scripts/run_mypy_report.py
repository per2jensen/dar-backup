#!/usr/bin/env python3
"""Run mypy once and write a validated structured diagnostic report."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Sequence

from mypy.errorcodes import error_codes
from mypy.main import process_options


LOGGER = logging.getLogger(__name__)
REPORT_SCHEMA_VERSION = 1
_CHECK_OPTION_NAMES = (
    "allow_redefinition",
    "allow_untyped_globals",
    "check_untyped_defs",
    "disallow_any_decorated",
    "disallow_any_explicit",
    "disallow_any_expr",
    "disallow_any_generics",
    "disallow_any_unimported",
    "disallow_incomplete_defs",
    "disallow_subclassing_any",
    "disallow_untyped_calls",
    "disallow_untyped_decorators",
    "disallow_untyped_defs",
    "extra_checks",
    "follow_imports",
    "follow_untyped_imports",
    "ignore_missing_imports",
    "implicit_optional",
    "implicit_reexport",
    "strict_bytes",
    "strict_equality",
    "strict_equality_for_none",
    "strict_optional",
    "warn_no_return",
    "warn_redundant_casts",
    "warn_return_any",
    "warn_unreachable",
    "warn_unused_ignores",
)


def _canonical_sha256(payload: object) -> str:
    """Return the SHA-256 of compact, key-sorted UTF-8 JSON.

    Args:
        payload: JSON-serializable value.

    Returns:
        Lowercase SHA-256 digest.

    Raises:
        TypeError: If the value cannot be serialized as JSON.
        ValueError: If the value contains a non-finite number.
    """
    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _effective_checks(target: str) -> dict[str, Any]:
    """Read mypy's effective checks after applying project configuration.

    Args:
        target: Source path passed to mypy.

    Returns:
        JSON-serializable effective-check configuration.

    Raises:
        AttributeError: If the installed mypy no longer exposes a required option.
        TypeError: If mypy returns an unsupported option value.
    """
    _sources, options = process_options([target])
    default_codes = {
        name for name, error_code in error_codes.items() if error_code.default_enabled
    }
    enabled_codes = (
        default_codes
        - set(options.disable_error_code)
        | set(options.enable_error_code)
    )

    option_values: dict[str, bool | str] = {}
    for name in _CHECK_OPTION_NAMES:
        value = getattr(options, name)
        if not isinstance(value, (bool, str)):
            raise TypeError(f"Unsupported effective mypy option {name!r}: {value!r}")
        option_values[name] = value

    module_overrides: dict[str, dict[str, Any]] = {}
    for module, raw_values in sorted(options.per_module_options.items()):
        if not isinstance(module, str) or not isinstance(raw_values, dict):
            raise TypeError("Invalid mypy per-module configuration")
        normalized_values: dict[str, Any] = {}
        for name, value in sorted(raw_values.items()):
            if isinstance(value, list):
                if not all(isinstance(item, str) for item in value):
                    raise TypeError(f"Invalid list option {name!r} for mypy module {module!r}")
                normalized_values[name] = sorted(value)
            elif isinstance(value, (bool, int, str)) or value is None:
                normalized_values[name] = value
            else:
                raise TypeError(f"Invalid option {name!r} for mypy module {module!r}")
        module_overrides[module] = normalized_values

    return {
        "python_version": ".".join(str(part) for part in options.python_version),
        "platform": options.platform,
        "enabled_error_codes": sorted(enabled_codes),
        "options": option_values,
        "module_overrides": module_overrides,
    }


def _run_command(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run one command without a shell and capture its complete output.

    Args:
        command: Executable and arguments.

    Returns:
        Completed subprocess result.

    Raises:
        OSError: If the executable cannot be started.
        ValueError: If the command is empty.
    """
    if not command:
        raise ValueError("command must not be empty")
    return subprocess.run(  # noqa: S603 - arguments are never passed through a shell.
        list(command),
        check=False,
        capture_output=True,
        text=True,
    )


def _parse_diagnostics(output: str) -> list[dict[str, Any]]:
    """Parse and validate mypy JSON Lines diagnostics.

    Args:
        output: Standard output from mypy's JSON formatter.

    Returns:
        Parsed diagnostic objects in emitted order.

    Raises:
        TypeError: If a diagnostic is not an object or has invalid fields.
        ValueError: If a line is malformed JSON or lacks required values.
    """
    diagnostics: list[dict[str, Any]] = []
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            diagnostic = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"mypy JSON diagnostic line {line_number} is malformed: {exc.msg}"
            ) from exc
        if not isinstance(diagnostic, dict):
            raise TypeError(f"mypy diagnostic line {line_number} is not an object")
        for field in ("file", "message", "severity"):
            value = diagnostic.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"mypy diagnostic line {line_number} has invalid {field!r}"
                )
        if str(diagnostic["severity"]).casefold() not in {"error", "note", "warning"}:
            raise ValueError(
                f"mypy diagnostic line {line_number} has unsupported severity"
            )
        for field in ("line", "column", "end_line", "end_column"):
            value = diagnostic.get(field)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise ValueError(
                    f"mypy diagnostic line {line_number} has invalid {field!r}"
                )
        code = diagnostic.get("code")
        if code is not None and (not isinstance(code, str) or not code.strip()):
            raise ValueError(f"mypy diagnostic line {line_number} has invalid 'code'")
        diagnostics.append(diagnostic)
    return diagnostics


def _build_summary(diagnostics: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Summarize validated mypy diagnostics.

    Args:
        diagnostics: Parsed mypy diagnostics.

    Returns:
        Counts by severity and number of files containing errors.
    """
    severities = Counter(str(diagnostic["severity"]).casefold() for diagnostic in diagnostics)
    files_with_errors = {
        str(diagnostic["file"])
        for diagnostic in diagnostics
        if str(diagnostic["severity"]).casefold() == "error"
    }
    return {
        "errors": severities["error"],
        "notes": severities["note"],
        "warnings": severities["warning"],
        "files_with_errors": len(files_with_errors),
        "diagnostics": len(diagnostics),
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write one JSON report.

    Args:
        path: Destination report path.
        payload: JSON-serializable report.

    Returns:
        None.

    Raises:
        OSError: If the report cannot be written.
        TypeError: If the report cannot be serialized.
        ValueError: If the report contains a non-finite number.
    """
    if path is None:
        raise ValueError("output path must not be None")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary_path: Path | None = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as report_file:
            json.dump(
                payload,
                report_file,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            report_file.write("\n")
            report_file.flush()
            os.fsync(report_file.fileno())
        os.replace(temporary_name, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def create_report(target: str) -> tuple[dict[str, Any], int]:
    """Run mypy and build its structured report.

    Args:
        target: Source path passed to mypy.

    Returns:
        Report object and original mypy exit code.

    Raises:
        OSError: If Python or mypy cannot be started.
        TypeError: If mypy configuration or diagnostics are invalid.
        ValueError: If the target, version, or diagnostics are invalid.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("mypy target must be a non-empty string")

    version_result = _run_command([sys.executable, "-m", "mypy", "--version"])
    version = version_result.stdout.strip()
    if version_result.returncode != 0 or not version:
        raise ValueError(
            f"Cannot determine mypy version: {version_result.stderr.strip()}"
        )

    checks = _effective_checks(target)
    result = _run_command(
        [
            sys.executable,
            "-m",
            "mypy",
            "-O",
            "json",
            "--no-pretty",
            "--no-color-output",
            "--show-error-codes",
            target,
        ]
    )
    diagnostics = _parse_diagnostics(result.stdout)
    if result.returncode == 0:
        status = "passed"
    elif result.returncode == 1:
        status = "failed"
    else:
        status = "error"

    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": status,
        "version": version,
        "exit_code": result.returncode,
        "target": target,
        "checks": checks,
        "checks_sha256": _canonical_sha256(checks),
        "summary": _build_summary(diagnostics),
        "diagnostics": diagnostics,
        "stderr": result.stderr,
    }
    return report, result.returncode


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        arguments: Optional arguments excluding the program name.

    Returns:
        Parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("target")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run mypy, persist its report, and preserve its exit status.

    Args:
        arguments: Optional arguments excluding the program name.

    Returns:
        Mypy's exit code, or two when report generation fails.
    """
    args = parse_args(arguments)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        report, exit_code = create_report(args.target)
        _write_json(args.output, report)
    except (AttributeError, OSError, TypeError, ValueError):
        LOGGER.exception("Cannot create structured mypy report")
        return 2

    for diagnostic in report["diagnostics"]:
        LOGGER.error(
            "%s:%s:%s: %s: %s [%s]",
            diagnostic["file"],
            diagnostic.get("line", 0),
            diagnostic.get("column", 0),
            diagnostic["severity"],
            diagnostic["message"],
            diagnostic.get("code", "no-code"),
        )
    if exit_code == 0:
        LOGGER.info("mypy passed with %s", report["version"])
    else:
        LOGGER.error(
            "mypy exited with status %d (%d diagnostic(s))",
            exit_code,
            report["summary"]["diagnostics"],
        )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
