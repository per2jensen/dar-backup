#!/usr/bin/env python3
"""Validate release tools and packaged wheel documentation."""

from __future__ import annotations

import argparse
import logging
import sys
import zipfile
from collections.abc import Mapping, Sequence
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from packaging.version import InvalidVersion, Version

LOGGER = logging.getLogger(__name__)

MINIMUM_TOOL_VERSIONS: tuple[tuple[str, str], ...] = (
    ("packaging", "26.0"),
    ("twine", "6.2.0"),
)


def read_installed_versions(package_names: Sequence[str]) -> dict[str, str]:
    """Read installed versions for the requested Python packages.

    Args:
        package_names: Non-empty package names to inspect.

    Returns:
        A new mapping from package name to installed version.

    Raises:
        ValueError: If a package name is empty or a package is not installed.
    """
    if not package_names:
        raise ValueError("At least one package name is required")

    installed_versions: dict[str, str] = {}
    for package_name in package_names:
        if not isinstance(package_name, str) or not package_name.strip():
            raise ValueError("Package names must be non-empty strings")

        try:
            installed_versions[package_name] = version(package_name)
        except PackageNotFoundError as exc:
            LOGGER.exception("Required release package is not installed: %s", package_name)
            raise ValueError(f"Required release package is not installed: {package_name}") from exc

    return installed_versions


def validate_tool_versions(
    installed_versions: Mapping[str, str],
    minimum_versions: Sequence[tuple[str, str]] = MINIMUM_TOOL_VERSIONS,
) -> None:
    """Require every release tool to meet its minimum supported version.

    Args:
        installed_versions: Installed versions keyed by package name.
        minimum_versions: Package names paired with minimum accepted versions.

    Returns:
        None.

    Raises:
        ValueError: If inputs are invalid, a tool is missing, or a version is too old.
    """
    if not isinstance(installed_versions, Mapping):
        # Repository input-validation policy requires ValueError for bad inputs.
        raise ValueError("installed_versions must be a mapping")  # noqa: TRY004
    if not minimum_versions:
        raise ValueError("At least one minimum tool version is required")

    for package_name, minimum_version in minimum_versions:
        installed_version = installed_versions.get(package_name)
        if not installed_version:
            raise ValueError(f"Required release package is not installed: {package_name}")

        try:
            installed = Version(installed_version)
            minimum = Version(minimum_version)
        except InvalidVersion as exc:
            LOGGER.exception(
                "Invalid release-tool version for %s: installed=%r minimum=%r",
                package_name,
                installed_version,
                minimum_version,
            )
            raise ValueError(f"Invalid version for release package {package_name}") from exc

        if installed < minimum:
            raise ValueError(
                f"Release package {package_name} {installed} is too old; "
                f"version {minimum} or newer is required"
            )


def collect_staged_document_paths(staging_dir: Path) -> tuple[str, ...]:
    """Collect archive paths for all documentation staged for a wheel.

    Args:
        staging_dir: Package staging directory, such as ``src/dar_backup``.

    Returns:
        Sorted wheel-member paths for every staged documentation file.

    Raises:
        ValueError: If the staging layout or required documentation is missing.
    """
    if not isinstance(staging_dir, Path):
        # Repository input-validation policy requires ValueError for bad inputs.
        raise ValueError("staging_dir must be a pathlib.Path")  # noqa: TRY004
    if not staging_dir.is_dir():
        raise ValueError(f"Wheel documentation staging directory does not exist: {staging_dir}")

    required_top_level = (staging_dir / "README.md", staging_dir / "Changelog.md")
    missing_top_level = [path.name for path in required_top_level if not path.is_file()]
    if missing_top_level:
        raise ValueError(
            "Wheel documentation staging is missing required files: "
            + ", ".join(sorted(missing_top_level))
        )

    docs_dir = staging_dir / "doc"
    staged_docs = tuple(sorted(docs_dir.glob("*.md"))) if docs_dir.is_dir() else ()
    if not staged_docs:
        raise ValueError(f"Wheel documentation staging contains no Markdown docs: {docs_dir}")

    staged_files = (*required_top_level, *staged_docs)
    return tuple(
        f"{staging_dir.name}/{path.relative_to(staging_dir).as_posix()}"
        for path in staged_files
    )


def validate_wheel_documentation(wheel_path: Path, required_paths: Sequence[str]) -> None:
    """Verify that a wheel contains every required documentation path.

    Args:
        wheel_path: Wheel archive to inspect.
        required_paths: Non-empty wheel-member paths that must be present.

    Returns:
        None.

    Raises:
        OSError: If the wheel cannot be read.
        ValueError: If inputs are invalid or required files are absent.
        zipfile.BadZipFile: If the wheel is not a valid ZIP archive.
    """
    if not isinstance(wheel_path, Path):
        # Repository input-validation policy requires ValueError for bad inputs.
        raise ValueError("wheel_path must be a pathlib.Path")  # noqa: TRY004
    if not wheel_path.is_file():
        raise ValueError(f"Wheel does not exist: {wheel_path}")
    if wheel_path.suffix != ".whl":
        raise ValueError(f"Expected a .whl file: {wheel_path}")
    if not required_paths:
        raise ValueError("At least one required wheel path is required")

    with zipfile.ZipFile(wheel_path) as wheel:
        wheel_members = frozenset(wheel.namelist())

    missing_paths = sorted(set(required_paths) - wheel_members)
    if missing_paths:
        raise ValueError(
            f"Wheel {wheel_path} is missing staged documentation: "
            + ", ".join(missing_paths)
        )


def validate_wheels(staging_dir: Path, wheel_paths: Sequence[Path]) -> None:
    """Validate staged documentation against one or more built wheels.

    Args:
        staging_dir: Package staging directory containing documentation.
        wheel_paths: Wheel archives to validate.

    Returns:
        None.

    Raises:
        OSError: If a wheel cannot be read.
        ValueError: If inputs, staging, or wheel contents are invalid.
        zipfile.BadZipFile: If a wheel is not a valid ZIP archive.
    """
    if not wheel_paths:
        raise ValueError("At least one wheel is required")

    required_paths = collect_staged_document_paths(staging_dir)
    for wheel_path in wheel_paths:
        validate_wheel_documentation(wheel_path, required_paths)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Args:
        None.

    Returns:
        Configured argument parser.

    Raises:
        None.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("environment", help="validate installed release-tool versions")

    wheel_parser = subparsers.add_parser(
        "wheel-docs",
        help="verify that built wheels contain all staged documentation",
    )
    wheel_parser.add_argument("--staging-dir", required=True, type=Path)
    wheel_parser.add_argument("wheels", nargs="+", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested release validation.

    Args:
        argv: Optional command-line arguments; defaults to ``sys.argv``.

    Returns:
        Zero on success and one when validation fails.

    Raises:
        SystemExit: If command-line arguments are invalid.
    """
    args = build_parser().parse_args(argv)

    try:
        if args.command == "environment":
            package_names = tuple(name for name, _ in MINIMUM_TOOL_VERSIONS)
            installed_versions = read_installed_versions(package_names)
            validate_tool_versions(installed_versions)
            for package_name, _ in MINIMUM_TOOL_VERSIONS:
                LOGGER.info("Release tool accepted: %s %s", package_name, installed_versions[package_name])
            return 0

        if args.command == "wheel-docs":
            validate_wheels(args.staging_dir, tuple(args.wheels))
            for wheel_path in args.wheels:
                LOGGER.info("Wheel documentation accepted: %s", wheel_path)
            return 0

        raise ValueError(f"Unsupported validation command: {args.command}")
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        # Validation errors are expected operator feedback, so omit a traceback.
        LOGGER.error("Release validation failed: %s", exc)  # noqa: TRY400
        return 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    sys.exit(main())
