#!/usr/bin/env python3
"""Update and validate dar-backup versions in the Quick Guide."""

from __future__ import annotations

import argparse
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Match, Sequence


LOGGER = logging.getLogger(__name__)
VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){2,3}$")
PACKAGE_VERSION_PATTERN = re.compile(
    r"(?P<prefix>\bdar-backup-)(?P<version>[0-9]+(?:\.[0-9]+){2,3})"
)
CLI_VERSION_PATTERN = re.compile(
    r"^(?P<prefix>(?P<command>manager|dar-backup)(?:\.py)?:[ \t]+)"
    r"(?P<version>[0-9]+(?:\.[0-9]+){2,3})(?P<suffix>[ \t]*)$",
    re.MULTILINE,
)


def validate_release_version(version: str) -> None:
    """Validate a stable dar-backup release version.

    Args:
        version: Candidate release version without the ``v2-`` tag prefix.

    Returns:
        None.

    Raises:
        ValueError: If the version is empty or malformed.
    """
    if not isinstance(version, str) or not version:
        raise ValueError("Release version must be a non-empty string")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError(
            "Release version must contain three or four numeric components: "
            f"{version!r}"
        )


def replace_quick_guide_versions(content: str, version: str) -> tuple[str, int]:
    """Replace every expected dar-backup version in Quick Guide content.

    Args:
        content: Complete Quick Guide Markdown content.
        version: Stable release version without the ``v2-`` tag prefix.

    Returns:
        Updated content and the total number of matched version references.

    Raises:
        ValueError: If inputs are invalid or an expected reference is absent.
    """
    validate_release_version(version)
    if not isinstance(content, str) or not content:
        raise ValueError("Quick Guide content must be a non-empty string")

    package_matches = 0

    def replace_package(match: Match[str]) -> str:
        """Replace one installed-package version.

        Args:
            match: Regular-expression match for a package version.

        Returns:
            Package reference containing the requested release version.
        """
        nonlocal package_matches
        package_matches += 1
        return f"{match.group('prefix')}{version}"

    cli_matches = {"manager": 0, "dar-backup": 0}

    def replace_cli(match: Match[str]) -> str:
        """Replace one CLI startup-settings version.

        Args:
            match: Regular-expression match for a CLI version line.

        Returns:
            CLI version line containing the requested release version.
        """
        command = match.group("command")
        cli_matches[command] += 1
        return f"{match.group('prefix')}{version}{match.group('suffix')}"

    updated = PACKAGE_VERSION_PATTERN.sub(replace_package, content)
    updated = CLI_VERSION_PATTERN.sub(replace_cli, updated)

    missing: list[str] = []
    if package_matches == 0:
        missing.append("installed dar-backup package")
    if cli_matches["manager"] == 0:
        missing.append("manager startup version")
    if cli_matches["dar-backup"] == 0:
        missing.append("dar-backup startup version")
    if missing:
        raise ValueError(
            "Quick Guide is missing expected release-version reference(s): "
            + ", ".join(missing)
        )

    total_matches = package_matches + sum(cli_matches.values())
    return updated, total_matches


def update_quick_guide(path: Path, version: str) -> int:
    """Atomically update Quick Guide release-version references.

    Args:
        path: Quick Guide Markdown path.
        version: Stable release version without the ``v2-`` tag prefix.

    Returns:
        Number of validated version references found and updated.

    Raises:
        OSError: If the guide cannot be read or atomically replaced.
        ValueError: If the path or guide content is invalid.
    """
    validate_release_version(version)
    if not isinstance(path, Path):
        raise ValueError("Quick Guide path must be a pathlib.Path")  # noqa: TRY004
    if not path.is_file():
        raise ValueError(f"Quick Guide does not exist or is not a regular file: {path}")

    original = path.read_text(encoding="utf-8")
    updated, match_count = replace_quick_guide_versions(original, version)
    if updated == original:
        return match_count

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary_file:
            temporary_file.write(updated)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)

        os.chmod(temporary_path, path.stat().st_mode)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    return match_count


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and update the Quick Guide.

    Args:
        argv: Optional arguments excluding the executable name.

    Returns:
        Zero on success, one for filesystem failures, and two for validation
        failures.

    Raises:
        SystemExit: If argparse rejects the command-line syntax.
    """
    parser = argparse.ArgumentParser(
        description="Update and validate release versions in the Quick Guide."
    )
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        match_count = update_quick_guide(args.path, args.version)
    except ValueError:
        LOGGER.exception("Quick Guide validation failed")
        return 2
    except OSError:
        LOGGER.exception("Could not update the Quick Guide")
        return 1

    LOGGER.info(
        "Updated %d validated Quick Guide version reference(s) to %s",
        match_count,
        args.version,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
