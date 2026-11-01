# SPDX-License-Identifier: GPL-3.0-or-later
"""Linux mount identity inspection for backup preflight checks."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


_MOUNTINFO_ESCAPE = re.compile(r"\\([0-7]{3})")


@dataclass(frozen=True)
class MountIdentity:
    """Describe the mounted filesystem containing a path.

    Args:
        target: Mount target reported by the Linux kernel.
        source: Mounted filesystem source.
        filesystem_type: Mounted filesystem type.
    """

    target: str
    source: str
    filesystem_type: str


def _decode_mountinfo_field(value: str) -> str:
    """Decode octal escapes used in Linux mountinfo fields.

    Args:
        value: Raw mountinfo field.

    Returns:
        Decoded field value.
    """
    return _MOUNTINFO_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def parse_mountinfo(contents: str) -> list[MountIdentity]:
    """Parse mount identities from Linux ``/proc/*/mountinfo`` text.

    Args:
        contents: Complete mountinfo file contents.

    Returns:
        Valid mount identities. Malformed lines are ignored.

    Raises:
        ValueError: If ``contents`` is empty or not a string.
    """
    if not isinstance(contents, str) or not contents.strip():
        raise ValueError("mountinfo contents must be a non-empty string")

    identities: list[MountIdentity] = []
    for line in contents.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if separator < 6 or len(fields) <= separator + 2:
            continue
        identities.append(
            MountIdentity(
                target=_decode_mountinfo_field(fields[4]),
                filesystem_type=_decode_mountinfo_field(fields[separator + 1]),
                source=_decode_mountinfo_field(fields[separator + 2]),
            )
        )
    return identities


def get_mount_identity(
    path: str,
    mountinfo_path: str = "/proc/self/mountinfo",
) -> MountIdentity:
    """Return the most specific mounted filesystem containing ``path``.

    Args:
        path: Existing path whose containing mount should be inspected.
        mountinfo_path: Linux mountinfo file to read.

    Returns:
        Identity of the longest matching mount target.

    Raises:
        ValueError: If an input is empty or no containing mount is found.
        OSError: If the path or mountinfo file cannot be read or resolved.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError("mount lookup path must be a non-empty string")
    if not isinstance(mountinfo_path, str) or not mountinfo_path.strip():
        raise ValueError("mountinfo_path must be a non-empty string")

    resolved_path = Path(path).resolve(strict=True)
    contents = Path(mountinfo_path).read_text(encoding="utf-8")
    matches: list[tuple[int, MountIdentity]] = []
    for identity in parse_mountinfo(contents):
        mount_target = Path(identity.target)
        if resolved_path != mount_target and mount_target not in resolved_path.parents:
            continue
        matches.append((len(mount_target.parts), identity))

    if not matches:
        raise ValueError(f"no containing mount found for '{resolved_path}'")
    return max(matches, key=lambda item: item[0])[1]


def validate_expected_mount(
    name: str,
    path: str,
    expected_source: Optional[str],
    expected_filesystem_type: Optional[str],
) -> Optional[str]:
    """Validate the mounted filesystem containing a configured directory.

    Args:
        name: Configuration directory name used in diagnostics.
        path: Configured directory to inspect.
        expected_source: Exact expected mount source, or ``None``.
        expected_filesystem_type: Exact expected filesystem type, or ``None``.

    Returns:
        ``None`` when the mount matches, otherwise a diagnostic error string.

    Raises:
        ValueError: If no expected identity field is supplied.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("mount configuration name must be a non-empty string")
    if expected_source is None and expected_filesystem_type is None:
        raise ValueError("at least one expected mount identity field is required")

    try:
        actual = get_mount_identity(path)
    except (OSError, ValueError) as exc:
        return f"Cannot determine mount identity for {name} ({path}): {exc}"

    mismatches: list[str] = []
    if expected_source is not None and actual.source != expected_source:
        mismatches.append(f"source expected '{expected_source}', found '{actual.source}'")
    if (
        expected_filesystem_type is not None
        and actual.filesystem_type != expected_filesystem_type
    ):
        mismatches.append(
            "filesystem type expected "
            f"'{expected_filesystem_type}', found '{actual.filesystem_type}'"
        )
    if not mismatches:
        return None

    return (
        f"{name} mount identity mismatch for '{path}' "
        f"(mounted at '{actual.target}'): {'; '.join(mismatches)}"
    )
