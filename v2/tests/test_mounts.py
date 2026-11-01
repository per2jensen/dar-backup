"""Tests for fail-closed backup mount identity inspection."""

from pathlib import Path

from dar_backup.mounts import (
    MountIdentity,
    get_mount_identity,
    parse_mountinfo,
    validate_expected_mount,
)
import pytest


pytestmark = pytest.mark.unit


def test_parse_mountinfo_valid_nested_mounts_decodes_fields() -> None:
    """Parse valid identities and decode kernel octal escapes.

    Returns:
        None.
    """
    contents = (
        "20 1 0:1 / / rw - overlay overlay rw\n"
        "21 20 0:2 / /mnt/backup\\040store rw - nfs4 server:/backup\\040store rw\n"
    )

    identities = parse_mountinfo(contents)

    assert identities == [
        MountIdentity(target="/", source="overlay", filesystem_type="overlay"),
        MountIdentity(
            target="/mnt/backup store",
            source="server:/backup store",
            filesystem_type="nfs4",
        ),
    ]


def test_parse_mountinfo_empty_contents_raises_value_error() -> None:
    """Reject empty mount table input instead of treating it as no mounts.

    Returns:
        None.

    Raises:
        AssertionError: If empty input is accepted.
    """
    with pytest.raises(ValueError, match="non-empty"):
        parse_mountinfo("")


def test_get_mount_identity_nested_path_selects_most_specific_mount(
    tmp_path: Path,
) -> None:
    """Choose the longest mount target containing the requested path.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    target = tmp_path / "mounted" / "backups"
    target.mkdir(parents=True)
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "20 1 0:1 / / rw - overlay overlay rw\n"
        f"21 20 0:2 / {tmp_path / 'mounted'} rw - nfs4 server:/backups rw\n",
        encoding="utf-8",
    )

    identity = get_mount_identity(str(target), str(mountinfo))

    assert identity.source == "server:/backups"
    assert identity.filesystem_type == "nfs4"
    assert identity.target == str(tmp_path / "mounted")


def test_validate_expected_mount_current_identity_passes(tmp_path: Path) -> None:
    """Accept the actual kernel-reported source and filesystem type.

    Args:
        tmp_path: Existing path on the test filesystem.

    Returns:
        None.
    """
    identity = get_mount_identity(str(tmp_path))

    error = validate_expected_mount(
        "BACKUP_DIR",
        str(tmp_path),
        identity.source,
        identity.filesystem_type,
    )

    assert error is None


def test_validate_expected_mount_wrong_source_reports_mismatch(tmp_path: Path) -> None:
    """Reject a writable directory when its mounted source is unexpected.

    Args:
        tmp_path: Existing path on the test filesystem.

    Returns:
        None.
    """
    identity = get_mount_identity(str(tmp_path))

    error = validate_expected_mount(
        "BACKUP_DIR",
        str(tmp_path),
        "source-that-cannot-match",
        identity.filesystem_type,
    )

    assert error is not None
    assert "mount identity mismatch" in error
    assert "source-that-cannot-match" in error
    assert identity.source in error
