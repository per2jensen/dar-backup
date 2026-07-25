# SPDX-License-Identifier: GPL-3.0-or-later

"""Real-filesystem POSIX ACL coverage for overwrite restore preflight."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from dar_backup.restore_target_safety import ExistingDataPolicy, RestoreTargetError, RestoreTargetPolicy, prepare_restore_target

pytestmark = [pytest.mark.integration, pytest.mark.smoke]


def _run_acl_command(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    """Run an ACL utility and require a successful result.

    Args:
        arguments: Command name followed by its arguments.

    Returns:
        The completed ACL utility process.

    Raises:
        ValueError: If arguments is empty.
        AssertionError: If the ACL utility is unavailable or exits nonzero.
    """
    if not arguments:
        raise ValueError("arguments must not be empty")

    executable = shutil.which(arguments[0])
    assert executable is not None, f"Required ACL test utility '{arguments[0]}' is unavailable; install the operating system's ACL package."
    result = subprocess.run(
        [executable, *arguments[1:]],
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, (
        f"ACL command failed (rc={result.returncode}): command={arguments!r} stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    return result


@pytest.mark.parametrize(
    ("acl_kind", "xattr_name"),
    [
        ("access", "system.posix_acl_access"),
        ("default", "system.posix_acl_default"),
    ],
)
def test_overwrite_preflight_real_extended_acl_rejects_then_accepts_after_removal(
    tmp_path: Path,
    acl_kind: str,
    xattr_name: str,
) -> None:
    """Real access and default ACLs fail closed until the operator removes them.

    Args:
        tmp_path: Isolated filesystem location supplied by pytest.
        acl_kind: ACL variant to create: access or default.
        xattr_name: POSIX ACL xattr expected for the selected variant.
    """
    target = tmp_path / f"{acl_kind}-acl-target"
    target.mkdir(mode=0o700)
    guarded_directory = target / "guarded"
    guarded_directory.mkdir(mode=0o700)

    # A read-only named-user entry keeps group write bits clear, isolating the
    # extended-ACL rejection from the separate mode-bit rejection. Use the
    # mapped test UID so this remains a real ACL test inside user namespaces
    # that reject ACL entries for unmapped identities. The production policy
    # deliberately rejects every extended ACL, including one for a trusted UID.
    acl_uid = os.geteuid()
    acl_prefix = "d:" if acl_kind == "default" else ""
    acl_specification = f"{acl_prefix}u:{acl_uid}:r-x"
    _run_acl_command(["setfacl", "--modify", acl_specification, str(guarded_directory)])

    acl_bytes = os.getxattr(guarded_directory, xattr_name)
    assert acl_bytes, f"{xattr_name} was not created on {guarded_directory}"
    acl_listing = _run_acl_command(["getfacl", "--absolute-names", "--numeric", str(guarded_directory)]).stdout
    listing_prefix = "default:" if acl_kind == "default" else ""
    assert f"{listing_prefix}user:{acl_uid}:r-x" in acl_listing

    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)
    with pytest.raises(RestoreTargetError) as error_info:
        with prepare_restore_target(str(target), policy):
            pytest.fail("restore target with a real extended ACL passed preflight")

    error_message = str(error_info.value)
    assert str(guarded_directory) in error_message
    assert "has an extended POSIX ACL" in error_message
    assert "No restore data was written." in error_message

    removal_option = "--remove-default" if acl_kind == "default" else "--remove-all"
    _run_acl_command(["setfacl", removal_option, str(guarded_directory)])

    with prepare_restore_target(str(target), policy) as handle:
        assert handle.canonical_path == str(target.resolve())
