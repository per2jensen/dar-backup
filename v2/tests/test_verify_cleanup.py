import os
from unittest.mock import MagicMock, patch, mock_open
from types import SimpleNamespace
from dar_backup.dar_backup import verify
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.smoke]






def test_verify_removes_existing_file_before_restore(env, tmp_path):
    """
    Proves that an existing file in the restore directory is removed 
    before the restore command is executed.
    """
    # 1. Setup
    restore_dir = tmp_path / "restore_test"
    restore_dir.mkdir()
    
    filename = "test_file.txt"
    file_path = "/path/to/" + filename
    restore_path = restore_dir / "path/to" / filename
    
    # Create the file that should be removed
    restore_path.parent.mkdir(parents=True, exist_ok=True)
    restore_path.write_text("I should be deleted")
    
    assert restore_path.exists()

    args = SimpleNamespace(
        verbose=True,
        do_not_compare=False,
        darrc=env.dar_rc
    )

    config = SimpleNamespace(
        test_restore_dir=str(restore_dir),
        logfile_location=env.log_file,
        command_timeout_secs=10,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=1,
        # Ensure filters don't exclude our file
        restoretest_exclude_prefixes=[],
        restoretest_exclude_suffixes=[],
        restoretest_exclude_regex=None,
        restore_ownership=False,
    )

    # Mock get_backed_up_files to return our specific file
    files_list = [(file_path, "100 o")]

    # Mock runner to simulate success but NOT actually restore the file
    # This ensures that if the file still exists, it wasn't deleted.
    # If it's gone, it was deleted (since we didn't restore it).
    mock_runner = MagicMock()
    mock_runner.run.return_value.returncode = 0

    # Mock filecmp.cmp to avoid errors when comparing missing file
    mock_cmp = MagicMock(return_value=True)
    
    # Mock open for definition file reading
    mock_def_content = "-R /\n-s 10G\n"

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.get_backed_up_files", return_value=files_list), \
         patch("dar_backup.dar_backup.filecmp.cmp", mock_cmp), \
         patch("dar_backup.dar_backup.logger") as mock_logger, \
         patch("builtins.open", mock_open(read_data=mock_def_content)):
        
        # 2. Execute
        verify(args, "mock-backup", env.config_file, config)

    # 3. Verify
    # The file should have been removed by verify() before calling runner (which we mocked to do nothing)
    assert not restore_path.exists(), f"File {restore_path} should have been removed before restore attempt"
    
    # Ensure it was actually the code path we expect
    mock_logger.info.assert_any_call(f"Restoring file: '{file_path}' from backup to: '{restore_dir}' for file comparing")


def test_verify_warns_when_stale_file_removal_fails(env, tmp_path):
    """When os.remove() raises OSError on a stale restore file, verify() must log
    a warning rather than silently swallowing the error.

    Monkeypatching os.remove is used here because triggering a permission-denied
    or read-only-filesystem error on a specific file cannot be done reliably on
    real hardware without root access.  The mock reproduces exactly the failure
    path that would occur on a read-only NFS mount or a file owned by root.
    """
    restore_dir = tmp_path / "restore_test"
    restore_dir.mkdir()

    file_path = "/path/to/test_file.txt"
    restore_path = restore_dir / "path/to" / "test_file.txt"
    restore_path.parent.mkdir(parents=True, exist_ok=True)
    restore_path.write_text("stale content that cannot be removed")

    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)
    config = SimpleNamespace(
        test_restore_dir=str(restore_dir),
        logfile_location=env.log_file,
        command_timeout_secs=10,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=1,
        restoretest_exclude_prefixes=[],
        restoretest_exclude_suffixes=[],
        restoretest_exclude_regex=None,
        restore_ownership=False,
    )

    mock_runner = MagicMock()
    mock_runner.run.return_value.returncode = 0
    mock_def_content = "-R /\n-s 10G\n"

    original_remove = os.remove

    def remove_raises_for_restore_path(path):
        if os.path.normpath(path) == os.path.normpath(str(restore_path)):
            raise OSError("Permission denied (simulated read-only mount)")
        return original_remove(path)

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.get_backed_up_files", return_value=[(file_path, "100 o")]), \
         patch("dar_backup.dar_backup.filecmp.cmp", return_value=True), \
         patch("dar_backup.dar_backup.logger") as mock_logger, \
         patch("dar_backup.dar_backup.os.remove", side_effect=remove_raises_for_restore_path), \
         patch("builtins.open", mock_open(read_data=mock_def_content)):
        verify(args, "mock-backup", env.config_file, config)

    warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
    assert any("stale" in c.lower() or "could not remove" in c.lower() for c in warning_calls), (
        f"Expected a warning about the stale file removal failure; got: {warning_calls}"
    )


def test_verify_restore_command_includes_overwrite_flag(env, tmp_path):
    """The dar restore command used inside verify() must include -wa so that a
    stale file left in the restore directory is overwritten rather than causing
    dar to refuse and return non-zero (which would produce a false FAIL).

    Consistent with restore_backup() (line 729) and _restore_with_dar() (line 1041)
    which both already pass -wa.
    """
    restore_dir = tmp_path / "restore_test"
    restore_dir.mkdir()

    file_path = "/path/to/test_file.txt"

    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)
    config = SimpleNamespace(
        test_restore_dir=str(restore_dir),
        logfile_location=env.log_file,
        command_timeout_secs=10,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=1,
        restoretest_exclude_prefixes=[],
        restoretest_exclude_suffixes=[],
        restoretest_exclude_regex=None,
        restore_ownership=False,
    )

    mock_runner = MagicMock()
    mock_runner.run.return_value.returncode = 0
    mock_def_content = "-R /\n-s 10G\n"

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.get_backed_up_files", return_value=[(file_path, "100 o")]), \
         patch("dar_backup.dar_backup.filecmp.cmp", return_value=True), \
         patch("dar_backup.dar_backup.logger"), \
         patch("builtins.open", mock_open(read_data=mock_def_content)):
        verify(args, "mock-backup", env.config_file, config)

    # Find the dar restore call (the one that includes -x, not manager --add-specific-archive)
    dar_calls = [
        call for call in mock_runner.run.call_args_list
        if call.args and isinstance(call.args[0], list) and call.args[0][:2] == ["dar", "-x"]
    ]
    assert dar_calls, "Expected at least one 'dar -x' call from verify()"
    dar_cmd = dar_calls[0].args[0]
    assert "-wa" in dar_cmd, (
        f"dar verify-restore command must include -wa to overwrite stale files; got: {dar_cmd}"
    )


def test_verify_runner_exception_logs_error_not_print(env, tmp_path):
    """When runner.run() itself raises during the dar -t integrity check,
    verify() must log via logger.error() — not print() — and re-raise.

    On a systemd service stdout is not captured.  The error message must say
    'verification' not 'backup' so that operators can identify the failing phase.
    """
    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)
    config = SimpleNamespace(
        test_restore_dir=str(tmp_path),
        logfile_location=env.log_file,
        command_timeout_secs=10,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=1,
        restoretest_exclude_prefixes=[],
        restoretest_exclude_suffixes=[],
        restoretest_exclude_regex=None,
        restore_ownership=False,
    )

    mock_runner = MagicMock()
    mock_runner.run.side_effect = OSError("cannot spawn dar process")

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.logger") as mock_logger:
        with pytest.raises(OSError):
            verify(args, "mock-backup", env.config_file, config)

    error_calls = [str(c) for c in mock_logger.error.call_args_list]
    assert any("verification" in c.lower() and "could not be run" in c.lower() for c in error_calls), (
        f"Expected logger.error naming a verification failure; got: {error_calls}"
    )
    assert not any("backup failed" in c.lower() for c in error_calls), (
        "Error message must not say 'backup failed' for a verification-phase failure"
    )
