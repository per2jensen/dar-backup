from unittest.mock import MagicMock, patch, mock_open
from types import SimpleNamespace
from dar_backup.dar_backup import verify
import pytest

pytestmark = pytest.mark.integration






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
