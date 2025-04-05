import pytest
import os
from unittest.mock import patch
from types import SimpleNamespace
from dar_backup.util import BackupError
from dar_backup.dar_backup import verify
from unittest.mock import patch, MagicMock, mock_open


def test_verify_filecmp_mismatch_raises_backup_error(env):
    args = SimpleNamespace(
        verbose=False,
        do_not_compare=False,
        darrc=env.dar_rc  # ← This fixes the final crash
    )

    config = SimpleNamespace(
        test_restore_dir=env.restore_dir,
        logfile_location=env.log_file,
        verify_files=["/some/file.txt"],
        command_timeout_secs=86400,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=5
    )

    mock_runner = MagicMock()
    mock_runner.run.return_value.returncode = 0

    mock_definition_content = "-R /\n-s 10G\n"

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.filecmp.cmp", return_value=False), \
         patch("dar_backup.dar_backup.get_backed_up_files", return_value=[("/some/file.txt", "10 Mio")]), \
         patch("dar_backup.dar_backup.logger"), \
         patch("dar_backup.dar_backup.show_log_driven_bar"), \
         patch("builtins.open", mock_open(read_data=mock_definition_content)):
        with pytest.raises(BackupError, match="did not match the original"):
            verify(args, "mock-backup", env.config_file, config)



def test_verify_filecmp_permission_error_logged(env):
    """Ensure PermissionError during filecmp is caught and logged."""
    args = SimpleNamespace(
        verbose=False,
        do_not_compare=False,
        darrc=env.dar_rc
    )

    config = SimpleNamespace(
        test_restore_dir=env.restore_dir,
        logfile_location=env.log_file,
        verify_files=["/some/file.txt"],
        command_timeout_secs=86400,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=5
    )

    mock_runner = MagicMock()
    mock_runner.run.return_value.returncode = 0
    mock_definition_content = "-R /\n-s 10G\n"

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.get_backed_up_files", return_value=[("/some/file.txt", "10 Mio")]), \
         patch("dar_backup.dar_backup.filecmp.cmp", side_effect=PermissionError), \
         patch("dar_backup.dar_backup.logger") as mock_logger, \
         patch("dar_backup.dar_backup.show_log_driven_bar"), \
         patch("builtins.open", mock_open(read_data=mock_definition_content)):

        verify(args, "mock-backup", env.config_file, config)

        assert mock_logger.exception.called
        assert mock_logger.error.called




from unittest.mock import patch, MagicMock
from types import SimpleNamespace
from dar_backup.dar_backup import verify

def test_verify_do_not_compare_skips_verification(env):
    """Verify that --do-not-compare skips file comparison and exits cleanly."""
    args = SimpleNamespace(
        verbose=False,
        do_not_compare=True,
        darrc=env.dar_rc
    )

    config = SimpleNamespace(
        test_restore_dir=env.restore_dir,
        logfile_location=env.log_file,
        verify_files=["/some/file.txt"],
        command_timeout_secs=86400,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=5
    )

    mock_runner = MagicMock()
    mock_runner.run.return_value.returncode = 0

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.get_backed_up_files") as mock_get_files, \
         patch("dar_backup.dar_backup.filecmp.cmp") as mock_cmp, \
         patch("dar_backup.dar_backup.logger"), \
         patch("dar_backup.dar_backup.show_log_driven_bar"), \
         patch("builtins.open", MagicMock(read_data="-R /\n")):
        
        result = verify(args, "mock-backup", env.config_file, config)
        
        assert result is True
        mock_get_files.assert_not_called()
        mock_cmp.assert_not_called()



def test_verify_success_path_with_verbose_logging(env):
    """Test full successful verification flow with verbose logging enabled."""
    args = SimpleNamespace(
        verbose=True,
        do_not_compare=False,
        darrc=env.dar_rc
    )

    config = SimpleNamespace(
        test_restore_dir=env.restore_dir,
        logfile_location=env.log_file,
        verify_files=["/some/file.txt"],
        command_timeout_secs=86400,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=1
    )

    mock_runner = MagicMock()
    mock_runner.run.return_value.returncode = 0

    mock_file = "/some/file.txt"
    mock_definition_content = "-R /\n-s 10G\n"

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.filecmp.cmp", return_value=True) as mock_cmp, \
         patch("dar_backup.dar_backup.get_backed_up_files", return_value=[(mock_file, "10 Mio")]), \
         patch("dar_backup.dar_backup.logger") as mock_logger, \
         patch("dar_backup.dar_backup.show_log_driven_bar"), \
         patch("builtins.open", mock_open(read_data=mock_definition_content)):

        result = verify(args, "mock-backup", env.config_file, config)

        assert result is True
        mock_cmp.assert_called_once()
        mock_logger.info.assert_any_call(f"Success: file '{mock_file}' matches the original")



from types import SimpleNamespace
from dar_backup.dar_backup import perform_backup

def test_perform_backup_skips_definition_with_underscore_in_args(env):
    args = SimpleNamespace(backup_definition="bad_name_with_underscore.dcf")

    config = SimpleNamespace(
        backup_d_dir=os.path.join(env.test_dir, "backup.d")  # manually set expected directory
    )
    os.makedirs(config.backup_d_dir, exist_ok=True)  # make sure dir exists

    with patch("dar_backup.dar_backup.logger") as mock_logger:
        results = perform_backup(args, config, "FULL")

    assert results == [("Skipping backup definition: 'bad_name_with_underscore.dcf' due to '_' in name", 1)]
    mock_logger.error.assert_called_once()




def test_perform_backup_skips_files_with_underscore_in_directory(env):
    config = SimpleNamespace(
        backup_d_dir=os.path.join(env.test_dir, "backup.d")
    )
    os.makedirs(config.backup_d_dir, exist_ok=True)

    # Create a bad file with an underscore
    bad_file = os.path.join(config.backup_d_dir, "bad_file_with_underscore.dcf")
    with open(bad_file, "w") as f:
        f.write("-R /\n")

    args = SimpleNamespace(backup_definition=None)

    with patch("dar_backup.dar_backup.logger") as mock_logger:
        results = perform_backup(args, config, "FULL")

    assert len(results) == 1
    assert "due to '_' in: name" in results[0][0]
    assert results[0][1] == 1
    mock_logger.error.assert_called_once()
