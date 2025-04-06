import pytest
import os
from unittest.mock import patch
from types import SimpleNamespace
from dar_backup.util import BackupError
from dar_backup.dar_backup import verify
import dar_backup.dar_backup as db
from unittest.mock import patch, MagicMock, mock_open
import subprocess
from dar_backup.dar_backup import restore_backup, RestoreError
import dar_backup.dar_backup as db


def test_verify_filecmp_mismatch_returns_false(env):
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
         patch("dar_backup.dar_backup.filecmp.cmp", return_value=False), \
         patch("dar_backup.dar_backup.get_backed_up_files", return_value=[("/some/file.txt", "10 Mio")]), \
         patch("dar_backup.dar_backup.logger"), \
         patch("dar_backup.dar_backup.show_log_driven_bar"), \
         patch("builtins.open", mock_open(read_data=mock_definition_content)):
        
        result = verify(args, "mock-backup", env.config_file, config)
        assert result is False


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



from types import SimpleNamespace
from dar_backup.dar_backup import perform_backup

def test_perform_backup_skips_diff_when_no_base_backup(env):
    args = SimpleNamespace(
        backup_definition="test.dcf",
        alternate_reference_archive=None,
        darrc=env.dar_rc
    )

    config = SimpleNamespace(
        backup_d_dir=env.test_dir,
        backup_dir=env.backup_dir
    )

    # Create a fake backup definition file
    os.makedirs(config.backup_d_dir, exist_ok=True)
    with open(os.path.join(config.backup_d_dir, "test.dcf"), "w") as f:
        f.write("-R /\n")

    # Ensure backup_dir is empty (no .1.dar base backups)
    os.makedirs(config.backup_dir, exist_ok=True)

    with patch("dar_backup.dar_backup.logger") as mock_logger:
        results = perform_backup(args, config, "DIFF")

    assert len(results) == 1
    assert "No FULL backup found" in results[0][0]
    assert results[0][1] == 1




def test_perform_backup_handles_failed_verification(env):
    args = SimpleNamespace(
        backup_definition="test.dcf",
        alternate_reference_archive=None,
        darrc=env.dar_rc
    )

    config = SimpleNamespace(
        backup_d_dir=env.test_dir,
        backup_dir=env.backup_dir
    )

    # Fake backup definition
    os.makedirs(config.backup_d_dir, exist_ok=True)
    with open(os.path.join(config.backup_d_dir, "test.dcf"), "w") as f:
        f.write("-R /\n")

    # Fake FULL backup exists to pass DIFF check
    backup_file_path = os.path.join(config.backup_dir, "test_FULL_2000-01-01.1.dar")
    os.makedirs(config.backup_dir, exist_ok=True)
    with open(backup_file_path, "w") as f:
        f.write("DAR FILE")

    with patch("dar_backup.dar_backup.verify", return_value=False), \
         patch("dar_backup.dar_backup.generic_backup", return_value=[]), \
         patch("dar_backup.dar_backup.create_backup_command", return_value=["dar", "-c"]), \
         patch("dar_backup.dar_backup.generate_par2_files"), \
         patch("dar_backup.dar_backup.logger") as mock_logger:
        results = perform_backup(args, config, "FULL")

    assert any("Verification of" in r[0] for r in results)





def test_perform_backup_handles_exception_during_processing(env):
    args = SimpleNamespace(
        backup_definition="test.dcf",
        alternate_reference_archive=None,
        darrc=env.dar_rc
    )

    config = SimpleNamespace(
        backup_d_dir=env.test_dir,
        backup_dir=env.backup_dir
    )

    os.makedirs(config.backup_d_dir, exist_ok=True)
    with open(os.path.join(config.backup_d_dir, "test.dcf"), "w") as f:
        f.write("-R /\n")

    with patch("dar_backup.dar_backup.generic_backup", side_effect=RuntimeError("Boom")), \
         patch("dar_backup.dar_backup.create_backup_command", return_value=["dar", "-c"]), \
         patch("dar_backup.dar_backup.verify", return_value=True), \
         patch("dar_backup.dar_backup.logger") as mock_logger:
        results = perform_backup(args, config, "FULL")

    assert len(results) == 1
    assert "Boom" in results[0][0]
    mock_logger.exception.assert_called_once()

## ==================================================

from dar_backup.dar_backup import list_contents


def test_list_contents_with_selection_parses_and_extends_command(env, capsys):
    backup_name = "dummy_backup"
    backup_dir = env.backup_dir
    selection = "--selections somefile.txt"

    mock_process = SimpleNamespace(stdout="[Saved] somefile.txt", stderr="", returncode=0)

    mock_runner = MagicMock()
    mock_runner.run.return_value = mock_process

    with patch("dar_backup.dar_backup.runner", mock_runner):
        list_contents(backup_name, backup_dir, selection)

    captured = capsys.readouterr()
    assert "[Saved]" in captured.out
    mock_runner.run.assert_called_once()

def test_list_contents_handles_nonzero_returncode(env):
    backup_name = "fail_backup"
    backup_dir = env.backup_dir

    mock_process = SimpleNamespace(stdout="", stderr="err", returncode=1)
    mock_runner = MagicMock()
    mock_runner.run.return_value = mock_process

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.logger") as mock_logger:
        with pytest.raises(RuntimeError):
            list_contents(backup_name, backup_dir)

    mock_logger.error.assert_called_once_with(f"Error listing contents of backup: '{backup_name}'")


import subprocess

def test_list_contents_raises_backup_error_on_called_process_error(env):
    backup_name = "error_backup"
    backup_dir = env.backup_dir

    mock_runner = MagicMock()
    mock_runner.run.side_effect = subprocess.CalledProcessError(1, "dar")

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.logger") as mock_logger:
        with pytest.raises(BackupError):
            list_contents(backup_name, backup_dir)

    mock_logger.error.assert_called_once_with(f"Error listing contents of backup: '{backup_name}'")



def test_list_contents_raises_runtime_error_on_generic_exception(env):
    backup_name = "broken_backup"
    backup_dir = env.backup_dir

    mock_runner = MagicMock()
    mock_runner.run.side_effect = Exception("Unexpected!")

    with patch("dar_backup.dar_backup.runner", mock_runner):
        with pytest.raises(RuntimeError) as excinfo:
            list_contents(backup_name, backup_dir)

    assert f"Unexpected error listing contents of backup: '{backup_name}'" in str(excinfo.value)

#===================


def test_restore_backup_process_fails(tmp_path):
    config = SimpleNamespace(
        backup_dir=tmp_path,
        command_timeout_secs=10
    )
    backup_name = "backup"
    darrc = "dummy_darrc"
    restore_dir = tmp_path / "restore"

    # Create dummy backup file
    (tmp_path / backup_name).touch()

    # Inject a mock CommandRunner instance
    db.runner = MagicMock()
    db.logger = MagicMock()

    # Configure runner.run() to simulate a failure
    db.runner.run.return_value = SimpleNamespace(
        returncode=1,
        stdout="mock stdout",
        stderr="mock stderr"
    )

    with pytest.raises(RestoreError, match="mock stderr"):
        restore_backup(backup_name, config, str(restore_dir), darrc)

    db.logger.error.assert_any_call(
        "Restore command failed: \n ==> stdout: mock stdout, \n ==> stderr: mock stderr"
    )



def test_restore_backup_calledprocesserror(tmp_path):
    config = SimpleNamespace(
        backup_dir=tmp_path,
        command_timeout_secs=10
    )
    backup_name = "backup"
    darrc = "dummy_darrc"
    restore_dir = tmp_path / "restore"

    # Touch dummy backup file
    (tmp_path / backup_name).touch()

    with patch.object(db, "runner") as mock_runner, \
         patch.object(db, "logger", new=MagicMock()):
        # Raise the expected exception from the runner
        mock_runner.run.side_effect = subprocess.CalledProcessError(1, "cmd")

        # Now test
        with pytest.raises(RestoreError, match="Restore command failed"):
            restore_backup(backup_name, config, str(restore_dir), darrc)



def test_restore_backup_oserror(tmp_path):
    config = SimpleNamespace(
        backup_dir=tmp_path,
        command_timeout_secs=10
    )
    backup_name = "backup"
    darrc = "dummy_darrc"
    restore_dir = tmp_path / "restore"

    with patch("os.makedirs", side_effect=OSError("Permission denied")), \
         patch.object(db, "runner", new=MagicMock()), \
         patch.object(db, "logger", new=MagicMock()):
        with pytest.raises(RestoreError, match="Could not create restore directory"):
            restore_backup(backup_name, config, str(restore_dir), darrc)
