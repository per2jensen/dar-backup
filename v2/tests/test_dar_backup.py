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
from pathlib import Path 



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


# =========================00

def test_generic_backup_warns_on_returncode_5(env):
    from dar_backup.dar_backup import generic_backup

    args = SimpleNamespace(
        darrc=env.dar_rc,
        config_file=env.config_file,
        verbose=False
    )

    config = SimpleNamespace(
        logfile_location=env.log_file,
        command_timeout_secs=10
    )

    mock_runner = MagicMock()
    mock_runner.run.return_value = SimpleNamespace(returncode=5, stdout="partial backup", stderr="")
    
    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.get_logger"), \
         patch("dar_backup.dar_backup.logger") as mock_logger, \
         patch("dar_backup.dar_backup.show_log_driven_bar"):
        
        result = generic_backup("FULL", ["dar", "-c"], "backup", "example.dcf", env.dar_rc, config, args)

        assert isinstance(result, list)
        mock_logger.warning.assert_called_once()



def test_catalog_add_failure_handled(env):
    from dar_backup.dar_backup import generic_backup

    args = SimpleNamespace(
        darrc=env.dar_rc,
        config_file=env.config_file,
        verbose=False
    )

    config = SimpleNamespace(
        logfile_location=env.log_file,
        command_timeout_secs=10
    )

    # simulate backup succeeded (0) but catalog failed (1)
    mock_runner = MagicMock()
    mock_runner.run.side_effect = [
        SimpleNamespace(returncode=0, stdout="ok", stderr=""),
        SimpleNamespace(returncode=1, stdout="", stderr="manager failed")
    ]

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.get_logger"), \
         patch("dar_backup.dar_backup.logger") as mock_logger, \
         patch("dar_backup.dar_backup.show_log_driven_bar"):

        result = generic_backup("FULL", ["dar", "-c"], "backup", "example.dcf", env.dar_rc, config, args)

        assert len(result) == 1
        assert result[0][1] == 1
        assert "not added" in result[0][0]
        mock_logger.error.assert_called()



import pytest
from types import SimpleNamespace
from unittest.mock import patch, mock_open
from dar_backup.dar_backup import verify
from dar_backup.util import BackupError

def test_verify_raises_error_if_no_root_path(env):
    """
    Ensure that verify() raises a BackupError if no '-R' line is present in the backup definition.
    """
    args = SimpleNamespace(
        verbose=False,
        do_not_compare=False,
        darrc=env.dar_rc
    )

    config = SimpleNamespace(
        test_restore_dir=env.restore_dir,
        logfile_location=env.log_file,
        command_timeout_secs=10,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=1
    )

    # Simulate successful 'dar -t' command with returncode 0
    fake_process = SimpleNamespace(returncode=0)

    with patch("builtins.open", mock_open(read_data="-s 10G\n")), \
         patch("dar_backup.dar_backup.runner") as mock_runner, \
         patch("dar_backup.dar_backup.get_backed_up_files", return_value=[("/file.txt", "10 Mio")]), \
         patch("dar_backup.dar_backup.logger"), \
         patch("dar_backup.dar_backup.show_log_driven_bar"), \
         patch("dar_backup.dar_backup.get_logger"), \
         patch("threading.Thread"):  # skip actual threading for test

        mock_runner.run.return_value = fake_process

        with pytest.raises(BackupError, match="No Root.*-R"):
            verify(args, "mock.dar", "mock-def.dcf", config)


def test_restore_backup_raises_if_restore_dir_none(tmp_path):
    from dar_backup.dar_backup import restore_backup, RestoreError

    config = SimpleNamespace(
        backup_dir=str(tmp_path),
        command_timeout_secs=10
    )

    backup_name = "archive"
    (tmp_path / backup_name).touch()

    with patch("dar_backup.dar_backup.runner"), \
         patch("dar_backup.dar_backup.logger"):
        with pytest.raises(RestoreError, match="directory.*not specified"):
            restore_backup(backup_name, config, restore_dir=None, darrc="darrc")




import subprocess
import sys

def test_main_fails_when_definition_file_missing(tmp_path):
    bad_def_dir = tmp_path / "missing_dir"
    logfile_path = tmp_path / "dar-backup.log"
    config_path = tmp_path / "dar.conf"

    config_text = f"""
    [MISC]
    LOGFILE_LOCATION = {logfile_path}
    MAX_SIZE_VERIFICATION_MB = 20
    MIN_SIZE_VERIFICATION_MB = 0
    NO_FILES_VERIFICATION = 5
    COMMAND_TIMEOUT_SECS = 86400

    [DIRECTORIES]
    BACKUP_DIR = {tmp_path}/backups
    BACKUP.D_DIR = {bad_def_dir}
    DATA_DIR = {tmp_path}/data
    TEST_RESTORE_DIR = {tmp_path}/restore

    [AGE]
    DIFF_AGE = 30
    INCR_AGE = 15

    [PAR2]
    ERROR_CORRECTION_PERCENT = 5
    ENABLED = true
    """
    config_path.write_text(config_text.strip())
    assert not bad_def_dir.exists()

    result = subprocess.run([
        sys.executable,
        "-m", "dar_backup.dar_backup",
        "--full-backup",
        "--backup-definition", "foo.dcf",
        "--config-file", str(config_path)
    ], capture_output=True, text=True)

    if result.returncode != 127 or not result.stderr:
        print("STDOUT:\n", result.stdout)
        print("STDERR:\n", result.stderr)

    assert result.returncode == 127


import pytest
from unittest.mock import patch, MagicMock
from types import SimpleNamespace
from pathlib import Path

def test_main_defensive_check_invalid_result_format(env, setup_environment):
    from dar_backup.dar_backup import main

    # Ensure dummy .dcf file exists so it passes early validation
    (Path(env.backup_d_dir) / "example.dcf").touch()

    # This will be the mocked logger returned from setup_logging()
    mock_logger = MagicMock()

    with patch("dar_backup.dar_backup.generic_backup", return_value="not-a-valid-list"), \
         patch("dar_backup.dar_backup.setup_logging", return_value=mock_logger), \
         patch("dar_backup.dar_backup.CommandRunner"), \
         patch("dar_backup.dar_backup.requirements"):

        with patch("argparse.ArgumentParser.parse_args", return_value=SimpleNamespace(
            full_backup=True,
            config_file=env.config_file,
            darrc=env.dar_rc,
            verbose=True,
            log_stdout=True,
            backup_definition="example.dcf",
            differential_backup=False,
            incremental_backup=False,
            restore=None,
            list=False,
            list_contents=None,
            suppress_dar_msg=False,
            do_not_compare=False,
            examples=False,
            version=False,
            readme=False,
            readme_pretty=False,
            changelog=False,
            changelog_pretty=False,
            selection=None,
            restore_dir=None,
            alternate_reference_archive=None,
            log_level="info"
        )):

            # Expect SystemExit due to final exit(1) in main
            with pytest.raises(SystemExit) as exc_info:
                main()

            # Check it exited with code 1
            assert exc_info.value.code == 1

            # Verify that the logger caught the defensive error message
            mock_logger.error.assert_any_call("Unexpected return format from generic_backup")



from dar_backup.dar_backup import main as dar_main

def test_test_restore_cli(monkeypatch):
    args = ["dar-backup", "--test-restore", "-d", "example", "--config-file", "dummy.conf"]
    monkeypatch.setattr(sys, "argv", args)

    with patch("dar_backup.command_runner.CommandRunner.run") as mock_run:
        mock_run.return_value.returncode = 0
        with pytest.raises(SystemExit):
            dar_main()



from types import SimpleNamespace
from dar_backup.dar_backup import find_files_between_min_and_max_size

def test_find_files_within_min_max_range(env):
    files = [
        ("tiny.txt", "0 o"),
        ("small.txt", "512 kio"),
        ("valid1.txt", "1 Mio"),
        ("valid2.txt", "5 Mio"),
        ("large.txt", "20 Mio"),
        ("huge.txt", "2 Gio"),
    ]

    config = SimpleNamespace(
        min_size_verification_mb=1,
        max_size_verification_mb=10,
        logger=env.logger
    )

    # Monkey patch the logger inside dar_backup
    import dar_backup.dar_backup as dar_module
    dar_module.logger = env.logger

    result = find_files_between_min_and_max_size(files, config)

    assert "valid1.txt" in result
    assert "valid2.txt" in result
    assert "tiny.txt" not in result
    assert "small.txt" not in result
    assert "large.txt" not in result
    assert "huge.txt" not in result
    assert len(result) == 2


def test_filter_restoretest_candidates_case_insensitive():
    import re
    from dar_backup.dar_backup import filter_restoretest_candidates

    files = [
        "Docs/Report.LOG",
        ".cache/foo.txt",
        "notes.txt",
        "dir/Cache/file.tmp",
        "data.db",
    ]
    config = SimpleNamespace(
        restoretest_exclude_prefixes=[".CACHE/"],
        restoretest_exclude_suffixes=[".log", ".TMP"],
        restoretest_exclude_regex=re.compile(r"(^|/)(cache|logs)/", re.IGNORECASE),
    )

    result = filter_restoretest_candidates(files, config)

    assert "notes.txt" in result
    assert "data.db" in result
    assert "Docs/Report.LOG" not in result
    assert ".cache/foo.txt" not in result
    assert "dir/Cache/file.tmp" not in result


def test_restoretest_filters_and_verifies_all_good_files(env):
    import re
    from dar_backup.dar_backup import verify

    args = SimpleNamespace(
        verbose=True,
        do_not_compare=False,
        darrc=env.dar_rc
    )

    config = SimpleNamespace(
        test_restore_dir=env.restore_dir,
        logfile_location=env.log_file,
        command_timeout_secs=86400,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=2,
        restoretest_exclude_prefixes=[".cache/"],
        restoretest_exclude_suffixes=[".log", ".tmp"],
        restoretest_exclude_regex=re.compile(r"(^|/)(Cache|cache)/", re.IGNORECASE),
    )

    good_files = [
        "/good/dir1/file1.txt",
        "/good/dir3/file3.txt",
    ]
    backed_up_files = [
        ("/.cache/skip1.txt", "10 Mio"),
        ("/good/dir1/file1.txt", "10 Mio"),
        ("/good/dir2/file2.log", "10 Mio"),
        ("/good/dir3/file3.txt", "10 Mio"),
        ("/data/Cache/file4.txt", "10 Mio"),
        ("/var/tmp/skip.tmp", "10 Mio"),
    ]

    mock_runner = MagicMock()
    mock_runner.run.return_value.returncode = 0

    mock_definition_content = "-R /\n-s 10G\n"

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.filecmp.cmp", return_value=True), \
         patch("dar_backup.dar_backup.get_backed_up_files", return_value=backed_up_files), \
         patch("dar_backup.dar_backup.logger") as mock_logger, \
         patch("dar_backup.dar_backup.show_log_driven_bar"), \
         patch("dar_backup.dar_backup.random.sample", side_effect=lambda files, n: list(files)), \
         patch("builtins.open", mock_open(read_data=mock_definition_content)):

        result = verify(args, "mock-backup", env.config_file, config)

    assert result is True

    restore_calls = [
        call for call in mock_runner.run.call_args_list
        if "-x" in call.args[0]
    ]
    assert len(restore_calls) == len(good_files)
    for path in good_files:
        expected_token = path.lstrip("/")
        assert any(expected_token in call.args[0] for call in restore_calls)

    mock_logger.debug.assert_any_call(
        "Restore test filter excluded 4 of 6 candidates"
    )



####################################################
# 2025-10-08


# tests/test_dar_backup.py
import os
import pytest
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import dar_backup.dar_backup as db
from dar_backup.util import BackupError


# 1) generic_backup(): inner try/except when runner raises a generic Exception
#    Improvement #4: parametrize over FULL/DIFF/INCR
@pytest.mark.parametrize("btype", ["FULL", "DIFF", "INCR"])
def test_generic_backup_runner_exception_raises(env, tmp_path, btype):
    config = SimpleNamespace(
        logfile_location=str(tmp_path / "dar-backup.log"),
        command_timeout_secs=5,
    )
    args = SimpleNamespace(config_file=str(tmp_path / "dar-backup.conf"))
    darrc = str(tmp_path / "dummy_darrc")
    os.makedirs(tmp_path, exist_ok=True)
    open(darrc, "w").close()

    class DummyThread:
        def __init__(self, *a, **k): pass
        def start(self): pass
        def join(self): pass

    with patch.object(db, "threading") as mock_threading, \
         patch.object(db, "show_log_driven_bar"), \
         patch.object(db, "get_logger") as mock_get_logger, \
         patch.object(db, "logger", new=MagicMock()):
        mock_threading.Thread.side_effect = lambda *a, **k: DummyThread()
        mock_get_logger.return_value = MagicMock(info=MagicMock())

        with patch.object(db, "runner") as mock_runner:
            mock_runner.run.side_effect = Exception("boom")
            with pytest.raises(Exception, match="boom"):
                db.generic_backup(
                    type=btype,
                    command=["dar", "-c", "archive", "-R", "/"],
                    backup_file="archive.1.dar",
                    backup_definition=str(tmp_path / "backup.d/photos"),
                    config_settings=config,
                    args=args,
                    darrc=darrc,
                )

        # Improvement #4 add-on: ensure progress thread constructed
        assert mock_threading.Thread.call_count == 1


# 2) generic_backup(): outer handler wraps CalledProcessError -> BackupError
#    Improvement #4: parametrize over FULL/DIFF/INCR
@pytest.mark.parametrize("btype", ["FULL", "DIFF", "INCR"])
def test_generic_backup_calledprocesserror_wrapped(env, tmp_path, btype):
    config = SimpleNamespace(
        logfile_location=str(tmp_path / "dar-backup.log"),
        command_timeout_secs=5,
    )
    args = SimpleNamespace(config_file=str(tmp_path / "dar-backup.conf"))
    darrc = str(tmp_path / "dummy_darrc")
    open(darrc, "w").close()

    class DummyThread:
        def __init__(self, *a, **k): pass
        def start(self): pass
        def join(self): pass

    with patch.object(db, "threading") as mock_threading, \
         patch.object(db, "show_log_driven_bar"), \
         patch.object(db, "get_logger") as mock_get_logger, \
         patch.object(db, "logger", new=MagicMock()):
        mock_threading.Thread.side_effect = lambda *a, **k: DummyThread()
        mock_get_logger.return_value = MagicMock(info=MagicMock())

        with patch.object(db, "runner") as mock_runner:
            mock_runner.run.side_effect = subprocess.CalledProcessError(
                1, ["dar", "-c", "archive"]
            )
            with pytest.raises(BackupError) as exc:
                db.generic_backup(
                    type=btype,
                    command=["dar", "-c", "archive", "-R", "/"],
                    backup_file="archive.1.dar",
                    backup_definition=str(tmp_path / "backup.d/photos"),
                    config_settings=config,
                    args=args,
                    darrc=darrc,
                )
            assert "Backup command failed" in str(exc.value)

        # Improvement #4 add-on: ensure progress thread constructed
        assert mock_threading.Thread.call_count == 1


# 3) restore_backup(): selection handling and darrc propagation
#    Improvement #1: assert -B darrc is in command
#    Improvement #2: cover selection present vs None with parametrization
@pytest.mark.parametrize(
    "selection, expect_tokens",
    [
        ('--selections some/file.txt --selections "dir with spaces/"',
         ["--selections", "some/file.txt", "dir with spaces/"]),
        (None, []),
    ],
)
def test_restore_backup_selection_and_darrc(tmp_path, selection, expect_tokens):
    config = SimpleNamespace(
        backup_dir=str(tmp_path),
        command_timeout_secs=5,
    )
    backup_name = "backup_FULL_20240101"
    darrc = str(tmp_path / "dummy_darrc")
    open(darrc, "w").close()
    restore_dir = tmp_path / "restore"
    (tmp_path / backup_name).touch()  # simulate existing archive

    with patch.object(db, "runner") as mock_runner, \
         patch.object(db, "logger", new=MagicMock()):
        mock_runner.run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        db.restore_backup(backup_name, config, str(restore_dir), darrc, selection)

        called_cmd = mock_runner.run.call_args[0][0]
        # -R restore target present
        assert "-R" in called_cmd and str(restore_dir) in called_cmd
        # Improvement #1: darrc must be passed with -B
        assert "-B" in called_cmd and darrc in called_cmd

        # Improvement #2: selection tokens when provided, absent when None
        for tok in expect_tokens:
            assert tok in called_cmd
        if selection is None:
            assert "--selections" not in called_cmd


# 4) print_markdown(): missing file exits with code 1 and prints error
def test_print_markdown_missing_file_exits(capsys, tmp_path):
    missing = str(tmp_path / "NO_SUCH_FILE.md")
    with pytest.raises(SystemExit) as exc:
        db.print_markdown(missing, pretty=False)
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "File not found" in out


# 5) get_backed_up_files(): error mapping
#    Improvement #3: parametrize generic Exception -> RuntimeError, and CalledProcessError -> BackupError
@pytest.mark.parametrize(
    "side_effect, expected_exc, match",
    [
        (subprocess.CalledProcessError(1, "dar"), BackupError, r"Error listing backed up files"),
        (Exception("explode"), RuntimeError, r"Unexpected error listing backed up files.*dummy_backup"),
    ],
)
def test_get_backed_up_files_error_mapping(tmp_path, side_effect, expected_exc, match):
    backup_name = "dummy_backup"
    backup_dir = str(tmp_path)
    (tmp_path / backup_name).touch()

    with patch.object(db, "runner") as mock_runner, \
         patch.object(db, "logger", new=MagicMock()):
        mock_runner.run.side_effect = side_effect
        with pytest.raises(expected_exc, match=match):
            db.get_backed_up_files(backup_name, backup_dir)



###############################################

# --- get_backed_up_files -----------------------------------------------------

def test_get_backed_up_files_success_parses_xml(tmp_path):
    """Success path: returns parsed (path, size) tuples from dar -Txml output."""
    backup_name = "dummy_backup"
    backup_dir = str(tmp_path)
    (tmp_path / backup_name).touch()

    # Minimal XML that matches find_files_with_paths() expectations
    xml = """<?xml version="1.0"?>
<DARArchive>
  <Directory name="dirA">
    <File name="a.txt" size="123"/>
    <Directory name="nested">
      <File name="b.bin" size="456"/>
    </Directory>
  </Directory>
  <File name="root.log" size="78"/>
</DARArchive>
"""

    with patch.object(db, "runner") as mock_runner, \
         patch.object(db, "logger", new=MagicMock()):
        mock_runner.run.return_value = SimpleNamespace(returncode=0, stdout=xml, stderr="")
        files = db.get_backed_up_files(backup_name, backup_dir)

    # Expect normalized paths with sizes as strings
    # Order should match traversal: dirA/a.txt, dirA/nested/b.bin, root.log
    assert ("dirA/a.txt", "123") in files
    assert ("dirA/nested/b.bin", "456") in files
    assert ("root.log", "78") in files
    assert len(files) == 3


# --- generate_par2_files -----------------------------------------------------

def test_generate_par2_files_success_invokes_par2(tmp_path):
    # Arrange: create two DAR slices the function will discover
    (tmp_path / "example_FULL_2025-01-01.1.dar").write_text("")
    (tmp_path / "example_FULL_2025-01-01.2.dar").write_text("")
    backup_file = "example_FULL_2025-01-01"
    cfg = SimpleNamespace(
        backup_dir=str(tmp_path),
        error_correction_percent=10,
        command_timeout_secs=5,
        logfile_location=str(tmp_path / "dar-backup.log"),
    )
    args = SimpleNamespace(config_file=str(tmp_path / "dar-backup.conf"))

    with patch.object(db, "runner") as mock_runner, \
         patch.object(db, "logger", new=MagicMock()):
        mock_runner.run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")

        db.generate_par2_files(backup_file, cfg, args)

        # Two slices -> two calls
        assert mock_runner.run.call_count == 2
        # Commands should include -r10 and the slice path
        called_cmds = [c[0][0] for c in mock_runner.run.call_args_list]
        assert any("-r10" in " ".join(map(str, cmd)) for cmd in called_cmds)
        assert any("example_FULL_2025-01-01.1.dar" in " ".join(map(str, cmd)) for cmd in called_cmds)
        assert any("example_FULL_2025-01-01.2.dar" in " ".join(map(str, cmd)) for cmd in called_cmds)


def test_generate_par2_files_failure_raises_calledprocesserror(tmp_path):
    # Arrange: one slice present so the function actually calls runner.run
    (tmp_path / "example_FULL_2025-01-01.1.dar").write_text("")
    backup_file = "example_FULL_2025-01-01"
    cfg = SimpleNamespace(
        backup_dir=str(tmp_path),
        error_correction_percent=5,
        command_timeout_secs=5,
        logfile_location=str(tmp_path / "dar-backup.log"),
    )
    args = SimpleNamespace(config_file=str(tmp_path / "dar-backup.conf"))

    with patch.object(db, "runner") as mock_runner, \
         patch.object(db, "logger", new=MagicMock()):
        mock_runner.run.side_effect = subprocess.CalledProcessError(1, ["par2", "create"])
        with pytest.raises(subprocess.CalledProcessError):
            db.generate_par2_files(backup_file, cfg, args)


# --- print_markdown ----------------------------------------------------------

def test_print_markdown_from_string_pretty_false(capsys):
    """from_string=True + pretty=False prints raw content to stdout."""
    content = "# Title\nText"
    db.print_markdown(content, from_string=True, pretty=False)
    out = capsys.readouterr().out
    assert "# Title" in out
    assert "Text" in out


def test_print_markdown_pretty_falls_back_when_rich_missing(tmp_path, monkeypatch, capsys):
    """pretty=True but importing rich fails -> prints fallback notice + content."""
    md_path = tmp_path / "note.md"
    md_path.write_text("# Hello\nWorld", encoding="utf-8")

    # Force ImportError for rich.* imports
    real_import = __import__

    def blocked_import(name, *a, **k):
        if name.startswith("rich"):
            raise ImportError("no rich")
        return real_import(name, *a, **k)

    monkeypatch.setattr("builtins.__import__", blocked_import)
    db.print_markdown(str(md_path), from_string=False, pretty=True)

    out = capsys.readouterr().out
    assert "rich" in out.lower()  # fallback message mentions rich
    assert "Hello" in out and "World" in out
