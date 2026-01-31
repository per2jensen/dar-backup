# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
from unittest.mock import MagicMock, patch
import os
import sys
import datetime
from dar_backup.manager import restore_at, main, _restore_with_dar, _pitr_chain_report, relocate_archive_paths
from dar_backup.config_settings import ConfigSettings
from dar_backup.command_runner import CommandResult

# --- Fixtures ---

@pytest.fixture
def mock_config(tmp_path):
    """Creates a basic ConfigSettings object with temporary directories."""
    config = MagicMock(spec=ConfigSettings)
    config.backup_dir = str(tmp_path / "backups")
    config.backup_d_dir = str(tmp_path / "backup.d")
    # manager_db_dir is optional in the real class, so we simulate getting it
    # We'll just patch get_db_dir to return a known path
    return config

@pytest.fixture
def mock_runner():
    """Mocks the CommandRunner."""
    runner = MagicMock()
    runner.run.return_value = CommandResult(0, "stdout", "stderr", note=None)
    return runner

@pytest.fixture
def mock_logger():
    """Mocks the logger."""
    return MagicMock()

# --- Tests for restore_at logic ---

def test_restore_at_basic_success(mock_config, mock_logger):
    """Test a standard restore operation with a valid date and target."""

    # Setup
    backup_def = "test_backup"
    paths = ["home/user/file.txt"]
    when = "2023-10-27 14:30"
    target = "/tmp/restore_target"
    parsed_date = datetime.datetime(2023, 10, 27, 14, 30, 0)

    def _exists(path):
        if path == "/tmp/db_dir/test_backup.db":
            return True
        if path == target:
            return True
        return False

    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("os.path.exists", side_effect=_exists), \
         patch("dateparser.parse", return_value=parsed_date), \
         patch("dar_backup.manager.logger", mock_logger), \
         patch("dar_backup.manager._restore_with_dar", return_value=0) as mock_restore:

        ret = restore_at(backup_def, paths, when, target, mock_config)

        assert ret == 0
        mock_restore.assert_called_once_with(backup_def, paths, parsed_date, target, mock_config)


def test_restore_at_invalid_date(mock_config, mock_runner, mock_logger):
    """Test that an unparseable date returns an error."""
    
    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("os.path.exists", return_value=True), \
         patch("dar_backup.manager.logger", mock_logger):
        
        ret = restore_at("def", ["file"], "invalid-date-string", "/tmp", mock_config)
        
        assert ret == 1
        mock_logger.error.assert_called_with("Could not parse date: 'invalid-date-string'")
        mock_runner.run.assert_not_called()


def test_restore_at_no_db(mock_config, mock_logger):
    """Test failure when the database file does not exist."""
    
    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("os.path.exists", return_value=False), \
         patch("dar_backup.manager.logger", mock_logger):
        
        ret = restore_at("def", ["file"], "now", "/tmp", mock_config)
        
        assert ret == 1
        mock_logger.error.assert_called()


def test_restore_at_target_creation_fail(mock_config, mock_logger):
    """Test failure when target directory cannot be created."""
    
    # We mock dateparser to return a dummy date so it doesn't call os.path.exists internally
    mock_date = datetime.datetime(2023, 1, 1)
    
    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("dateparser.parse", return_value=mock_date), \
         patch("os.path.exists", side_effect=[True, False]), \
         patch("os.makedirs", side_effect=PermissionError("Boom")), \
         patch("dar_backup.manager.logger", mock_logger):
        
        ret = restore_at("def", ["file"], "now", "/root/protected", mock_config)
        
        assert ret == 1
        mock_logger.error.assert_called()


def test_restore_at_returns_restore_with_dar_code(mock_config, mock_logger):
    """Test that restore_at returns the direct dar restore result."""
    def _exists(path):
        if path == "/tmp/db_dir/def.db":
            return True
        if path == "/tmp":
            return True
        return False

    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("os.path.exists", side_effect=_exists), \
         patch("dateparser.parse", return_value=datetime.datetime(2023, 1, 1)), \
         patch("dar_backup.manager.logger", mock_logger), \
         patch("dar_backup.manager._restore_with_dar", return_value=5) as mock_restore:

        ret = restore_at("def", ["file"], "now", "/tmp", mock_config)

        assert ret == 5
        mock_restore.assert_called_once()


def test_restore_at_existing_target_paths_abort(tmp_path, mock_config, mock_runner, mock_logger):
    """Test restore aborts when target already contains requested paths."""
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    (db_dir / "def.db").write_text("")

    target = tmp_path / "restore"
    (target / "tmp").mkdir(parents=True)
    (target / "tmp" / "file.txt").write_text("existing")

    mock_runner.run.return_value = CommandResult(1, "stdout", "stderr", note=None)

    with patch("dar_backup.manager.get_db_dir", return_value=str(db_dir)), \
         patch("dateparser.parse", return_value=datetime.datetime(2023, 1, 1)), \
         patch("dar_backup.manager.runner", mock_runner), \
         patch("dar_backup.manager.logger", mock_logger):

        ret = restore_at("def", ["tmp/file.txt"], "now", str(target), mock_config)

        assert ret == 1
        mock_logger.error.assert_any_call(
            "Restore target '%s' already contains path(s) to restore: %s%s. For safety, PITR restores abort "
            "without overwriting existing files. Use a clean/empty target.",
            str(target),
            "tmp/file.txt",
            "",
        )
        mock_runner.run.assert_not_called()


def test_restore_at_empty_target_allows_restore(tmp_path, mock_config, mock_logger):
    """Test restore proceeds when target does not contain requested paths."""
    db_dir = tmp_path / "db"
    db_dir.mkdir()
    (db_dir / "def.db").write_text("")

    target = tmp_path / "restore"
    target.mkdir()

    with patch("dar_backup.manager.get_db_dir", return_value=str(db_dir)), \
         patch("dateparser.parse", return_value=datetime.datetime(2023, 1, 1)), \
         patch("dar_backup.manager.logger", mock_logger), \
         patch("dar_backup.manager._restore_with_dar", return_value=0) as mock_restore:

        ret = restore_at("def", ["tmp/file.txt"], "now", str(target), mock_config)

        assert ret == 0
        mock_restore.assert_called_once()


def test_restore_at_multiple_paths_and_no_target(mock_config, mock_runner, mock_logger):
    """Test that restore requires a target directory."""

    paths = ["file1.txt", "dir/file2.txt"]
    
    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("os.path.exists", return_value=True), \
         patch("dar_backup.manager.runner", mock_runner), \
         patch("dar_backup.manager.logger", mock_logger):
        
        ret = restore_at("def", paths, "yesterday", None, mock_config)
        
        assert ret == 1
        mock_logger.error.assert_called_with("Restore target directory is required (--target).")
        mock_runner.run.assert_not_called()

# --- Integration-style tests for CLI argument parsing ---

def test_cli_restore_path_requires_backup_def(capsys):
    """Test that --restore-path fails without --backup-def."""
    
    # Simulate sys.argv
    with patch.object(sys, 'argv', ["manager", "--restore-path", "file.txt"]), \
         patch("dar_backup.manager.setup_logging"), \
         patch("dar_backup.manager.ConfigSettings"), \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("os.path.dirname", return_value="/tmp"): # Mock config load
        
        # We expect a SystemExit(1)
        with pytest.raises(SystemExit) as excinfo:
            main()
        
        assert excinfo.value.code == 1
        
        # Check that error was logged (we can't easily check logger calls inside main without more complex patching,
        # but we can check if it didn't crash before that check).
        # Actually, in the code: logger.error("--restore-path requires...") -> sys.exit(1)


def test_cli_restore_path_requires_target(capsys):
    """Test that --restore-path fails without --target."""
    with patch.object(sys, 'argv', [
            "manager",
            "--backup-def", "mydef",
            "--restore-path", "file.txt",
            "--when", "now",
            "--config-file", "dummy.conf",
         ]), \
         patch("dar_backup.manager.setup_logging"), \
         patch("dar_backup.manager.ConfigSettings"), \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("os.path.dirname", return_value="/tmp"):

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 1


def test_cli_pitr_report_does_not_require_target(capsys):
    with patch.object(sys, 'argv', [
            "manager",
            "--backup-def", "mydef",
            "--restore-path", "file.txt",
            "--when", "now",
            "--pitr-report",
            "--config-file", "dummy.conf",
         ]), \
         patch("dar_backup.manager.setup_logging"), \
         patch("dar_backup.manager.ConfigSettings"), \
         patch("dar_backup.manager._pitr_chain_report", return_value=0), \
         patch("os.path.exists", return_value=True), \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("os.path.dirname", return_value="/tmp"):

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0


def test_restore_at_uses_direct_dar_restore(mock_config, mock_logger):
    """Test that PITR restore uses direct dar restore path."""
    def _exists(path):
        if path == "/tmp/db_dir/def.db":
            return True
        if path == "/tmp/restore":
            return True
        return False

    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("os.path.exists", side_effect=_exists), \
         patch("dateparser.parse", return_value=datetime.datetime(2023, 1, 1)), \
         patch("dar_backup.manager.logger", mock_logger), \
         patch("dar_backup.manager._restore_with_dar", return_value=0) as mock_restore:

        ret = restore_at("def", ["tmp/file.txt"], "now", "/tmp/restore", mock_config, verbose=True)

        assert ret == 0
        mock_restore.assert_called_once()


def test_restore_at_default_when_uses_now(mock_config, mock_logger):
    """Test that restore_at uses current time when --when is not provided."""
    fixed_now = datetime.datetime(2026, 1, 31, 12, 0, 0)

    def _exists(path):
        if path == "/tmp/db_dir/def.db":
            return True
        if path == "/tmp/restore":
            return True
        return False

    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("os.path.exists", side_effect=_exists), \
         patch("dar_backup.manager.datetime") as mock_datetime, \
         patch("dar_backup.manager.logger", mock_logger), \
         patch("dar_backup.manager._restore_with_dar", return_value=0) as mock_restore:

        mock_datetime.now.return_value = fixed_now

        ret = restore_at("def", ["tmp/file.txt"], None, "/tmp/restore", mock_config)

        assert ret == 0
        mock_restore.assert_called_once_with("def", ["tmp/file.txt"], fixed_now, "/tmp/restore", mock_config)


def test_restore_with_dar_logs_candidates_and_summary(mock_config, mock_runner, mock_logger):
    """Test that restore logs candidate selection and summary."""
    list_output = (
        "archive #   |    path      |    basename\n"
        "------------+--------------+---------------\n"
        "1 /tmp/backups example_FULL_2026-01-29\n"
        "2 /tmp/backups example_DIFF_2026-01-29\n"
    )
    file_output = (
        "1 Thu Jan 29 15:00:34 2026  saved\n"
        "2 Thu Jan 29 15:00:41 2026  saved\n"
    )
    mock_runner.run.side_effect = [
        CommandResult(0, list_output, "", note=None),
        CommandResult(0, file_output, "", note=None),
        CommandResult(0, "ok", "", note=None),
    ]
    mock_config.command_timeout_secs = 30

    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("dar_backup.manager.runner", mock_runner), \
         patch("dar_backup.manager.logger", mock_logger), \
         patch("dar_backup.manager.send_discord_message") as mock_discord, \
         patch("os.path.exists", return_value=True), \
         patch("dar_backup.manager._guess_darrc_path", return_value=None):

        when_dt = datetime.datetime(2026, 1, 29, 16, 0, 0)
        ret = _restore_with_dar("def", ["tmp/file.txt"], when_dt, "/tmp/restore", mock_config)

        assert ret == 0
        debug_calls = mock_logger.debug.call_args_list
        assert any(
            call.args[0] == "PITR archive map: %s"
            and "#1=/tmp/backups/example_FULL_2026-01-29" in call.args[1]
            and "#2=/tmp/backups/example_DIFF_2026-01-29" in call.args[1]
            for call in debug_calls
        )
        assert any(
            call.args[0] == "PITR candidates for '%s': %s"
            and call.args[1] == "tmp/file.txt"
            and "#2@2026-01-29 15:00:41" in call.args[2]
            for call in debug_calls
        )
        info_calls = mock_logger.info.call_args_list
        assert any(
            call.args[0] == "PITR selected archive %s for '%s'."
            and "example_DIFF_2026-01-29" in call.args[1]
            and call.args[2] == "tmp/file.txt"
            for call in info_calls
        )
        assert any(
            call.args[0] == "PITR restore summary: %d succeeded, %d failed."
            and call.args[1] == 1
            and call.args[2] == 0
            for call in info_calls
        )
        mock_discord.assert_not_called()


def test_restore_with_dar_directory_logs_chain_details(mock_config, mock_runner, mock_logger):
    list_output = (
        "archive #   |    path      |    basename\n"
        "------------+--------------+---------------\n"
        "1 /tmp/backups example_FULL_2026-01-29\n"
        "2 /tmp/backups example_DIFF_2026-01-29\n"
    )
    file_output = "1 Thu Jan 29 15:00:34 2026  saved\n"
    mock_runner.run.side_effect = [
        CommandResult(0, list_output, "", note=None),
        CommandResult(0, file_output, "", note=None),
        CommandResult(0, "ok", "", note=None),
        CommandResult(0, "ok", "", note=None),
    ]
    mock_config.command_timeout_secs = 30

    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("dar_backup.manager.runner", mock_runner), \
         patch("dar_backup.manager.logger", mock_logger), \
         patch("dar_backup.manager._is_directory_path", return_value=True), \
         patch("dar_backup.manager._guess_darrc_path", return_value=None), \
         patch("os.path.exists", return_value=True):

        when_dt = datetime.datetime(2026, 1, 29, 16, 0, 0)
        ret = _restore_with_dar("def", ["tmp/dir"], when_dt, "/tmp/restore", mock_config)

        assert ret == 0
        info_calls = mock_logger.info.call_args_list
        assert any(
            call.args[0] == "PITR restore directory '%s' using archive chain: %s"
            and call.args[1] == "tmp/dir"
            and "example_FULL_2026-01-29" in call.args[2]
            and "example_DIFF_2026-01-29" in call.args[2]
            for call in info_calls
        )


def test_pitr_report_directory_missing_slice_fails(mock_config, mock_runner, mock_logger):
    list_output = (
        "archive #   |    path      |    basename\n"
        "------------+--------------+---------------\n"
        "1 /tmp/backups example_FULL_2026-01-29\n"
        "2 /tmp/backups example_DIFF_2026-01-29\n"
    )
    mock_runner.run.return_value = CommandResult(0, list_output, "", note=None)

    def _exists(path):
        if path.endswith("example_DIFF_2026-01-29.1.dar"):
            return False
        return True

    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("dar_backup.manager.runner", mock_runner), \
         patch("dar_backup.manager.logger", mock_logger), \
         patch("dar_backup.manager._is_directory_path", return_value=True), \
         patch("os.path.exists", side_effect=_exists):

        ret = _pitr_chain_report("def", ["tmp/dir"], "2026-01-29 16:00:00", mock_config)

        assert ret == 1
        mock_logger.error.assert_any_call(
            "PITR chain report missing archive: %s",
            "/tmp/backups/example_DIFF_2026-01-29.1.dar",
        )


def test_restore_with_dar_directory_missing_chain_fails(mock_config, mock_runner, mock_logger):
    list_output = (
        "archive #   |    path      |    basename\n"
        "------------+--------------+---------------\n"
        "1 /tmp/backups example_FULL_2026-01-29\n"
        "2 /tmp/backups example_DIFF_2026-01-29\n"
    )
    file_output = "1 Thu Jan 29 15:00:34 2026  saved\n"
    mock_runner.run.side_effect = [
        CommandResult(0, list_output, "", note=None),
        CommandResult(0, file_output, "", note=None),
    ]
    mock_config.command_timeout_secs = 30

    def _exists(path):
        if path.endswith("example_DIFF_2026-01-29.1.dar"):
            return False
        return True

    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("dar_backup.manager.runner", mock_runner), \
         patch("dar_backup.manager.logger", mock_logger), \
         patch("dar_backup.manager._is_directory_path", return_value=True), \
         patch("dar_backup.manager._guess_darrc_path", return_value=None), \
         patch("dar_backup.manager.send_discord_message"), \
         patch("os.path.exists", side_effect=_exists):

        when_dt = datetime.datetime(2026, 1, 29, 16, 0, 0)
        ret = _restore_with_dar("def", ["tmp/dir"], when_dt, "/tmp/restore", mock_config)

        assert ret == 1
        mock_logger.error.assert_any_call(
            "PITR restore missing archive in chain for '%s': %s",
            "tmp/dir",
            "/tmp/backups/example_DIFF_2026-01-29.1.dar",
        )


def test_restore_at_rejects_protected_target(mock_config, mock_runner, mock_logger):
    """Test that protected system directories are rejected as restore targets."""
    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("os.path.exists", return_value=True), \
         patch("dar_backup.manager.runner", mock_runner), \
         patch("dar_backup.manager.logger", mock_logger):

        ret = restore_at("def", ["tmp/file.txt"], "now", "/etc", mock_config)

        assert ret == 1
        mock_logger.error.assert_called_with(
            "Restore target '/etc' is a protected system directory. Choose a safer location."
        )
        mock_runner.run.assert_not_called()

def test_cli_restore_execution(mock_runner):
    """Test that valid CLI args trigger the restore_at function."""
    
    with patch.object(sys, 'argv', [
            "manager", 
            "--backup-def", "mydef", 
            "--restore-path", "file.txt", 
            "--when", "now",
            "--target", "/tmp/out",
            "--config-file", "dummy.conf"
         ]), \
         patch("dar_backup.manager.ConfigSettings") as MockSettings, \
         patch("dar_backup.manager.setup_logging"), \
         patch("dar_backup.manager.get_logger"), \
         patch("dar_backup.manager.runner", mock_runner), \
         patch("dar_backup.manager.restore_at", return_value=0) as mock_restore, \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("os.path.dirname", return_value="/tmp"), \
         patch("os.path.exists", return_value=True): # For backup def path check
        
        # Mock ConfigSettings instance
        settings_instance = MockSettings.return_value
        settings_instance.logfile_location = "/tmp/log"
        settings_instance.backup_d_dir = "/tmp/backup.d"
        
        # Run main
        try:
            main()
        except SystemExit as e:
            assert e.code == 0
        
        # Check if restore_at was called with correct args
        mock_restore.assert_called_once()
        call_args = mock_restore.call_args
        assert call_args[0][0] == "mydef" # backup_def
        assert call_args[0][1] == ["file.txt"] # paths
        assert call_args[0][2] == "now" # when
        assert call_args[0][3] == "/tmp/out" # target


def test_cli_relocate_requires_backup_def():
    with patch.object(sys, 'argv', [
            "manager",
            "--relocate-archive-path", "/old", "/new",
            "--config-file", "dummy.conf",
         ]), \
         patch("dar_backup.manager.setup_logging"), \
         patch("dar_backup.manager.ConfigSettings"), \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("os.path.dirname", return_value="/tmp"):

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 1


def test_cli_relocate_dry_run_executes():
    with patch.object(sys, 'argv', [
            "manager",
            "--backup-def", "mydef",
            "--relocate-archive-path", "/old", "/new",
            "--relocate-archive-path-dry-run",
            "--config-file", "dummy.conf",
         ]), \
         patch("dar_backup.manager.ConfigSettings") as MockSettings, \
         patch("dar_backup.manager.setup_logging"), \
         patch("dar_backup.manager.get_logger"), \
         patch("dar_backup.manager.relocate_archive_paths", return_value=0) as mock_relocate, \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("os.path.dirname", return_value="/tmp"), \
         patch("os.path.exists", return_value=True):

        settings_instance = MockSettings.return_value
        settings_instance.logfile_location = "/tmp/log"
        settings_instance.backup_d_dir = "/tmp/backup.d"

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 0
        mock_relocate.assert_called_once()


def test_cli_relocate_dry_run_requires_relocate():
    with patch.object(sys, 'argv', [
            "manager",
            "--relocate-archive-path-dry-run",
            "--config-file", "dummy.conf",
         ]), \
         patch("dar_backup.manager.setup_logging"), \
         patch("dar_backup.manager.ConfigSettings"), \
         patch("os.path.isfile", return_value=True), \
         patch("os.access", return_value=True), \
         patch("os.path.dirname", return_value="/tmp"):

        with pytest.raises(SystemExit) as excinfo:
            main()

        assert excinfo.value.code == 1

def test_relocate_archive_paths_dry_run(mock_config, mock_runner, mock_logger):
    list_output = (
        "archive #   |    path      |    basename\n"
        "------------+--------------+---------------\n"
        "1 /old/path example_FULL_2026-01-29\n"
        "2 /keep/path example_DIFF_2026-01-29\n"
        "3 /old/path example_INCR_2026-01-30\n"
    )
    mock_runner.run.return_value = CommandResult(0, list_output, "", note=None)

    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("os.path.exists", return_value=True), \
         patch("dar_backup.manager.runner", mock_runner), \
         patch("dar_backup.manager.logger", mock_logger):

        ret = relocate_archive_paths("def", "/old/path", "/new/path", mock_config, dry_run=True)

        assert ret == 0
        mock_runner.run.assert_called_once()


def test_relocate_archive_paths_apply(mock_config, mock_runner, mock_logger):
    list_output = (
        "archive #   |    path      |    basename\n"
        "------------+--------------+---------------\n"
        "1 /old/path example_FULL_2026-01-29\n"
        "2 /keep/path example_DIFF_2026-01-29\n"
        "3 /old/path example_INCR_2026-01-30\n"
    )
    mock_runner.run.side_effect = [
        CommandResult(0, list_output, "", note=None),
        CommandResult(0, "", "", note=None),
        CommandResult(0, "", "", note=None),
    ]

    with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
         patch("os.path.exists", return_value=True), \
         patch("dar_backup.manager.runner", mock_runner), \
         patch("dar_backup.manager.logger", mock_logger):

        ret = relocate_archive_paths("def", "/old/path", "/new/path", mock_config, dry_run=False)

        assert ret == 0
        calls = mock_runner.run.call_args_list
        assert calls[0].args[0][:3] == ["dar_manager", "--base", "/tmp/db_dir/def.db"]
        assert calls[1].args[0] == ["dar_manager", "--base", "/tmp/db_dir/def.db", "-p", "1", "/new/path"]
        assert calls[2].args[0] == ["dar_manager", "--base", "/tmp/db_dir/def.db", "-p", "3", "/new/path"]
