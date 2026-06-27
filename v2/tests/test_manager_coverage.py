import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from dar_backup.command_runner import CommandResult
import dar_backup.manager as manager
import pytest

pytestmark = pytest.mark.component









def make_config(tmp_path: Path, logfile_name: str = "dar-backup.log") -> Path:
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    restore_dir = tmp_path / "restore"
    backup_dir.mkdir()
    backup_d_dir.mkdir()
    restore_dir.mkdir()

    config_path = tmp_path / "dar-backup.conf"
    config_path.write_text(
        "\n".join(
            [
                "[MISC]",
                f"LOGFILE_LOCATION = {tmp_path / logfile_name}",
                "MAX_SIZE_VERIFICATION_MB = 20",
                "MIN_SIZE_VERIFICATION_MB = 0",
                "NO_FILES_VERIFICATION = 5",
                "COMMAND_TIMEOUT_SECS = 86400",
                "",
                "[DIRECTORIES]",
                f"BACKUP_DIR = {backup_dir}",
                f"BACKUP.D_DIR = {backup_d_dir}",
                f"TEST_RESTORE_DIR = {restore_dir}",
                "",
                "[AGE]",
                "DIFF_AGE = 30",
                "INCR_AGE = 15",
                "",
                "[PAR2]",
                "ERROR_CORRECTION_PERCENT = 5",
                "ENABLED = True",
            ]
        )
    )
    return config_path


def run_main(monkeypatch, tmp_path, args, config_path=None, config_settings=None):
    config_path = config_path or make_config(tmp_path)
    argv = ["manager"] + args
    if "--config-file" not in argv:
        argv += ["--config-file", str(config_path)]
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(manager.argcomplete, "autocomplete", lambda *_a, **_k: None)
    monkeypatch.setattr(manager, "get_binary_info", lambda **_k: {"path": "dar_manager", "version": "0"})
    monkeypatch.setattr(manager, "print_aligned_settings", lambda *_a, **_k: None)
    monkeypatch.setattr(manager, "init_logging", lambda *_a, **_k: (MagicMock(), "/dev/null"))
    monkeypatch.setattr(manager, "get_logger", lambda *_a, **_k: MagicMock())
    monkeypatch.setattr(manager, "CommandRunner", MagicMock(return_value=MagicMock()))
    monkeypatch.setattr(manager, "get_invocation_command_line", lambda: "cmd")
    if config_settings is not None:
        monkeypatch.setattr(manager, "ConfigSettings", lambda _path: config_settings)

    exit_calls = []
    monkeypatch.setattr(manager.sys, "exit", lambda code=0: exit_calls.append(code))
    manager.main()
    return exit_calls


def test_open_command_log_returns_none_without_handler(monkeypatch):
    class DummyLogger:
        handlers = [object()]

    monkeypatch.setattr(manager, "get_logger", lambda **_k: DummyLogger())
    log_file, lock = manager._open_command_log(["cmd", "--arg"])

    assert log_file is None
    assert lock is None


def test_open_command_log_writes_header(monkeypatch, tmp_path):
    log_path = tmp_path / "command.log"

    class DummyHandler:
        def __init__(self, path):
            self.baseFilename = str(path)

    class DummyLogger:
        handlers = [DummyHandler(log_path)]

    monkeypatch.setattr(manager, "get_logger", lambda **_k: DummyLogger())
    log_file, lock = manager._open_command_log(["cmd", "--arg"])
    assert lock is not None
    log_file.close()

    content = log_path.read_bytes()
    assert b"COMMAND:" in content


def test_list_catalogs_runner_ignores_short_lines_and_handles_no_date(tmp_path, capsys):
    backup_def = "example"
    db_path = tmp_path / f"{backup_def}.db"
    db_path.touch()

    config = SimpleNamespace(backup_dir=tmp_path, manager_db_dir=None, command_timeout_secs=None)
    lines = [
        "archive #",
        "bad\tline",
        "1\t/path\tNODEF",
        "2\t/path\tadef_FULL_2025-01-01",
    ]

    def fake_stream(cmd, callback, *, timeout=None):
        for line in lines:
            callback(line)
        return CommandResult(0, "", "")

    mock_runner = MagicMock()
    mock_runner.stream_command.side_effect = fake_stream

    with patch("dar_backup.manager.runner", new=mock_runner), \
         patch("dar_backup.manager.logger", new=MagicMock()):
        result = manager.list_catalogs(backup_def, config)

    # "bad\tline" has only 2 tab-separated parts → excluded from archive_lines
    assert "bad\tline" not in result.stdout
    # "NODEF" has 3 parts → included
    assert "NODEF" in result.stdout
    assert capsys.readouterr().out



def test_list_catalogs_subprocess_error_with_stderr_text(tmp_path):
    backup_def = "example"
    db_path = tmp_path / f"{backup_def}.db"
    db_path.touch()

    config = SimpleNamespace(backup_dir=tmp_path, command_capture_max_bytes=None, manager_db_dir=None, command_timeout_secs=None)

    mock_runner = MagicMock()
    mock_runner.stream_command.return_value = CommandResult(1, "", "bad\n")

    with patch("dar_backup.manager.runner", new=mock_runner), \
         patch("dar_backup.manager.logger", new=MagicMock()) as mock_logger:
        result = manager.list_catalogs(backup_def, config, suppress_output=True)

    assert result.returncode == 1
    mock_logger.error.assert_any_call('%s', f'Error listing catalogs for: "{db_path}"')
    assert "bad" in result.stderr


def test_list_archive_contents_db_missing(tmp_path):
    config = SimpleNamespace(backup_dir=tmp_path, manager_db_dir=None, command_timeout_secs=None)
    archive = "example_FULL_2025-01-01"

    with patch("dar_backup.manager.logger", new=MagicMock()) as mock_logger:
        result = manager.list_archive_contents(archive, config)

    assert result == 1
    mock_logger.error.assert_called_once()


def test_list_archive_contents_runner_prints_saved_lines(tmp_path, capsys):
    archive = "example_FULL_2025-01-01"
    db_path = tmp_path / "example.db"
    db_path.touch()
    config = SimpleNamespace(backup_dir=tmp_path, manager_db_dir=None, command_timeout_secs=None)

    def fake_stream(cmd, callback, *, timeout=None):
        callback("[ Saved ] file1.txt")
        callback("other line")
        return CommandResult(0, "", "")

    mock_runner = MagicMock()
    mock_runner.stream_command.side_effect = fake_stream

    with patch("dar_backup.manager.cat_no_for_name", return_value=1), \
         patch("dar_backup.manager.logger", new=MagicMock()), \
         patch("dar_backup.manager.runner", new=mock_runner):
        result = manager.list_archive_contents(archive, config)

    assert result == 0
    assert "[ Saved ] file1.txt" in capsys.readouterr().out


def test_list_archive_contents_runner_prints_empty_info(tmp_path, capsys):
    archive = "example_FULL_2025-01-01"
    db_path = tmp_path / "example.db"
    db_path.touch()
    config = SimpleNamespace(backup_dir=tmp_path, manager_db_dir=None, command_timeout_secs=None)

    def fake_stream(cmd, callback, *, timeout=None):
        callback("no files")
        return CommandResult(0, "", "")

    mock_runner = MagicMock()
    mock_runner.stream_command.side_effect = fake_stream

    with patch("dar_backup.manager.cat_no_for_name", return_value=1), \
         patch("dar_backup.manager.logger", new=MagicMock()), \
         patch("dar_backup.manager.runner", new=mock_runner):
        result = manager.list_archive_contents(archive, config)

    assert result == 0
    assert "is empty" in capsys.readouterr().out



def test_list_archive_contents_subprocess_error_with_stderr_text(tmp_path):
    archive = "example_FULL_2025-01-01"
    db_path = tmp_path / "example.db"
    db_path.touch()
    config = SimpleNamespace(backup_dir=tmp_path, command_capture_max_bytes=None, manager_db_dir=None, command_timeout_secs=None)

    mock_runner = MagicMock()
    mock_runner.stream_command.return_value = CommandResult(1, "", "bad\n")

    with patch("dar_backup.manager.cat_no_for_name", return_value=1), \
         patch("dar_backup.manager.runner", new=mock_runner), \
         patch("dar_backup.manager.logger", new=MagicMock()) as mock_logger:
        result = manager.list_archive_contents(archive, config)

    assert result == 1
    mock_logger.error.assert_any_call('%s', f'Error listing contents of archive: "{db_path}"')



def test_add_specific_archive_old_archive_confirmed(tmp_path):
    archive = "example_FULL_2025-01-01"
    (tmp_path / f"{archive}.1.dar").touch()
    (tmp_path / "example").touch()
    config = SimpleNamespace(backup_dir=tmp_path, backup_d_dir=tmp_path, manager_db_dir=None, command_timeout_secs=None)

    process = SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch("dar_backup.manager.subprocess.run") as mock_run, \
         patch("dar_backup.manager.confirm_add_old_archive", return_value=True), \
         patch("dar_backup.manager.logger", new=MagicMock()), \
         patch("dar_backup.manager.runner") as mock_runner:
        mock_run.return_value = SimpleNamespace(stdout="1\t/path\texample_FULL_2025-02-01")
        mock_runner.run.return_value = process
        result = manager.add_specific_archive(archive, config)

    assert result == 0


def test_add_specific_archive_newer_than_catalog_skips_prompt(tmp_path):
    """Archive dated AFTER the latest catalog entry must not trigger the old-archive prompt."""
    archive = "example_FULL_2026-03-01"
    (tmp_path / f"{archive}.1.dar").touch()
    (tmp_path / "example").touch()
    config = SimpleNamespace(backup_dir=tmp_path, backup_d_dir=tmp_path, manager_db_dir=None, command_timeout_secs=None)

    process = SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch("dar_backup.manager.subprocess.run") as mock_run, \
         patch("dar_backup.manager.confirm_add_old_archive", side_effect=AssertionError("should not prompt")), \
         patch("dar_backup.manager.logger", new=MagicMock()), \
         patch("dar_backup.manager.runner") as mock_runner:
        mock_run.return_value = SimpleNamespace(stdout="1\t/path\texample_FULL_2025-02-01")
        mock_runner.run.return_value = process
        result = manager.add_specific_archive(archive, config)

    assert result == 0


def test_add_specific_archive_malformed_name_returns_error(tmp_path):
    """Archive name that doesn't match the naming convention must be rejected early."""
    archive = "example_FULL"  # no date — not a valid archive name
    (tmp_path / f"{archive}.1.dar").touch()
    config = SimpleNamespace(backup_dir=tmp_path, backup_d_dir=tmp_path, manager_db_dir=None, command_timeout_secs=None)

    with patch("dar_backup.manager.confirm_add_old_archive", side_effect=AssertionError("should not prompt")), \
         patch("dar_backup.manager.logger", new=MagicMock()) as mock_logger:
        result = manager.add_specific_archive(archive, config)

    assert result == 1
    error_calls = [str(c) for c in mock_logger.error.call_args_list]
    assert any("naming convention" in c for c in error_calls), (
        f"Expected an error about naming convention; got: {error_calls}"
    )


def test_add_directory_logs_error_on_failure(tmp_path):
    args = SimpleNamespace(add_dir=str(tmp_path))
    (tmp_path / "example_FULL_2025-01-01.1.dar").touch()
    config = SimpleNamespace()

    with patch("dar_backup.manager.logger", new=MagicMock()) as mock_logger, \
         patch("dar_backup.manager.add_specific_archive", return_value=1):
        manager.add_directory(args, config)

    mock_logger.error.assert_called_once()


def test_confirm_add_old_archive_returns_false_on_none(monkeypatch):
    monkeypatch.setattr(manager, "logger", MagicMock())
    monkeypatch.setattr(manager, "inputimeout", lambda **_k: None)
    assert manager.confirm_add_old_archive("archive", "2025-01-01") is False


def test_manager_main_python_version_too_low(monkeypatch):
    monkeypatch.setattr(manager.sys, "version_info", (3, 8))
    exit_calls = []
    monkeypatch.setattr(manager.sys, "exit", lambda code=0: exit_calls.append(code))
    manager.main()
    assert exit_calls == [1]


def test_manager_main_config_missing(monkeypatch, tmp_path):
    missing = tmp_path / "missing.conf"
    monkeypatch.setattr(sys, "argv", ["manager", "--config-file", str(missing)])
    monkeypatch.setattr(manager.argcomplete, "autocomplete", lambda *_a, **_k: None)
    monkeypatch.setattr(manager.os.path, "isfile", lambda _p: False)
    monkeypatch.setattr(manager.os, "access", lambda *_a, **_k: False)

    with pytest.raises(SystemExit) as exc:
        manager.main()
    assert exc.value.code == 127


def test_manager_main_logfile_dir_missing(monkeypatch, tmp_path):
    config_path = make_config(tmp_path)
    dummy_settings = SimpleNamespace(
        logfile_location="dar-backup.log",
        logfile_max_bytes=1,
        logfile_backup_count=1,
        backup_dir=str(tmp_path / "backups"),
        backup_d_dir=str(tmp_path / "backup.d"),
        command_capture_max_bytes=None,
        manager_db_dir=None,
        command_timeout_secs=None,
    )

    exit_calls = run_main(
        monkeypatch,
        tmp_path,
        args=[],
        config_path=config_path,
        config_settings=dummy_settings,
    )

    assert exit_calls == [1]


@pytest.mark.parametrize(
    "args",
    [
        ["--add-dir", " "],
        ["--remove-specific-archive", " "],
        ["--add-dir", "foo", "--add-specific-archive", "arc"],
        ["-d", " "],
        ["-d", "missing"],
        ["--list-archive-contents", " "],
        ["--find-file", "somefile"],
        ["--alternate-archive-dir", "missing-dir"],
    ],
)
def test_manager_main_sanity_returns(monkeypatch, tmp_path, args):
    config_path = make_config(tmp_path)
    if "--alternate-archive-dir" in args:
        args = args[:-1] + [str(tmp_path / "missing-dir")]
    exit_calls = run_main(monkeypatch, tmp_path, args, config_path=config_path)
    assert exit_calls == [1]


def test_manager_main_create_db_returns(monkeypatch, tmp_path):
    config_path = make_config(tmp_path)
    backup_def = Path(config_path.parent) / "backup.d" / "example"
    backup_def.touch()

    with patch("dar_backup.manager.create_db", return_value=0) as mock_create:
        exit_calls = run_main(
            monkeypatch,
            tmp_path,
            ["--create-db", "--backup-def", "example"],
            config_path=config_path,
        )

    mock_create.assert_called_once()
    assert exit_calls == [0]


def test_manager_main_add_specific_archive_returns(monkeypatch, tmp_path):
    config_path = make_config(tmp_path)

    with patch("dar_backup.manager.add_specific_archive", return_value=0) as mock_add:
        exit_calls = run_main(
            monkeypatch,
            tmp_path,
            ["--add-specific-archive", "example_FULL_2025-01-01"],
            config_path=config_path,
        )

    mock_add.assert_called_once()
    assert exit_calls == [0]


def test_manager_main_add_dir_returns(monkeypatch, tmp_path):
    config_path = make_config(tmp_path)
    (tmp_path / "archives").mkdir()

    with patch("dar_backup.manager.add_directory", return_value=0) as mock_add:
        exit_calls = run_main(
            monkeypatch,
            tmp_path,
            ["--add-dir", str(tmp_path / "archives")],
            config_path=config_path,
        )

    mock_add.assert_called_once()
    assert exit_calls == [0]


def test_manager_main_list_catalogs_returns(monkeypatch, tmp_path):
    config_path = make_config(tmp_path)
    backup_def = Path(config_path.parent) / "backup.d" / "example"
    backup_def.touch()

    fake_result = SimpleNamespace(returncode=1)

    with patch("dar_backup.manager.list_catalogs", return_value=fake_result) as mock_list:
        exit_calls = run_main(
            monkeypatch,
            tmp_path,
            ["--list-catalogs"],
            config_path=config_path,
        )

    assert mock_list.called
    assert exit_calls == [1]


def test_manager_main_list_archive_contents_returns(monkeypatch, tmp_path):
    config_path = make_config(tmp_path)

    with patch("dar_backup.manager.list_archive_contents", return_value=0) as mock_list:
        exit_calls = run_main(
            monkeypatch,
            tmp_path,
            ["--list-archive-contents", "example_FULL_2025-01-01"],
            config_path=config_path,
        )

    mock_list.assert_called_once()
    assert exit_calls == [0]


def test_manager_main_find_file_returns(monkeypatch, tmp_path):
    config_path = make_config(tmp_path)
    backup_def = Path(config_path.parent) / "backup.d" / "example"
    backup_def.touch()

    with patch("dar_backup.manager.find_file", return_value=0) as mock_find:
        exit_calls = run_main(
            monkeypatch,
            tmp_path,
            ["--find-file", "path/file", "-d", "example"],
            config_path=config_path,
        )

    mock_find.assert_called_once()
    assert exit_calls == [0]
