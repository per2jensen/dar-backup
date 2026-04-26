import logging
import os
import sys
from unittest.mock import MagicMock, patch

import dar_backup.dar_backup as dar_backup
import pytest

pytestmark = pytest.mark.unit









def _reset_logger(name):
    logger = logging.getLogger(name)
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
    return logger


def _write_min_config(path, *, logfile_location):
    backup_dir = path.parent / "backups"
    backup_d_dir = path.parent / "backup.d"
    restore_dir = path.parent / "restore"

    backup_dir.mkdir(exist_ok=True)
    backup_d_dir.mkdir(exist_ok=True)
    restore_dir.mkdir(exist_ok=True)

    config_text = (
        "[MISC]\n"
        f"LOGFILE_LOCATION = {logfile_location}\n"
        "MAX_SIZE_VERIFICATION_MB = 20\n"
        "MIN_SIZE_VERIFICATION_MB = 0\n"
        "NO_FILES_VERIFICATION = 5\n"
        "COMMAND_TIMEOUT_SECS = 30\n"
        "\n"
        "[DIRECTORIES]\n"
        f"BACKUP_DIR = {backup_dir}\n"
        f"BACKUP.D_DIR = {backup_d_dir}\n"
        f"TEST_RESTORE_DIR = {restore_dir}\n"
        "\n"
        "[AGE]\n"
        "DIFF_AGE = 30\n"
        "INCR_AGE = 15\n"
        "\n"
        "[PAR2]\n"
        "ERROR_CORRECTION_PERCENT = 5\n"
        "ENABLED = false\n"
    )
    path.write_text(config_text)


def test_dar_backup_unreadable_config_exits_127(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "dar-backup.conf"
    _write_min_config(config_path, logfile_location=str(tmp_path / "dar-backup.log"))

    os.chmod(config_path, 0)
    try:
        monkeypatch.setattr(sys, "argv", ["dar-backup", "--config-file", str(config_path)])
        monkeypatch.setattr(dar_backup.argcomplete, "autocomplete", lambda *a, **k: None)
        monkeypatch.setattr(dar_backup, "stderr", sys.stderr)

        with pytest.raises(SystemExit) as exc:
            dar_backup.main()

        assert exc.value.code == 127
        err = capsys.readouterr().err
        assert "must exist and be readable" in err.lower()
    finally:
        os.chmod(config_path, 0o644)


def test_dar_backup_warns_on_bad_logfile_location(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "dar-backup.conf"
    _write_min_config(config_path, logfile_location=str(tmp_path / "dar-backup.txt"))

    monkeypatch.setattr(sys, "argv", ["dar-backup", "--config-file", str(config_path)])
    monkeypatch.setattr(dar_backup.argcomplete, "autocomplete", lambda *a, **k: None)
    monkeypatch.setattr(dar_backup, "validate_required_directories", lambda *_a, **_k: None)
    monkeypatch.setattr(dar_backup, "preflight_check", lambda *_a, **_k: True)
    monkeypatch.setattr(dar_backup, "setup_logging", lambda *_a, **_k: (_ for _ in ()).throw(SystemExit(0)))
    monkeypatch.setattr(dar_backup, "stderr", sys.stderr)

    with pytest.raises(SystemExit):
        dar_backup.main()

    err = capsys.readouterr().err
    assert "does not end at 'dar-backup.log'" in err


def test_dar_backup_logs_preflight_failures_to_main_log(monkeypatch, tmp_path):
    config_path = tmp_path / "dar-backup.conf"
    log_path = tmp_path / "dar-backup.log"
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    probe_file = backup_dir / ".dar-backup-preflight"

    _write_min_config(config_path, logfile_location=str(log_path))
    (backup_d_dir / "example.dcf").write_text("-R /tmp\n")

    _reset_logger("main_logger")
    _reset_logger("command_output_logger")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dar-backup",
            "--full-backup",
            "--backup-definition",
            "example.dcf",
            "--config-file",
            str(config_path),
        ],
    )
    monkeypatch.setattr(dar_backup.argcomplete, "autocomplete", lambda *a, **k: None)
    monkeypatch.setattr(dar_backup, "stderr", sys.stderr)
    monkeypatch.setattr(dar_backup, "send_discord_message", lambda *a, **k: None)
    monkeypatch.setattr(dar_backup.shutil, "which", lambda cmd: f"/bin/{cmd}")
    monkeypatch.setattr(dar_backup.subprocess, "run", lambda *a, **k: None)

    real_open = open

    def fake_open(path, *args, **kwargs):
        if os.fspath(path) == os.fspath(probe_file):
            raise OSError("stale NFS handle")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)

    with pytest.raises(SystemExit) as exc:
        dar_backup.main()

    assert exc.value.code == 127

    log_text = log_path.read_text()
    assert "Preflight checks failed." in log_text
    assert "Preflight check failed: Cannot write to BACKUP_DIR" in log_text
    assert "stale NFS handle" in log_text


def test_locale_ok_returns_true_when_lang_is_en_us_utf8(monkeypatch):
    """_locale_ok() returns True when LANG is exactly en_US.UTF-8."""
    monkeypatch.setenv("LANG", dar_backup.REQUIRED_LANG)
    assert dar_backup._locale_ok() is True


def test_locale_ok_returns_false_when_lang_is_not_en_us_utf8(monkeypatch):
    """_locale_ok() returns False when LANG is any other value."""
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    assert dar_backup._locale_ok() is False



def _make_generic_backup_mocks(monkeypatch, lang: str) -> list:
    """
    Set up mocks needed to call generic_backup() in isolation.

    Args:
        monkeypatch: pytest monkeypatch fixture.
        lang: Value to set for the LANG environment variable.

    Returns:
        List of arguments passed to parse_dar_stats (empty means it was not called).
    """
    monkeypatch.setenv("LANG", lang)
    monkeypatch.setattr(dar_backup, "logger", MagicMock())

    fake_process = MagicMock()
    fake_process.returncode = 0
    fake_process.stdout_tail = ""
    fake_process.stderr_tail = ""

    fake_runner = MagicMock()
    fake_runner.run.return_value = fake_process
    monkeypatch.setattr(dar_backup, "runner", fake_runner)

    parse_called: list = []
    monkeypatch.setattr(dar_backup, "parse_dar_stats", lambda txt: parse_called.append(txt) or {})

    return parse_called


def test_generic_backup_calls_parse_dar_stats_when_locale_correct(monkeypatch):
    """generic_backup() always calls parse_dar_stats — LC_ALL=C is pinned in CommandRunner."""
    parse_called = _make_generic_backup_mocks(monkeypatch, dar_backup.REQUIRED_LANG)

    config = MagicMock()
    config.command_timeout_secs = 10

    dar_backup.generic_backup("FULL", ["dar", "-c", "test"], "/tmp/test", "example", "", config, MagicMock())

    assert len(parse_called) == 1, "parse_dar_stats should be called exactly once"


def test_generic_backup_calls_parse_dar_stats_regardless_of_caller_locale(monkeypatch):
    """
    generic_backup() calls parse_dar_stats even when the caller's LANG is not
    en_US.UTF-8.  CommandRunner pins LC_ALL=C for all subprocesses, so dar
    always produces consistent, parseable output.
    """
    parse_called = _make_generic_backup_mocks(monkeypatch, "de_DE.UTF-8")

    config = MagicMock()
    config.command_timeout_secs = 10

    dar_backup.generic_backup("FULL", ["dar", "-c", "test"], "/tmp/test", "example", "", config, MagicMock())

    assert len(parse_called) == 1, "parse_dar_stats must always be called"


def test_dar_backup_preflight_check_continues_with_fallback_logging(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "dar-backup.conf"
    log_path = tmp_path / "missing-logs" / "dar-backup.log"

    _reset_logger("main_logger")
    _reset_logger("command_output_logger")
    _write_min_config(config_path, logfile_location=str(log_path))

    monkeypatch.setattr(
        sys,
        "argv",
        ["dar-backup", "--preflight-check", "--config-file", str(config_path)],
    )
    monkeypatch.setattr(dar_backup.argcomplete, "autocomplete", lambda *a, **k: None)
    monkeypatch.setattr(dar_backup, "stderr", sys.stderr)
    monkeypatch.setattr(dar_backup, "send_discord_message", lambda *a, **k: None)
    monkeypatch.setattr(dar_backup.shutil, "which", lambda cmd: f"/bin/{cmd}")
    monkeypatch.setattr(dar_backup.subprocess, "run", lambda *a, **k: None)

    with pytest.raises(SystemExit) as exc:
        dar_backup.main()

    assert exc.value.code == 0

    captured = capsys.readouterr()
    assert "Preflight warnings:" in captured.out
    assert "LOGFILE_LOCATION directory does not exist" in captured.out
    assert "continuing with fallback" in captured.err.lower()
