import os
import sys
import pytest

import dar_backup.dar_backup as dar_backup


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
