import os
from types import SimpleNamespace
from textwrap import dedent

from dar_backup.config_settings import ConfigSettings
from dar_backup.dar_backup import preflight_check


def write_config(path, backup_dir, backup_d_dir, test_restore_dir, par2_enabled="false"):
    cfg = dedent(
        f"""
        [MISC]
        LOGFILE_LOCATION = {backup_dir}/dar-backup.log
        MAX_SIZE_VERIFICATION_MB = 20
        MIN_SIZE_VERIFICATION_MB = 0
        NO_FILES_VERIFICATION = 5
        COMMAND_TIMEOUT_SECS = 86400

        [DIRECTORIES]
        BACKUP_DIR = {backup_dir}
        BACKUP.D_DIR = {backup_d_dir}
        TEST_RESTORE_DIR = {test_restore_dir}

        [AGE]
        DIFF_AGE = 30
        INCR_AGE = 15

        [PAR2]
        ERROR_CORRECTION_PERCENT = 5
        ENABLED = {par2_enabled}
        """
    ).strip()
    path.write_text(cfg)
    return path


def make_args(backup_definition=None):
    return SimpleNamespace(
        backup_definition=backup_definition,
        darrc=None,
        alternate_reference_archive=None,
    )


def test_preflight_passes_when_env_is_valid(tmp_path, capsys):
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    test_restore_dir = tmp_path / "restore"
    backup_dir.mkdir()
    backup_d_dir.mkdir()
    test_restore_dir.mkdir()

    backup_def = backup_d_dir / "foo.dcf"
    backup_def.write_text("-R /tmp\n")

    config_file = tmp_path / "dar.conf"
    write_config(config_file, backup_dir, backup_d_dir, test_restore_dir, par2_enabled="false")
    config_settings = ConfigSettings(str(config_file))

    ok = preflight_check(make_args("foo.dcf"), config_settings)
    assert ok is True

    out = capsys.readouterr().out
    assert "Preflight checks passed." in out


def test_preflight_fails_when_backup_definition_missing(tmp_path, capsys):
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    test_restore_dir = tmp_path / "restore"
    backup_dir.mkdir()
    backup_d_dir.mkdir()
    test_restore_dir.mkdir()

    config_file = tmp_path / "dar.conf"
    write_config(config_file, backup_dir, backup_d_dir, test_restore_dir, par2_enabled="false")
    config_settings = ConfigSettings(str(config_file))

    ok = preflight_check(make_args("missing.dcf"), config_settings)
    assert ok is False

    out = capsys.readouterr().out
    assert "Backup definition not found" in out


def test_preflight_fails_when_directories_missing(tmp_path, capsys):
    backup_dir = tmp_path / "backups"  # not created
    backup_d_dir = tmp_path / "backup.d"  # not created
    test_restore_dir = tmp_path / "restore"  # not created

    config_file = tmp_path / "dar.conf"
    write_config(config_file, backup_dir, backup_d_dir, test_restore_dir, par2_enabled="false")
    config_settings = ConfigSettings(str(config_file))

    ok = preflight_check(make_args(), config_settings)
    assert ok is False

    out = capsys.readouterr().out
    assert "does not exist" in out
