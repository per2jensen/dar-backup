from types import SimpleNamespace
from textwrap import dedent
from pathlib import Path

from dar_backup.config_settings import ConfigSettings
from dar_backup.dar_backup import preflight_check
from dar_backup.mounts import get_mount_identity
import pytest

pytestmark = pytest.mark.unit









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


def test_preflight_passes_when_backup_mount_identity_matches(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Accept a configured mount identity that matches the kernel mount table.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
        capsys: Pytest output capture fixture.

    Returns:
        None.
    """
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    test_restore_dir = tmp_path / "restore"
    backup_dir.mkdir()
    backup_d_dir.mkdir()
    test_restore_dir.mkdir()
    identity = get_mount_identity(str(backup_dir))

    config_file = tmp_path / "dar.conf"
    write_config(config_file, backup_dir, backup_d_dir, test_restore_dir)
    config_settings = ConfigSettings(str(config_file))
    config_settings.backup_dir_mount_source = identity.source
    config_settings.backup_dir_mount_fstype = identity.filesystem_type

    errors: list[str] = []
    ok = preflight_check(make_args(), config_settings, errors_out=errors)

    assert ok is True
    assert errors == []
    assert "Preflight checks passed." in capsys.readouterr().out


def test_preflight_fails_when_backup_mount_source_is_wrong(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reject an unexpected mount source even when the directory is writable.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
        capsys: Pytest output capture fixture.

    Returns:
        None.
    """
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    test_restore_dir = tmp_path / "restore"
    backup_dir.mkdir()
    backup_d_dir.mkdir()
    test_restore_dir.mkdir()

    config_file = tmp_path / "dar.conf"
    write_config(config_file, backup_dir, backup_d_dir, test_restore_dir)
    config_settings = ConfigSettings(str(config_file))
    config_settings.backup_dir_mount_source = "source-that-cannot-match"

    errors: list[str] = []
    ok = preflight_check(make_args(), config_settings, errors_out=errors)

    assert ok is False
    assert any("mount identity mismatch" in error for error in errors)
    out = capsys.readouterr().out
    assert "BACKUP_DIR mount identity mismatch" in out
    assert "source-that-cannot-match" in out


def test_preflight_passes_when_manager_mount_identity_matches(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Accept a separate manager directory on its expected mounted filesystem.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
        capsys: Pytest output capture fixture.

    Returns:
        None.
    """
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    test_restore_dir = tmp_path / "restore"
    manager_dir = tmp_path / "manager"
    for directory in (backup_dir, backup_d_dir, test_restore_dir, manager_dir):
        directory.mkdir()
    identity = get_mount_identity(str(manager_dir))

    config_file = tmp_path / "dar.conf"
    write_config(config_file, backup_dir, backup_d_dir, test_restore_dir)
    config_settings = ConfigSettings(str(config_file))
    config_settings.manager_db_dir = str(manager_dir)
    config_settings.manager_db_dir_mount_source = identity.source
    config_settings.manager_db_dir_mount_fstype = identity.filesystem_type

    errors: list[str] = []
    ok = preflight_check(make_args(), config_settings, errors_out=errors)

    assert ok is True
    assert errors == []
    assert "Preflight checks passed." in capsys.readouterr().out


def test_preflight_fails_when_manager_mount_source_is_wrong(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reject a writable manager directory on an unexpected mount source.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
        capsys: Pytest output capture fixture.

    Returns:
        None.
    """
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    test_restore_dir = tmp_path / "restore"
    manager_dir = tmp_path / "manager"
    for directory in (backup_dir, backup_d_dir, test_restore_dir, manager_dir):
        directory.mkdir()
    sentinel = manager_dir / ".dar-backup-preflight"
    sentinel.write_text("must remain untouched", encoding="utf-8")

    config_file = tmp_path / "dar.conf"
    write_config(config_file, backup_dir, backup_d_dir, test_restore_dir)
    config_settings = ConfigSettings(str(config_file))
    config_settings.manager_db_dir = str(manager_dir)
    config_settings.manager_db_dir_mount_source = "source-that-cannot-match"

    errors: list[str] = []
    ok = preflight_check(make_args(), config_settings, errors_out=errors)

    assert ok is False
    assert any("MANAGER_DB_DIR mount identity mismatch" in error for error in errors)
    assert "source-that-cannot-match" in capsys.readouterr().out
    assert sentinel.read_text(encoding="utf-8") == "must remain untouched"
