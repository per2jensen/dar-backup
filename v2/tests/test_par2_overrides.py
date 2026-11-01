from configparser import ConfigParser
from pathlib import Path

from dar_backup.config_settings import ConfigSettings
from dar_backup.dar_backup import _validate_par2_mount
from dar_backup.mounts import get_mount_identity
import pytest

pytestmark = pytest.mark.unit









def test_par2_overrides_are_applied(tmp_path):
    config_path = tmp_path / "dar-backup.conf"

    config = ConfigParser()
    config["MISC"] = {
        "LOGFILE_LOCATION": str(tmp_path / "dar-backup.log"),
        "MAX_SIZE_VERIFICATION_MB": "20",
        "MIN_SIZE_VERIFICATION_MB": "0",
        "NO_FILES_VERIFICATION": "5",
        "COMMAND_TIMEOUT_SECS": "30",
    }
    config["DIRECTORIES"] = {
        "BACKUP_DIR": str(tmp_path / "backups"),
        "BACKUP.D_DIR": str(tmp_path / "backup.d"),
        "TEST_RESTORE_DIR": str(tmp_path / "restore"),
    }
    config["AGE"] = {
        "DIFF_AGE": "30",
        "INCR_AGE": "15",
    }
    config["PAR2"] = {
        "ERROR_CORRECTION_PERCENT": "5",
        "ENABLED": "True",
        "PAR2_DIR": "/global/par2",
        "PAR2_DIR_MOUNT_SOURCE": "global-server:/par2",
        "PAR2_DIR_MOUNT_FSTYPE": "nfs4",
    }
    config["media-files"] = {
        "PAR2_DIR": "/override/par2",
        "PAR2_DIR_MOUNT_SOURCE": "media-server:/par2",
        "PAR2_DIR_MOUNT_FSTYPE": "nfs",
        "PAR2_RATIO_FULL": "10",
    }
    config["documents"] = {"PAR2_RATIO_FULL": "12"}
    config["local-files"] = {"PAR2_DIR": "/local/par2"}

    with open(config_path, "w") as f:
        config.write(f)

    settings = ConfigSettings(str(config_path))
    par2_config = settings.get_par2_config("media-files")

    assert par2_config["par2_dir"] == "/override/par2"
    assert par2_config["par2_dir_mount_source"] == "media-server:/par2"
    assert par2_config["par2_dir_mount_fstype"] == "nfs"
    assert par2_config["par2_ratio_full"] == 10
    assert par2_config["par2_enabled"] is True

    default_par2_config = settings.get_par2_config("nonexistent")
    assert default_par2_config["par2_dir"] == "/global/par2"
    assert default_par2_config["par2_dir_mount_source"] == "global-server:/par2"
    assert default_par2_config["par2_dir_mount_fstype"] == "nfs4"

    inherited_par2_config = settings.get_par2_config("documents")
    assert inherited_par2_config["par2_dir"] == "/global/par2"
    assert inherited_par2_config["par2_dir_mount_source"] == "global-server:/par2"
    assert inherited_par2_config["par2_dir_mount_fstype"] == "nfs4"

    reset_par2_config = settings.get_par2_config("local-files")
    assert reset_par2_config["par2_dir"] == "/local/par2"
    assert reset_par2_config["par2_dir_mount_source"] is None
    assert reset_par2_config["par2_dir_mount_fstype"] is None


def _write_par2_mount_config(
    config_path: Path,
    base_dir: Path,
    par2_dir: Path,
    expected_source: str,
) -> Path:
    """Write a minimal configuration with protected global PAR2 storage.

    Args:
        config_path: Configuration file to create.
        base_dir: Base directory for unrelated required paths.
        par2_dir: PAR2 destination to protect.
        expected_source: Expected kernel mount source.

    Returns:
        The created configuration path.
    """
    config = ConfigParser()
    config["MISC"] = {
        "LOGFILE_LOCATION": str(base_dir / "dar-backup.log"),
        "MAX_SIZE_VERIFICATION_MB": "20",
        "MIN_SIZE_VERIFICATION_MB": "0",
        "NO_FILES_VERIFICATION": "5",
        "COMMAND_TIMEOUT_SECS": "30",
    }
    config["DIRECTORIES"] = {
        "BACKUP_DIR": str(base_dir / "backups"),
        "BACKUP.D_DIR": str(base_dir / "backup.d"),
        "TEST_RESTORE_DIR": str(base_dir / "restore"),
    }
    config["AGE"] = {"DIFF_AGE": "30", "INCR_AGE": "15"}
    config["PAR2"] = {
        "ERROR_CORRECTION_PERCENT": "5",
        "ENABLED": "true",
        "PAR2_DIR": str(par2_dir),
        "PAR2_DIR_MOUNT_SOURCE": expected_source,
    }
    with open(config_path, "w", encoding="utf-8") as config_file:
        config.write(config_file)
    return config_path


def test_validate_par2_mount_matching_source_returns_none(tmp_path: Path) -> None:
    """Accept an enabled PAR2 destination on its configured mount source.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    par2_dir = tmp_path / "par2"
    par2_dir.mkdir()
    identity = get_mount_identity(str(par2_dir))
    config_path = _write_par2_mount_config(
        tmp_path / "matching.conf",
        tmp_path,
        par2_dir,
        identity.source,
    )

    error = _validate_par2_mount(ConfigSettings(str(config_path)), "media-files")

    assert error is None


def test_validate_par2_mount_wrong_source_reports_error(tmp_path: Path) -> None:
    """Reject a per-definition PAR2 directory on an unexpected mount source.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    par2_dir = tmp_path / "par2"
    par2_dir.mkdir()
    identity = get_mount_identity(str(par2_dir))
    config_path = _write_par2_mount_config(
        tmp_path / "wrong.conf",
        tmp_path,
        par2_dir,
        identity.source,
    )
    config = ConfigParser()
    config.read(config_path)
    config["media-files"] = {
        "PAR2_DIR": str(par2_dir),
        "PAR2_DIR_MOUNT_SOURCE": "source-that-cannot-match",
    }
    with open(config_path, "w", encoding="utf-8") as config_file:
        config.write(config_file)

    error = _validate_par2_mount(ConfigSettings(str(config_path)), "media-files")

    assert error is not None
    assert "PAR2_DIR mount identity mismatch" in error
