import os
from configparser import ConfigParser

from dar_backup.config_settings import ConfigSettings


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
    }
    config["media-files"] = {
        "PAR2_DIR": "/override/par2",
        "PAR2_RATIO_FULL": "10",
    }

    with open(config_path, "w") as f:
        config.write(f)

    settings = ConfigSettings(str(config_path))
    par2_config = settings.get_par2_config("media-files")

    assert par2_config["par2_dir"] == "/override/par2"
    assert par2_config["par2_ratio_full"] == 10
    assert par2_config["par2_enabled"] is True

    default_par2_config = settings.get_par2_config("nonexistent")
    assert default_par2_config["par2_dir"] == "/global/par2"
