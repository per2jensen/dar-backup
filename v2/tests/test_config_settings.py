import os
from configparser import ConfigParser


from dar_backup.config_settings import ConfigSettings
from dar_backup.exceptions import ConfigSettingsError
import pytest

pytestmark = pytest.mark.unit









def write_config(
    path,
    base_dir,
    *,
    misc_overrides=None,
    dir_overrides=None,
    age_overrides=None,
    par2_overrides=None,
    extra_sections=None,
):
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
    config["AGE"] = {
        "DIFF_AGE": "30",
        "INCR_AGE": "15",
    }
    config["PAR2"] = {
        "ERROR_CORRECTION_PERCENT": "5",
        "ENABLED": "true",
    }

    if misc_overrides:
        config["MISC"].update(misc_overrides)
    if dir_overrides:
        config["DIRECTORIES"].update(dir_overrides)
    if age_overrides:
        config["AGE"].update(age_overrides)
    if par2_overrides:
        config["PAR2"].update(par2_overrides)
    if extra_sections:
        for section, values in extra_sections.items():
            if section in config:
                config[section].update(values)
            else:
                config[section] = values

    with open(path, "w") as handle:
        config.write(handle)
    return path


def test_config_settings_missing_file_raises(tmp_path):
    missing = tmp_path / "missing.conf"
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(missing))
    assert "not found" in str(exc_info.value).lower()


def test_config_settings_invalid_par2_enabled_value_raises(tmp_path):
    config_path = write_config(
        tmp_path / "bad.conf",
        tmp_path,
        par2_overrides={"ENABLED": "maybe"},
    )
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(config_path))
    assert "invalid boolean value" in str(exc_info.value).lower()


def test_config_settings_optional_bool_invalid_raises(tmp_path):
    config_path = write_config(
        tmp_path / "bad.conf",
        tmp_path,
        par2_overrides={"PAR2_RUN_VERIFY": "maybe"},
    )
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(config_path))
    message = str(exc_info.value).lower()
    assert "unexpected error" in message
    assert "par2_run_verify" in message


def test_config_settings_optional_regex_invalid_raises(tmp_path):
    config_path = write_config(
        tmp_path / "bad.conf",
        tmp_path,
        misc_overrides={"RESTORETEST_EXCLUDE_REGEX": "["},
    )
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(config_path))
    assert "invalid regex" in str(exc_info.value).lower()


def test_config_settings_optional_csv_list_parses(tmp_path):
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        misc_overrides={
            "RESTORETEST_EXCLUDE_PREFIXES": "tmp, , cache,",
            "RESTORETEST_EXCLUDE_SUFFIXES": ".bak,  , .tmp",
        },
    )
    settings = ConfigSettings(str(config_path))
    assert settings.restoretest_exclude_prefixes == ["tmp", "cache"]
    assert settings.restoretest_exclude_suffixes == [".bak", ".tmp"]


def test_config_settings_optional_regex_compiles_case_insensitive(tmp_path):
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        misc_overrides={"RESTORETEST_EXCLUDE_REGEX": "Temp"},
    )
    settings = ConfigSettings(str(config_path))
    assert settings.restoretest_exclude_regex is not None
    assert settings.restoretest_exclude_regex.search("tempfile") is not None


def test_config_settings_expands_paths_and_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_BASE", str(tmp_path / "envbase"))
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        dir_overrides={"BACKUP_DIR": "$TEST_BASE/backups"},
        misc_overrides={"LOGFILE_LOCATION": "$TEST_BASE/logs/dar-backup.log"},
        par2_overrides={"PAR2_RATIO_FULL": "12"},
        extra_sections={
            "DIRECTORIES": {"MANAGER_DB_DIR": "~/manager-db"},
        },
    )
    settings = ConfigSettings(str(config_path))
    assert settings.backup_dir == os.path.expandvars("$TEST_BASE/backups")
    assert settings.logfile_location == os.path.expandvars("$TEST_BASE/logs/dar-backup.log")
    assert settings.manager_db_dir == "~/manager-db"
    assert settings.par2_ratio_full == 12
    assert settings.logfile_max_bytes == 26214400
    assert settings.command_capture_max_bytes == 102400


def test_get_par2_config_overrides_run_verify_and_enabled(tmp_path):
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        par2_overrides={"PAR2_RUN_VERIFY": "yes"},
        extra_sections={
            "media": {
                "PAR2_RUN_VERIFY": "no",
                "PAR2_ENABLED": "false",
                "PAR2_RATIO_DIFF": "7",
            }
        },
    )
    settings = ConfigSettings(str(config_path))
    par2_config = settings.get_par2_config("media")
    assert par2_config["par2_run_verify"] is False
    assert par2_config["par2_enabled"] is False
    assert par2_config["par2_ratio_diff"] == 7


def test_get_par2_config_invalid_run_verify_value_raises(tmp_path):
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        extra_sections={"media": {"PAR2_RUN_VERIFY": "bad"}},
    )
    settings = ConfigSettings(str(config_path))
    with pytest.raises(ConfigSettingsError) as exc_info:
        settings.get_par2_config("media")
    assert "par2_run_verify" in str(exc_info.value).lower()


def test_config_settings_repr_omits_none_fields(tmp_path):
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        extra_sections={"DIRECTORIES": {"MANAGER_DB_DIR": "/tmp/db"}},
    )
    settings = ConfigSettings(str(config_path))
    output = repr(settings)
    assert "config_file=" in output
    assert "manager_db_dir" not in output
    assert "par2_dir" not in output


def test_config_settings_env_timeout_overrides_config(tmp_path, monkeypatch):
    config_path = write_config(tmp_path / "cfg.conf", tmp_path, misc_overrides={"COMMAND_TIMEOUT_SECS": "30"})
    monkeypatch.setenv("DAR_BACKUP_COMMAND_TIMEOUT_SECS", "120")
    settings = ConfigSettings(str(config_path))
    assert settings.command_timeout_secs == 120


@pytest.mark.parametrize(
    "env_value,expected",
    [
        ("-1", -1),
        ("300", 300),
    ],
)
def test_config_settings_env_timeout_valid_values(tmp_path, monkeypatch, env_value, expected):
    config_path = write_config(tmp_path / "cfg.conf", tmp_path)
    monkeypatch.setenv("DAR_BACKUP_COMMAND_TIMEOUT_SECS", env_value)
    settings = ConfigSettings(str(config_path))
    assert settings.command_timeout_secs == expected


@pytest.mark.parametrize(
    "env_value",
    [
        "0",
        "banana",
        "",
        "  ",
    ],
)
def test_config_settings_env_timeout_invalid_values_raise(tmp_path, monkeypatch, env_value):
    config_path = write_config(tmp_path / "cfg.conf", tmp_path)
    monkeypatch.setenv("DAR_BACKUP_COMMAND_TIMEOUT_SECS", env_value)
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(config_path))
    assert "dar_backup_command_timeout_secs" in str(exc_info.value).lower()


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("MISC", "COMMAND_CAPTURE_MAX_BYTES", "not-an-int"),
        ("MISC", "LOGFILE_MAX_BYTES", "not-an-int"),
        ("MISC", "LOGFILE_BACKUP_COUNT", "not-an-int"),
        ("PAR2", "PAR2_RATIO_FULL", "not-an-int"),
    ],
)
def test_config_settings_invalid_optional_ints_raise(tmp_path, section, key, value):
    misc_overrides = None
    par2_overrides = None
    if section == "MISC":
        misc_overrides = {key: value}
    if section == "PAR2":
        par2_overrides = {key: value}

    config_path = write_config(
        tmp_path / "bad.conf",
        tmp_path,
        misc_overrides=misc_overrides,
        par2_overrides=par2_overrides,
    )

    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(config_path))
    message = str(exc_info.value).lower()
    if section.lower() == "par2":
        assert "invalid value in config" in message
        assert "not-an-int" in message
    else:
        assert key.lower() in message
