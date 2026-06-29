import logging
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
    assert "invalid boolean value" in message
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
    assert settings.manager_db_dir == os.path.expanduser("~/manager-db")  # path expansion now applies to declared fields
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
    assert "manager_db_dir='/tmp/db'" in output  # declared field with non-None value appears in repr
    assert "par2_dir" not in output               # par2_dir is None so still absent


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
    assert "not-an-int" in message
    assert key.lower() in message


# ---------------------------------------------------------------------------
# Range validation — DIFF_AGE, INCR_AGE, ERROR_CORRECTION_PERCENT
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("diff_age", [0, -1])
def test_config_settings_diff_age_out_of_range_raises(tmp_path, diff_age):
    """
    DIFF_AGE = 0 would delete every DIFF backup immediately;
    negative values silently disable cleanup. Both must be rejected.
    """
    config_path = write_config(
        tmp_path / "bad.conf",
        tmp_path,
        age_overrides={"DIFF_AGE": str(diff_age)},
    )
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(config_path))
    assert "diff_age" in str(exc_info.value).lower()


@pytest.mark.parametrize("incr_age", [0, -1])
def test_config_settings_incr_age_out_of_range_raises(tmp_path, incr_age):
    """
    INCR_AGE = 0 would delete every INCR backup immediately;
    negative values silently disable cleanup. Both must be rejected.
    """
    config_path = write_config(
        tmp_path / "bad.conf",
        tmp_path,
        age_overrides={"INCR_AGE": str(incr_age)},
    )
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(config_path))
    assert "incr_age" in str(exc_info.value).lower()


@pytest.mark.parametrize("percent", [-1, 0, 91, 100])
def test_config_settings_error_correction_percent_out_of_range_raises(tmp_path, percent):
    """
    ERROR_CORRECTION_PERCENT = 0 produces PAR2 files with no redundancy;
    values above 90 are capped at our policy limit. All must be caught at
    config load time.
    """
    config_path = write_config(
        tmp_path / "bad.conf",
        tmp_path,
        par2_overrides={"ERROR_CORRECTION_PERCENT": str(percent)},
    )
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(config_path))
    assert "error_correction_percent" in str(exc_info.value).lower()


@pytest.mark.parametrize("diff_age,incr_age", [(1, 1), (30, 15), (365, 180)])
def test_config_settings_valid_age_values_load_cleanly(tmp_path, diff_age, incr_age):
    """Boundary and typical values for DIFF_AGE and INCR_AGE must be accepted."""
    config_path = write_config(
        tmp_path / "good.conf",
        tmp_path,
        age_overrides={"DIFF_AGE": str(diff_age), "INCR_AGE": str(incr_age)},
    )
    cfg = ConfigSettings(str(config_path))
    assert cfg.diff_age == diff_age
    assert cfg.incr_age == incr_age


@pytest.mark.parametrize("percent", [1, 5, 50, 90])
def test_config_settings_valid_error_correction_percent_loads_cleanly(tmp_path, percent):
    """Boundary and typical values for ERROR_CORRECTION_PERCENT must be accepted."""
    config_path = write_config(
        tmp_path / "good.conf",
        tmp_path,
        par2_overrides={"ERROR_CORRECTION_PERCENT": str(percent)},
    )
    cfg = ConfigSettings(str(config_path))
    assert cfg.error_correction_percent == percent


# ---------------------------------------------------------------------------
# NO_FILES_VERIFICATION range validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("count", [0, -1])
def test_config_settings_no_files_verification_out_of_range_raises(tmp_path, count):
    """
    NO_FILES_VERIFICATION = 0 or negative means the restore test selects no files
    and passes vacuously — silently wrong, so it must be rejected at config load time.
    """
    config_path = write_config(
        tmp_path / "bad.conf",
        tmp_path,
        misc_overrides={"NO_FILES_VERIFICATION": str(count)},
    )
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(config_path))
    assert "no_files_verification" in str(exc_info.value).lower()


@pytest.mark.parametrize("count", [1, 5, 100])
def test_config_settings_no_files_verification_valid_values_load_cleanly(tmp_path, count):
    """Boundary and typical values for NO_FILES_VERIFICATION must be accepted."""
    config_path = write_config(
        tmp_path / "good.conf",
        tmp_path,
        misc_overrides={"NO_FILES_VERIFICATION": str(count)},
    )
    cfg = ConfigSettings(str(config_path))
    assert cfg.no_files_verification == count


# ---------------------------------------------------------------------------
# Age warning thresholds
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("diff_age", [366, 500])
def test_config_settings_diff_age_high_loads_cleanly(tmp_path, diff_age):
    """DIFF_AGE above 365 is valid; the config must load with the supplied value."""
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        age_overrides={"DIFF_AGE": str(diff_age)},
    )
    cfg = ConfigSettings(str(config_path))
    assert cfg.diff_age == diff_age


@pytest.mark.parametrize("incr_age", [32, 90])
def test_config_settings_incr_age_high_loads_cleanly(tmp_path, incr_age):
    """INCR_AGE above 31 is valid; the config must load with the supplied value."""
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        age_overrides={"INCR_AGE": str(incr_age)},
    )
    cfg = ConfigSettings(str(config_path))
    assert cfg.incr_age == incr_age


# ---------------------------------------------------------------------------
# RESTORE_OWNERSHIP config setting
# ---------------------------------------------------------------------------

def test_config_settings_restore_ownership_yes(tmp_path):
    """RESTORE_OWNERSHIP = yes is parsed as True."""
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        misc_overrides={"RESTORE_OWNERSHIP": "yes"},
    )
    cfg = ConfigSettings(str(config_path))
    assert cfg.restore_ownership is True


def test_config_settings_restore_ownership_no(tmp_path):
    """RESTORE_OWNERSHIP = no is parsed as False."""
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        misc_overrides={"RESTORE_OWNERSHIP": "no"},
    )
    cfg = ConfigSettings(str(config_path))
    assert cfg.restore_ownership is False


def test_config_settings_restore_ownership_missing_defaults_false(tmp_path):
    """When RESTORE_OWNERSHIP is absent from the config, it defaults to False.

    This preserves backward-compatible behaviour for existing users who do not
    have the key in their config file.
    """
    config_path = write_config(tmp_path / "cfg.conf", tmp_path)
    cfg = ConfigSettings(str(config_path))
    assert cfg.restore_ownership is False


def test_config_settings_restore_ownership_invalid_value_raises(tmp_path):
    """An invalid value for RESTORE_OWNERSHIP raises ConfigSettingsError."""
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        misc_overrides={"RESTORE_OWNERSHIP": "maybe"},
    )
    with pytest.raises(ConfigSettingsError):
        ConfigSettings(str(config_path))


# ---------------------------------------------------------------------------
# _get_config_value — tested via the public interface
# ---------------------------------------------------------------------------

def test_get_config_value_returns_default_when_key_absent(tmp_path):
    """Absent optional key returns the supplied default without error."""
    config_path = write_config(tmp_path / "cfg.conf", tmp_path)
    cfg = ConfigSettings(str(config_path))
    assert cfg.command_capture_max_bytes == 102400  # default from OPTIONAL_CONFIG_FIELDS


def test_get_config_value_converts_present_key(tmp_path):
    """A present optional key is read, stripped, and converted correctly."""
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        misc_overrides={"COMMAND_CAPTURE_MAX_BYTES": "  204800  "},
    )
    cfg = ConfigSettings(str(config_path))
    assert cfg.command_capture_max_bytes == 204800


def test_get_config_value_raises_with_key_and_bad_value_in_message(tmp_path):
    """Conversion failure names both the key and the offending value."""
    config_path = write_config(
        tmp_path / "cfg.conf",
        tmp_path,
        misc_overrides={"LOGFILE_MAX_BYTES": "not-a-number"},
    )
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(config_path))
    message = str(exc_info.value).lower()
    assert "logfile_max_bytes" in message
    assert "not-a-number" in message


# ---------------------------------------------------------------------------
# Error-handling quality — clear messages, no swallowed exceptions
# ---------------------------------------------------------------------------

def test_config_settings_malformed_file_raises_clear_message(tmp_path):
    """A config file with no section headers produces a ConfigSettingsError naming the file."""
    bad_config = tmp_path / "bad.conf"
    bad_config.write_text("key_without_section = value\n")
    with pytest.raises(ConfigSettingsError) as exc_info:
        ConfigSettings(str(bad_config))
    assert str(bad_config) in str(exc_info.value)


def test_config_settings_unreadable_file_raises_clear_message(tmp_path):
    """A config file that exists but cannot be read raises ConfigSettingsError with a clear message."""
    import os as _os
    if _os.getuid() == 0:
        pytest.skip("running as root: permission bits are not enforced")
    config_path = write_config(tmp_path / "locked.conf", tmp_path)
    _os.chmod(config_path, 0o000)
    try:
        with pytest.raises(ConfigSettingsError) as exc_info:
            ConfigSettings(str(config_path))
        message = str(exc_info.value).lower()
        # configparser.read() silently skips unreadable files; the check at
        # __post_init__ catches the empty-loaded-files case via RuntimeError.
        assert "not found" in message or "unreadable" in message or str(config_path) in str(exc_info.value)
    finally:
        _os.chmod(config_path, 0o644)


def test_config_settings_memory_error_propagates_not_swallowed(tmp_path, monkeypatch):
    """MemoryError must not be caught and re-wrapped as ConfigSettingsError.

    MemoryError is a subclass of Exception, so the old catch-all would have
    disguised it as a config error. This test verifies the new handlers let
    it propagate so the OS/interpreter can handle it correctly.
    """
    import configparser as _cp
    original_read = _cp.ConfigParser.read

    def raise_memory_error(self, *args, **kwargs):
        raise MemoryError("simulated out-of-memory")

    # Monkeypatching is the only way to trigger MemoryError reliably in tests.
    monkeypatch.setattr(_cp.ConfigParser, "read", raise_memory_error)
    config_path = write_config(tmp_path / "cfg.conf", tmp_path)
    with pytest.raises(MemoryError):
        ConfigSettings(str(config_path))
