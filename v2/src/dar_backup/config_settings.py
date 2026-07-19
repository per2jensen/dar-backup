# SPDX-License-Identifier: GPL-3.0-or-later

import configparser
import logging
import os
import re
from dataclasses import dataclass, field, fields
from os.path import expandvars, expanduser
from typing import Optional, Pattern, cast

from dar_backup.exceptions import ConfigSettingsError

logger = logging.getLogger(__name__)

@dataclass
class ConfigSettings:
    """
    Parses and holds configuration values from a dar-backup.conf file.

    Required fields are defined as dataclass attributes and must be present in the config file.
    Optional fields must be declared as dataclass fields with appropriate defaults AND listed in
    OPTIONAL_CONFIG_FIELDS, which maps config-file keys to field names and supplies the fallback
    value when the key is absent from the config file.  Both places must be kept in sync:
    - The dataclass field is the source of truth for type annotations and IDE visibility.
    - OPTIONAL_CONFIG_FIELDS drives the config-file-to-attribute mapping at runtime.

    The __repr__ method will only include fields whose value is not None,
    keeping debug output clean and focused on explicitly configured values.
    """

    config_file: str

    logfile_location: str = field(init=False)
    max_size_verification_mb: int = field(init=False)
    min_size_verification_mb: int = field(init=False)
    no_files_verification: int = field(init=False)
    command_timeout_secs: int = field(init=False)
    command_capture_max_bytes: Optional[int] = field(init=False, default=102400)  # 100 KiB; matches OPTIONAL_CONFIG_FIELDS default
    backup_dir: str = field(init=False)
    test_restore_dir: str = field(init=False)
    backup_d_dir: str = field(init=False)
    diff_age: int = field(init=False)
    incr_age: int = field(init=False)
    error_correction_percent: int = field(init=False)
    par2_enabled: bool = field(init=False)
    par2_dir: Optional[str] = field(init=False, default=None)
    par2_ratio_full: Optional[int] = field(init=False, default=None)
    par2_ratio_diff: Optional[int] = field(init=False, default=None)
    par2_ratio_incr: Optional[int] = field(init=False, default=None)
    par2_run_verify: Optional[bool] = field(init=False, default=None)
    logfile_max_bytes: int = field(init=False, default=26214400)  # 25 MB; matches OPTIONAL_CONFIG_FIELDS default
    logfile_backup_count: int = field(init=False, default=5)      # was logfile_no_count (wrong name, never populated)
    trace_log_max_bytes: int = field(init=False, default=10485760)  # 10 MB; matches OPTIONAL_CONFIG_FIELDS default
    trace_log_backup_count: int = field(init=False, default=1)    # matches OPTIONAL_CONFIG_FIELDS default
    dar_backup_discord_webhook_url: Optional[str] = field(init=False, default=None)
    metrics_db_path: Optional[str] = field(init=False, default=None)
    manager_db_dir: Optional[str] = field(init=False, default=None)
    restoretest_exclude_prefixes: list[str] = field(init=False, default_factory=list)
    restoretest_exclude_suffixes: list[str] = field(init=False, default_factory=list)
    restoretest_exclude_regex: Optional[Pattern[str]] = field(init=False, default=None)
    restore_ownership: bool = field(init=False, default=False)


    OPTIONAL_CONFIG_FIELDS = [
        {
            "section": "DIRECTORIES",
            "key": "MANAGER_DB_DIR",
            "attr": "manager_db_dir",
            "type": str,
            "default": None,
        },
        {
            "section": "MISC",
            "key": "LOGFILE_MAX_BYTES",
            "attr": "logfile_max_bytes",
            "type": int,
            "default": 26214400 , # 25 MB
        },
        {
            "section": "MISC",
            "key": "LOGFILE_BACKUP_COUNT",
            "attr": "logfile_backup_count",
            "type": int,
            "default": 5,
        },
        {
            "section": "MISC",
            "key": "TRACE_LOG_MAX_BYTES",
            "attr": "trace_log_max_bytes",
            "type": int,
            "default": 10485760, # 10 MB
        },
        {
            "section": "MISC",
            "key": "TRACE_LOG_BACKUP_COUNT",
            "attr": "trace_log_backup_count",
            "type": int,
            "default": 1,
        },
        {
            "section": "MISC",
            "key": "DAR_BACKUP_DISCORD_WEBHOOK_URL",
            "attr": "dar_backup_discord_webhook_url",
            "type": str,
            "default": None,
        },
        {
            "section": "MISC",
            "key": "COMMAND_CAPTURE_MAX_BYTES",
            "attr": "command_capture_max_bytes",
            "type": int,
            "default": 102400,
        },
        {
            "section": "MISC",
            "key": "METRICS_DB_PATH",
            "attr": "metrics_db_path",
            "type": str,
            "default": None,
        },
        # Add more optional fields here
    ]

    def __post_init__(self):
        if not self.config_file:
            raise ConfigSettingsError("`config_file` must be specified.")

        try:
            self.config = configparser.ConfigParser(inline_comment_prefixes=['#'])
            loaded_files = self.config.read(self.config_file)
            if not loaded_files:
                raise RuntimeError(f"Configuration file not found or unreadable: '{self.config_file}'")

            self.logfile_location = self.config['MISC']['LOGFILE_LOCATION']
            self.max_size_verification_mb = self._get_int('MISC', 'MAX_SIZE_VERIFICATION_MB')
            self.min_size_verification_mb = self._get_int('MISC', 'MIN_SIZE_VERIFICATION_MB')
            self.no_files_verification = self._get_int('MISC', 'NO_FILES_VERIFICATION')
            self.command_timeout_secs = self._get_int('MISC', 'COMMAND_TIMEOUT_SECS')
            if not (self.command_timeout_secs == -1 or self.command_timeout_secs > 0):
                raise ConfigSettingsError(
                    f"COMMAND_TIMEOUT_SECS must be -1 (disable timeout) or > 0, "
                    f"got: {self.command_timeout_secs}"
                )
            env_timeout = os.getenv("DAR_BACKUP_COMMAND_TIMEOUT_SECS")
            if env_timeout is not None:
                self.command_timeout_secs = self._parse_env_timeout(env_timeout)
            self.backup_dir = self.config['DIRECTORIES']['BACKUP_DIR']
            self.test_restore_dir = self.config['DIRECTORIES']['TEST_RESTORE_DIR']
            self.backup_d_dir = self.config['DIRECTORIES']['BACKUP.D_DIR']
            self.diff_age = self._get_int('AGE', 'DIFF_AGE')
            self.incr_age = self._get_int('AGE', 'INCR_AGE')
            self.error_correction_percent = self._get_int('PAR2', 'ERROR_CORRECTION_PERCENT')

            if self.no_files_verification < 1:
                raise ConfigSettingsError(
                    f"NO_FILES_VERIFICATION must be >= 1, got: {self.no_files_verification}"
                )

            if self.max_size_verification_mb <= 0:
                raise ConfigSettingsError(
                    f"MAX_SIZE_VERIFICATION_MB must be > 0, got: {self.max_size_verification_mb}"
                )

            if self.min_size_verification_mb < 0:
                raise ConfigSettingsError(
                    f"MIN_SIZE_VERIFICATION_MB must be >= 0, got: {self.min_size_verification_mb}"
                )

            if self.min_size_verification_mb > self.max_size_verification_mb:
                raise ConfigSettingsError(
                    f"MIN_SIZE_VERIFICATION_MB ({self.min_size_verification_mb}) must not "
                    f"exceed MAX_SIZE_VERIFICATION_MB ({self.max_size_verification_mb})"
                )

            if self.diff_age < 1:
                raise ConfigSettingsError(f"DIFF_AGE must be >= 1, got: {self.diff_age}")

            if self.incr_age < 1:
                raise ConfigSettingsError(f"INCR_AGE must be >= 1, got: {self.incr_age}")
            if not 1 <= self.error_correction_percent <= 90:
                raise ConfigSettingsError(
                    f"ERROR_CORRECTION_PERCENT must be between 1 and 90, got: {self.error_correction_percent}"
                )

            val = self.config['PAR2']['ENABLED'].strip().lower()
            if val in ('true', '1', 'yes'):
                self.par2_enabled = True
            elif val in ('false', '0', 'no'):
                self.par2_enabled = False
            else:
                raise ConfigSettingsError(f"Invalid boolean value for 'ENABLED' in [PAR2]: '{val}'")

            self.par2_dir = self._get_optional_str("PAR2", "PAR2_DIR", default=None)
            self.par2_ratio_full = self._get_optional_int("PAR2", "PAR2_RATIO_FULL", default=None)
            self.par2_ratio_diff = self._get_optional_int("PAR2", "PAR2_RATIO_DIFF", default=None)
            self.par2_ratio_incr = self._get_optional_int("PAR2", "PAR2_RATIO_INCR", default=None)
            self.par2_run_verify = self._get_optional_bool("PAR2", "PAR2_RUN_VERIFY", default=None)
            self.restoretest_exclude_prefixes = self._get_optional_csv_list(
                "MISC",
                "RESTORETEST_EXCLUDE_PREFIXES",
                default=[]
            )
            self.restoretest_exclude_suffixes = self._get_optional_csv_list(
                "MISC",
                "RESTORETEST_EXCLUDE_SUFFIXES",
                default=[]
            )
            self.restoretest_exclude_regex = self._get_optional_regex(
                "MISC",
                "RESTORETEST_EXCLUDE_REGEX",
                default=None
            )
            self.restore_ownership = self._get_optional_bool(
                "MISC", "RESTORE_OWNERSHIP", default=False
            )

            # Load optional fields
            for opt in self.OPTIONAL_CONFIG_FIELDS:
                setattr(
                    self,
                    opt['attr'],
                    self._get_config_value(opt['section'], opt['key'], opt['type'], opt.get('default')),
                )


            # Expand paths in all string fields that exist.
            # Loop var is `f` (not `field`) so it does not shadow the dataclasses
            # `field` imported at module scope.
            for f in fields(self):
                if hasattr(self, f.name):
                    value = getattr(self, f.name)
                    if isinstance(value, str):
                        setattr(self, f.name, expanduser(expandvars(value)))

        except ConfigSettingsError:
            raise
        except OSError as e:
            raise ConfigSettingsError(
                f"Cannot read or parse config file '{self.config_file}': {e}"
            ) from e
        except configparser.Error as e:
            raise ConfigSettingsError(
                f"Cannot parse config file '{self.config_file}': {e}"
            ) from e
        except RuntimeError as e:
            raise ConfigSettingsError(f"RuntimeError: {e}") from e
        except KeyError as e:
            raise ConfigSettingsError(f"Missing mandatory configuration key: {e}") from e
        except ValueError as e:
            raise ConfigSettingsError(f"Invalid value in config: {e}") from e



    def __repr__(self):
        safe_fields = [
            f"{field.name}={getattr(self, field.name)!r}"
            for field in fields(self)
            if hasattr(self, field.name) and getattr(self, field.name) is not None
        ]
        return f"<ConfigSettings({', '.join(safe_fields)})>"

    def _get_config_value(self, section: str, key: str, converter, default):
        """Read an optional config key and convert it with *converter*.

        Args:
            section: Config file section name.
            key: Config key within that section.
            converter: Callable applied to the stripped raw string, e.g. ``int`` or ``str``.
            default: Value returned when the key is absent from the config.

        Returns:
            ``converter(raw)`` if the key is present, ``default`` otherwise.

        Raises:
            ConfigSettingsError: If the key is present but ``converter`` raises.
        """
        if not self.config.has_option(section, key):
            return default
        raw = self.config.get(section, key).strip()
        try:
            return converter(raw)
        except (ValueError, TypeError) as e:
            raise ConfigSettingsError(
                f"Expected valid value for '{key}' in [{section}], got: '{raw}'"
            ) from e

    def _get_optional_str(self, section: str, key: str, default: Optional[str] = None) -> Optional[str]:
        """Read an optional string config value.

        Args:
            section: Config file section name.
            key: Config key within that section.
            default: Value to return when the key is absent.

        Returns:
            Stripped string value, or *default* if the key is not present.
        """
        return self._get_config_value(section, key, str, default)

    def _get_int(self, section: str, key: str) -> int:
        """Read a mandatory integer config value and raise ConfigSettingsError with context on failure.

        Args:
            section: Config file section name.
            key: Config key within that section.

        Returns:
            Parsed integer value.

        Raises:
            ConfigSettingsError: If the value cannot be parsed as an integer.
        """
        raw = self.config[section][key].strip()
        try:
            return int(raw)
        except ValueError as e:
            raise ConfigSettingsError(
                f"Expected an integer for '{key}' in [{section}], got: '{raw}'"
            ) from e

    def _get_optional_int(self, section: str, key: str, default: Optional[int] = None) -> Optional[int]:
        """Read an optional integer config value and raise ConfigSettingsError with context on failure.

        Args:
            section: Config file section name.
            key: Config key within that section.
            default: Value to return when the key is absent.

        Returns:
            Parsed integer, or *default* if the key is not present.

        Raises:
            ConfigSettingsError: If the key is present but cannot be parsed as an integer.
        """
        return self._get_config_value(section, key, int, default)

    def _get_optional_bool(self, section: str, key: str, default: Optional[bool] = None) -> Optional[bool]:
        if not self.config.has_option(section, key):
            return default
        val = self.config.get(section, key).strip().lower()
        if val in ('true', '1', 'yes'):
            return True
        if val in ('false', '0', 'no'):
            return False
        raise ConfigSettingsError(f"Invalid boolean value for '{key}' in [{section}]: '{val}'")

    def _parse_env_timeout(self, raw_value: str) -> int:
        raw = raw_value.strip()
        if not raw:
            raise ConfigSettingsError(
                "Invalid DAR_BACKUP_COMMAND_TIMEOUT_SECS environment value: must be -1 or > 0."
            )
        try:
            value = int(raw)
        except ValueError as exc:
            raise ConfigSettingsError(
                "Invalid DAR_BACKUP_COMMAND_TIMEOUT_SECS environment value: must be -1 or > 0."
            ) from exc
        if value == -1 or value > 0:
            return value
        raise ConfigSettingsError(
            "Invalid DAR_BACKUP_COMMAND_TIMEOUT_SECS environment value: must be -1 or > 0."
        )

    def _get_optional_csv_list(self, section: str, key: str, default: Optional[list[str]] = None) -> list[str]:
        if not self.config.has_option(section, key):
            return default if default is not None else []
        raw = self.config.get(section, key).strip()
        if not raw:
            return default if default is not None else []
        return [item.strip() for item in raw.split(",") if item.strip()]

    def _get_optional_regex(
        self,
        section: str,
        key: str,
        default: Optional[Pattern[str]] = None
    ) -> Optional[Pattern[str]]:
        if not self.config.has_option(section, key):
            return default
        raw = self.config.get(section, key).strip()
        if not raw:
            return default
        try:
            return re.compile(raw, re.IGNORECASE)
        except re.error as exc:
            raise ConfigSettingsError(
                f"Invalid regex for '{key}' in [{section}]: {exc}"
            ) from exc

    def get_par2_config(self, backup_definition: Optional[str] = None) -> dict:
        """
        Return PAR2 settings, applying per-backup overrides when present.
        """
        par2_config = {
            "par2_dir": self.par2_dir,
            "par2_ratio_full": self.par2_ratio_full,
            "par2_ratio_diff": self.par2_ratio_diff,
            "par2_ratio_incr": self.par2_ratio_incr,
            "par2_run_verify": self.par2_run_verify,
            "par2_enabled": self.par2_enabled,
        }

        if not backup_definition or not self.config.has_section(backup_definition):
            return par2_config

        s = backup_definition
        par2_config["par2_dir"] = self._get_config_value(s, "par2_dir", str, par2_config["par2_dir"])
        par2_config["par2_ratio_full"] = self._get_config_value(s, "par2_ratio_full", int, par2_config["par2_ratio_full"])
        par2_config["par2_ratio_diff"] = self._get_config_value(s, "par2_ratio_diff", int, par2_config["par2_ratio_diff"])
        par2_config["par2_ratio_incr"] = self._get_config_value(s, "par2_ratio_incr", int, par2_config["par2_ratio_incr"])
        par2_config["par2_run_verify"] = self._get_optional_bool(
            s, "par2_run_verify", cast(Optional[bool], par2_config["par2_run_verify"])
        )
        par2_config["par2_enabled"] = self._get_optional_bool(
            s, "par2_enabled", cast(Optional[bool], par2_config["par2_enabled"])
        )
        return par2_config
