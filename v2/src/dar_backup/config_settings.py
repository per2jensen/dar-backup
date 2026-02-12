# SPDX-License-Identifier: GPL-3.0-or-later

import configparser
import os
import re
from dataclasses import dataclass, field, fields
from os.path import expandvars, expanduser
from typing import Optional, Pattern

from dar_backup.exceptions import ConfigSettingsError

@dataclass
class ConfigSettings:
    """
    Parses and holds configuration values from a dar-backup.conf file.

    Required fields are defined as dataclass attributes and must be present in the config file.
    Optional fields can be declared in the OPTIONAL_CONFIG_FIELDS list. If a key is present in the
    config file, the field is set to its parsed value; otherwise, it defaults to None.

    The __repr__ method will only include optional fields if their value is not None,
    keeping debug output clean and focused on explicitly configured values.

    OPTIONAL_CONFIG_FIELDS = [
        {
            "section": "DIRECTORIES",
            "key": "MANAGER_DB_DIR",
            "attr": "manager_db_dir",
            "type": str,
            "default": None,
        }
    ]
    """

    config_file: str

    logfile_location: str = field(init=False)
    max_size_verification_mb: int = field(init=False)
    min_size_verification_mb: int = field(init=False)
    no_files_verification: int = field(init=False)
    command_timeout_secs: int = field(init=False)
    command_capture_max_bytes: Optional[int] = field(init=False, default=None)
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
    logfile_max_bytes: int = field(init=False)
    logfile_no_count: int = field(init=False)    
    trace_log_max_bytes: int = field(init=False)
    trace_log_backup_count: int = field(init=False)
    dar_backup_discord_webhook_url: Optional[str] = field(init=False, default=None)
    restoretest_exclude_prefixes: list[str] = field(init=False, default_factory=list)
    restoretest_exclude_suffixes: list[str] = field(init=False, default_factory=list)
    restoretest_exclude_regex: Optional[Pattern[str]] = field(init=False, default=None)


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
            self.max_size_verification_mb = int(self.config['MISC']['MAX_SIZE_VERIFICATION_MB'])
            self.min_size_verification_mb = int(self.config['MISC']['MIN_SIZE_VERIFICATION_MB'])
            self.no_files_verification = int(self.config['MISC']['NO_FILES_VERIFICATION'])
            self.command_timeout_secs = int(self.config['MISC']['COMMAND_TIMEOUT_SECS'])
            env_timeout = os.getenv("DAR_BACKUP_COMMAND_TIMEOUT_SECS")
            if env_timeout is not None:
                self.command_timeout_secs = self._parse_env_timeout(env_timeout)
            self.backup_dir = self.config['DIRECTORIES']['BACKUP_DIR']
            self.test_restore_dir = self.config['DIRECTORIES']['TEST_RESTORE_DIR']
            self.backup_d_dir = self.config['DIRECTORIES']['BACKUP.D_DIR']
            self.diff_age = int(self.config['AGE']['DIFF_AGE'])
            self.incr_age = int(self.config['AGE']['INCR_AGE'])
            self.error_correction_percent = int(self.config['PAR2']['ERROR_CORRECTION_PERCENT'])

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

            # Load optional fields
            for opt in self.OPTIONAL_CONFIG_FIELDS:
                if self.config.has_option(opt['section'], opt['key']):
                    raw_value = self.config.get(opt['section'], opt['key'])
                    try:
                        value = opt['type'](raw_value.strip())
                        setattr(self, opt['attr'], value)
                    except Exception as e:
                        raise ConfigSettingsError(
                            f"Failed to parse optional config '{opt['section']}::{opt['key']}': {e}"
                        )
                else:
                    setattr(self, opt['attr'], opt.get('default', None))


            # Expand paths in all string fields that exist
            for field in fields(self):
                if hasattr(self, field.name):
                    value = getattr(self, field.name)
                    if isinstance(value, str):
                        setattr(self, field.name, expanduser(expandvars(value)))

        except RuntimeError as e:
            raise ConfigSettingsError(f"RuntimeError: {e}")
        except KeyError as e:
            raise ConfigSettingsError(f"Missing mandatory configuration key: {e}")
        except ValueError as e:
            raise ConfigSettingsError(f"Invalid value in config: {e}")
        except Exception as e:
            raise ConfigSettingsError(f"Unexpected error during config initialization: {e}")



    def __repr__(self):
        safe_fields = [
            f"{field.name}={getattr(self, field.name)!r}"
            for field in fields(self)
            if hasattr(self, field.name) and getattr(self, field.name) is not None
        ]
        return f"<ConfigSettings({', '.join(safe_fields)})>"

    def _get_optional_str(self, section: str, key: str, default: Optional[str] = None) -> Optional[str]:
        if self.config.has_option(section, key):
            return self.config.get(section, key).strip()
        return default

    def _get_optional_int(self, section: str, key: str, default: Optional[int] = None) -> Optional[int]:
        if self.config.has_option(section, key):
            raw = self.config.get(section, key).strip()
            return int(raw)
        return default

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

        section = self.config[backup_definition]
        for raw_key, raw_value in section.items():
            key = raw_key.upper()
            value = raw_value.strip()
            if not key.startswith("PAR2_"):
                continue
            if key == "PAR2_DIR":
                par2_config["par2_dir"] = value
            elif key == "PAR2_RATIO_FULL":
                par2_config["par2_ratio_full"] = int(value)
            elif key == "PAR2_RATIO_DIFF":
                par2_config["par2_ratio_diff"] = int(value)
            elif key == "PAR2_RATIO_INCR":
                par2_config["par2_ratio_incr"] = int(value)
            elif key == "PAR2_RUN_VERIFY":
                val = value.lower()
                if val in ('true', '1', 'yes'):
                    par2_config["par2_run_verify"] = True
                elif val in ('false', '0', 'no'):
                    par2_config["par2_run_verify"] = False
                else:
                    raise ConfigSettingsError(f"Invalid boolean value for 'PAR2_RUN_VERIFY' in [{backup_definition}]: '{value}'")
            elif key == "PAR2_ENABLED":
                val = value.lower()
                if val in ('true', '1', 'yes'):
                    par2_config["par2_enabled"] = True
                elif val in ('false', '0', 'no'):
                    par2_config["par2_enabled"] = False
                else:
                    raise ConfigSettingsError(f"Invalid boolean value for 'PAR2_ENABLED' in [{backup_definition}]: '{value}'")

        return par2_config
