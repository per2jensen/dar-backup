# SPDX-License-Identifier: GPL-3.0-or-later

import configparser
from dataclasses import dataclass, field, fields
from os.path import expandvars, expanduser
from pathlib import Path

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
    backup_dir: str = field(init=False)
    test_restore_dir: str = field(init=False)
    backup_d_dir: str = field(init=False)
    diff_age: int = field(init=False)
    incr_age: int = field(init=False)
    error_correction_percent: int = field(init=False)
    par2_enabled: bool = field(init=False)
    logfile_max_bytes: int = field(init=False)
    logfile_no_count: int = field(init=False)    


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
        # Add more optional fields here
    ]

    def __post_init__(self):
        if not self.config_file:
            raise ConfigSettingsError("`config_file` must be specified.")

        try:
            self.config = configparser.ConfigParser()
            loaded_files = self.config.read(self.config_file)
            if not loaded_files:
                raise RuntimeError(f"Configuration file not found or unreadable: '{self.config_file}'")

            self.logfile_location = self.config['MISC']['LOGFILE_LOCATION']
            self.max_size_verification_mb = int(self.config['MISC']['MAX_SIZE_VERIFICATION_MB'])
            self.min_size_verification_mb = int(self.config['MISC']['MIN_SIZE_VERIFICATION_MB'])
            self.no_files_verification = int(self.config['MISC']['NO_FILES_VERIFICATION'])
            self.command_timeout_secs = int(self.config['MISC']['COMMAND_TIMEOUT_SECS'])
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


