from dataclasses import dataclass, field
import configparser
from pathlib import Path
import sys
import logging

@dataclass
class ConfigSettings:
    """
    A dataclass for holding configuration settings, initialized from a configuration file.

    Attributes:
        logfile_location (str): The location of the log file.
        max_size_verification_mb (int): The maximum size for verification in megabytes.
        min_size_verification_mb (int): The minimum size for verification in megabytes.
        no_files_verification (int): The number of files for verification.
        command_timeout_secs (int): The timeout in seconds for commands.
        backup_dir (str): The directory for backups.
        test_restore_dir (str): The directory for test restores.
        backup_d_dir (str): The directory for backup.d.
        diff_age (int): The age for differential backups before deletion.
        incr_age (int): The age for incremental backups before deletion.
    """

    def __init__(self, config_file: str):
        """
        Initializes the ConfigSettings instance by reading the specified configuration file.
        
        Args:
            config_file (str): The path to the configuration file.
        """
        if config_file is None:
            raise ValueError("`config_file` must be specified.")
        
        self.config = configparser.ConfigParser()
        try:
            self.config.read(config_file)
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
            self.par2_enabled = bool(self.config['PAR2']['ENABLED'])
            # Ensure the directories exist
            Path(self.backup_dir).mkdir(parents=True, exist_ok=True)
            Path(self.test_restore_dir).mkdir(parents=True, exist_ok=True)
            Path(self.backup_d_dir).mkdir(parents=True, exist_ok=True)

        except FileNotFoundError as e:
            logging.error(f"Configuration file not found: {self.config_file}")
            logging.error(f"Error details: {e}")
            sys.exit("Error: Configuration file not found.")
        except PermissionError as e:
            logging.error(f"Permission error while reading config file {self.config_file}")
            logging.error(f"Error details: {e}")
            sys.exit("Error: Permission error while reading config file.")
        except KeyError as e:
            logging.error(f"Missing mandatory configuration key: {e}")
            logging.error(f"Error details: {e}")
            sys.exit(f"Error: Missing mandatory configuration key: {e}.")
        except Exception as e:
            logging.exception(f"Unexpected error reading config file {self.config_file}: {e}")
            logging.error(f"Error details: {e}")
            sys.exit(f"Unexpected error reading config file: {e}.")