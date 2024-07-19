
from dataclasses import dataclass
import configparser
from pathlib import Path
import sys
import logging

# Define a dataclass for configuration settings
@dataclass
class ConfigSettings:
    """
    A dataclass for holding configuration settings.

    Attributes:
        logfile_location (str): The file path for logging output.
        max_size_verification_mb (int): The maximum file size in MB for verification purposes.
        min_size_verification_mb (int): The minimum file size in MB for verification purposes.
        no_files_verification (int): Flag indicating whether file verification should be skipped (1) or not (0).
        backup_dir (str): The directory where backup files will be stored.
        test_restore_dir (str): The directory to use for testing restoration of backup files.
        backup_d_dir (str): The directory containing backup definitions.
    """
    logfile_location: str
    max_size_verification_mb: int
    min_size_verification_mb: int
    no_files_verification: int
    backup_dir: str
    test_restore_dir: str
    backup_d_dir: str

def read_config(config_file: str) -> ConfigSettings:
    """
    Reads configuration settings from a specified file and initializes a ConfigSettings dataclass instance with these values.
    Args:
        config_file (str): The path to the configuration file.
    Returns:
        ConfigSettings: An instance of ConfigSettings dataclass containing the configuration settings.
    Raises:
        FileNotFoundError: If the configuration file does not exist.
        PermissionError: If there is a permission error while reading the configuration file.
        KeyError: If required configuration sections or keys are missing in the configuration file.
        Exception: For any other exceptions that occur.
    """
    config = configparser.ConfigParser()
    try:
        config.read(config_file)
        settings = ConfigSettings(
            logfile_location=config['MISC']['LOGFILE_LOCATION'],
            max_size_verification_mb=int(config['MISC']['MAX_SIZE_VERIFICATION_MB']),
            min_size_verification_mb=int(config['MISC']['MIN_SIZE_VERIFICATION_MB']),
            no_files_verification=int(config['MISC']['NO_FILES_VERIFICATION']),
            backup_dir=config['DIRECTORIES']['BACKUP_DIR'],
            test_restore_dir=config['DIRECTORIES']['TEST_RESTORE_DIR'],
            backup_d_dir=config['DIRECTORIES']['BACKUP.D_DIR']
        )

        # Ensure the directories exist
        Path(settings.backup_dir).mkdir(parents=True, exist_ok=True)
        Path(settings.test_restore_dir).mkdir(parents=True, exist_ok=True)
        Path(settings.backup_d_dir).mkdir(parents=True, exist_ok=True)

        return settings

    except FileNotFoundError as e:
        logging.error(f"Configuration file not found: {config_file}")
        sys.stderr.write(f"Error: Configuration file not found: {config_file}\n")
        sys.exit(1)
    except PermissionError as e:
        logging.error(f"Permission error while reading config file {config_file}: {e}")
        sys.stderr.write(f"Error: Permission error while reading config file {config_file}: {e}\n")
        sys.exit(1)
    except KeyError as e:
        logging.error(f"Missing mandatory configuration key: {e}")
        sys.stderr.write(f"Error: Missing mandatory configuration key: {e}\n")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"Error: config file {config_file}: {e}")
        sys.stderr.write(f"Error: config file {config_file}: {e}\n")
        sys.exit(1)