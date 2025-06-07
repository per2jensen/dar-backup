# SPDX-License-Identifier: GPL-3.0-or-later

"""
util.py source code is here: https://github.com/per2jensen/dar-backup

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file
"""
import typing
import locale
import configparser
import inspect
import logging

import os
import re
import subprocess
import shlex
import shutil
import sys
import threading
import traceback

import dar_backup.__about__ as about


from argcomplete.completers import ChoicesCompleter
from datetime import datetime
from dar_backup.config_settings import ConfigSettings
from logging.handlers import RotatingFileHandler
from pathlib import Path
from rich.console import Console
from rich.text import Text

from typing import NamedTuple, List
from typing import Tuple


logger=None
secondary_logger=None   

#def setup_logging(log_file: str, command_output_log_file: str, log_level: str = "info", log_to_stdout: bool = False) -> logging.Logger:
def setup_logging(
    log_file: str,
    command_output_log_file: str,
    log_level: str = "info",
    log_to_stdout: bool = False,
    logfile_max_bytes: int = 26214400,
    logfile_backup_count: int = 5,
) -> logging.Logger:

    """
    Sets up logging for the main program and a separate secondary logfile for command outputs.

    Args:
        log_file (str): The path to the main log file.
        command_output_log_file (str): The path to the secondary log file for command outputs.
        log_level (str): The log level to use. Can be "info", "debug", or "trace". Defaults to "info".
        log_to_stdout (bool): If True, log messages will be printed to the console. Defaults to False.
        logfile_max_bytes: max file size of a log file, defailt = 26214400.
        logfile_backup_count: max numbers of logs files, default = 5.

    Returns:
        a RotatingFileHandler logger instance.

    Raises:
        Exception: If an error occurs during logging initialization
    """
    global logger, secondary_logger
    try:
        TRACE_LEVEL_NUM = 5
        logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")

        def trace(self, message, *args, **kws):
            if self.isEnabledFor(TRACE_LEVEL_NUM):
                self.log(TRACE_LEVEL_NUM, message, *args, **kws)

        logging.Logger.trace = trace

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=logfile_max_bytes,
            backupCount=logfile_backup_count,
            encoding="utf-8",
        )

        command_handler = RotatingFileHandler(
            command_output_log_file,
            maxBytes=logfile_max_bytes,
            backupCount=logfile_backup_count,
            encoding="utf-8",
        )

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        command_handler.setFormatter(formatter)


        # Setup main logger
        logger = logging.getLogger("main_logger")
        logger.setLevel(logging.DEBUG if log_level == "debug" else TRACE_LEVEL_NUM if log_level == "trace" else logging.INFO)
        logger.addHandler(file_handler)

        # Setup secondary logger for command outputs
        secondary_logger = logging.getLogger("command_output_logger")
        secondary_logger.setLevel(logging.DEBUG if log_level == "debug" else TRACE_LEVEL_NUM if log_level == "trace" else logging.INFO)
        secondary_logger.addHandler(command_handler)

        if log_to_stdout:
            stdout_handler = logging.StreamHandler(sys.stdout)
            stdout_handler.setFormatter(formatter)
            logger.addHandler(stdout_handler)

        return logger
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)



def get_logger(command_output_logger: bool = False) -> logging.Logger:
    """
    Returns a logger

    Args:
        use_secondary (bool): If True, returns the secondary logger. Defaults to False.

    Returns:
      logger to dar-backup.log or the logger for command output.
    """
    global logger, secondary_logger

    return secondary_logger if command_output_logger else logger


# Setup completer logger only once
def _setup_completer_logger(logfile="/tmp/dar_backup_completer.log"):
    logger = logging.getLogger("completer")
    if not logger.handlers:
        handler = logging.FileHandler(logfile)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    return logger

# Singleton logger for completer debugging
completer_logger = _setup_completer_logger()
completer_logger.debug("Completer logger initialized.")


def print_debug(msg):
    """
    Print a debug message with the filename and line number of the caller.    
    """
    frame = inspect.currentframe().f_back
    print(f"[DEBUG] {frame.f_code.co_filename}:{frame.f_lineno} - {repr(msg)}")



def get_invocation_command_line() -> str:
    """
    Safely retrieves the exact command line used to invoke the current Python process.

    On Unix-like systems, this reads from /proc/[pid]/cmdline to reconstruct the
    command with interpreter and arguments. If any error occurs (e.g., file not found,
    permission denied, non-Unix platform), it returns a descriptive error message.

    Returns:
        str: The full command line string, or an error description if it cannot be retrieved.
    """
    try:
        cmdline_path = f"/proc/{os.getpid()}/cmdline"
        with open(cmdline_path, "rb") as f:
            content = f.read()
            if not content:
                return "[error: /proc/cmdline is empty]"
            return content.replace(b'\x00', b' ').decode().strip()
    except Exception as e:
        return f"[error: could not read /proc/[pid]/cmdline: {e}]"


def show_scriptname()  -> str:
    """
    Return script name, useful in start banner for example
    """
    try:
        scriptname = os.path.basename(sys.argv[0])
    except:
        scriptname = "unknown"
    return scriptname


def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {about.__version__}")
    print(f"{script_name} source code is here: https://github.com/per2jensen/dar-backup")
    print(about.__license__)

def extract_version(output):
    match = re.search(r'(\d+\.\d+(\.\d+)?)', output)
    return match.group(1) if match else "unknown"

def get_binary_info(command):
    """
    Return information about a binary command.
    Args:
        command (str): The command to check.
    Returns:
        dict: A dictionary containing the command, path, version, and full output.
        Dict structure:
            {
                "command": str,
                "path": str,
                "version": str,
                "full_output": str
            }
    Raises:
        Exception: If there is an error running the command.
    """
    path = shutil.which(command)
    if path is None:
        return {
            "command": command,
            "path": "Not found",
            "version": "unknown",
            "full_output": ""
        }

    try:
        result = subprocess.run(
            [path, '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Combine output regardless of return code
        combined_output = (result.stdout + result.stderr).strip()

        # Even if returncode != 0, the version info may still be valid
        version = extract_version(combined_output)

        return {
            "command": command,
            "path": path,
            "version": version if version else "unknown",
            "full_output": combined_output
        }

    except Exception as e:
        return {
            "command": command,
            "path": path,
            "version": "error",
            "full_output": str(e)
        }


def requirements(type: str, config_setting: ConfigSettings):
    """
    Perform PREREQ or POSTREQ requirements.

    Args:
        type (str): The type of prereq (PREREQ, POSTREQ).
        config_settings (ConfigSettings): An instance of the ConfigSettings class.

    Raises:
        RuntimeError: If a subprocess returns anything but zero.

        subprocess.CalledProcessError: if CalledProcessError is raised in subprocess.run(), let it bobble up.
    """
    
    if type is None or config_setting is None:
        raise RuntimeError(f"requirements: 'type' or config_setting is None")

    allowed_types = ['PREREQ', 'POSTREQ'] 
    if type not in allowed_types:
        raise RuntimeError(f"requirements: {type} not in: {allowed_types}")


    logger.debug(f"Performing  {type}")
    if type in config_setting.config:
        for key in sorted(config_setting.config[type].keys()):
            script = config_setting.config[type][key]
            try:
                result = subprocess.run(script, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, check=True)
                logger.debug(f"{type} {key}: '{script}' run, return code: {result.returncode}")
                logger.debug(f"{type} stdout:\n{result.stdout}")
                if result.returncode != 0:
                    logger.error(f"{type} stderr:\n{result.stderr}")
                    raise RuntimeError(f"{type} {key}: '{script}' failed, return code: {result.returncode}")    
            except subprocess.CalledProcessError as e:
                logger.error(f"Error executing {key}: '{script}': {e}")
                raise e




class BackupError(Exception):
    """Exception raised for errors in the backup process."""
    pass

class DifferentialBackupError(BackupError):
    """Exception raised for errors in the differential backup process."""
    pass

class IncrementalBackupError(BackupError):
    """Exception raised for errors in the incremental backup process."""
    pass

class RestoreError(Exception):
    """Exception raised for errors in the restore process."""
    pass


class CommandResult(NamedTuple):
    """
    The reult of the run_command() function.
    """
    process: subprocess.CompletedProcess
    stdout: str
    stderr: str
    returncode: int
    timeout: int
    command: list[str]

    def __str__(self):
        #return f"CommandResult: [Return Code: '{self.returncode}', \nCommand: '{' '.join(map(shlex.quote, self.command))}', \nStdout:\n'{self.stdout}', \nStderr:\n'{self.stderr}', \nTimeout: '{self.timeout}']"
        return f"CommandResult: [Return Code: '{self.returncode}', \nCommand: '{' '.join(map(shlex.quote, self.command))}']"


def list_backups(backup_dir, backup_definition=None):
    """
    Lists the available backup files in the specified directory along with their total sizes in megabytes. 
    The function filters and processes `.dar` files, grouping them by their base names and ensuring proper 
    alignment of the displayed sizes.
    Args:
        backup_dir (str): The directory containing the backup files.
        backup_definition (str, optional): A prefix to filter backups by their base name. Only backups 
                                           starting with this prefix will be included. Defaults to None.
    Raises:
        locale.Error: If setting the locale fails and the fallback to the 'C' locale is unsuccessful.
    Behavior:
        - Attempts to set the locale based on the environment for proper formatting of numbers.
        - Filters `.dar` files in the specified directory based on the following criteria:
            - The file name must contain one of the substrings: "_FULL_", "_DIFF_", or "_INCR_".
            - The file name must include a date in the format "_YYYY-MM-DD".
        - Groups files by their base name (excluding slice numbers and extensions) and calculates 
          the total size for each group in megabytes.
        - Sorts the backups by their base name and date (if included in the name).
        - Prints the backup names and their sizes in a formatted and aligned manner.
    Returns:
        None: The function prints the results directly to the console. If no backups are found, 
              it prints "No backups available.".

    List the available backups in the specified directory and their sizes in megabytes, with aligned sizes.
    """
    # Attempt to set locale from the environment or fall back to the default locale
    try:
        # Try to get the locale from the environment
        locale.setlocale(locale.LC_ALL, '')
    except locale.Error:
        # If setting locale fails, fall back to the default 'C' locale
        locale.setlocale(locale.LC_ALL, 'C')
    
    # Create a dictionary to hold backup names and their total sizes
    backup_sizes = {}

   # Define the date pattern
    date_pattern = re.compile(r'_\d{4}-\d{2}-\d{2}')
  

    # List all files and filter .dar files
    for f in os.listdir(backup_dir):
        if f.endswith('.dar'):
            # Extract the base name of the backup (without slice number and extension)
            base_name = f.rsplit('.', 2)[0]
            if backup_definition and not base_name.startswith(backup_definition):
                continue

            # Check if the base name contains any of the substrings
            substrings = ["_FULL_", "_DIFF_", "_INCR_"]
            if not any(substring in base_name for substring in substrings):
                continue

            # Check if the base name contains a date in the form "-YYYY-MM-DD"
            if not date_pattern.search(base_name):
                continue


            # Calculate the file size in megabytes
            file_path = os.path.join(backup_dir, f)
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            
            # Accumulate the size for each base backup name
            if base_name in backup_sizes:
                backup_sizes[base_name] += file_size_mb
            else:
                backup_sizes[base_name] = file_size_mb
    
    if not backup_sizes:
        print("No backups available.")
        return
    
    # Determine the maximum length of the archive names
    max_name_length = max(len(name) for name in backup_sizes.keys())

    formatted_sizes = [locale.format_string("%d", int(size), grouping=True) for size in backup_sizes.values()]
    max_size_length = max(len(size) for size in formatted_sizes)

    # Sort backups by name and possibly by date if included in the name
    sorted_backups = sorted(backup_sizes.items(), key=lambda x: (x[0].split('_')[0], datetime.strptime(x[0].split('_')[-1], '%Y-%m-%d')))
    
    # Print the backups and their sizes with aligned sizes
    for backup, size in sorted_backups:
        formatted_size = locale.format_string("%d", int(size), grouping=True)
        print(f"{backup.ljust(max_name_length)} : {formatted_size.rjust(max_size_length)} MB")


def expand_path(path: str) -> str:
    """
    Expand ~ and environment variables like $HOME in a path.
    """
    return os.path.expanduser(os.path.expandvars(path))



def backup_definition_completer(prefix, parsed_args, **kwargs):
    config_path = getattr(parsed_args, 'config_file', '~/.config/dar-backup/dar-backup.conf')
    config_path = expand_path(config_path)
    config_file = os.path.expanduser(config_path)
    try:
        config = ConfigSettings(config_file)
        backup_d_dir = os.path.expanduser(config.backup_d_dir)
        return [f for f in os.listdir(backup_d_dir) if f.startswith(prefix)]
    except Exception:
        return []


def extract_backup_definition_fallback() -> str:
    """
    Extracts --backup-definition or -d value directly from COMP_LINE.
    This is needed because argcomplete doesn't always populate parsed_args fully.

    Returns:
        str: The value of the --backup-definition argument if found, else an empty string.
    """
    comp_line = os.environ.get("COMP_LINE", "")
    # Match both "--backup-definition VALUE" and "-d VALUE"
    match = re.search(r"(--backup-definition|-d)\s+([^\s]+)", comp_line)
    if match:
        return match.group(2)
    return ""




def list_archive_completer(prefix, parsed_args, **kwargs):
    import os
    import configparser
    from dar_backup.util import extract_backup_definition_fallback

    backup_def = getattr(parsed_args, "backup_definition", None) or extract_backup_definition_fallback()
    config_path = getattr(parsed_args, "config_file", None) or "~/.config/dar-backup/dar-backup.conf"

    config_path = os.path.expanduser(os.path.expandvars(config_path))
    if not os.path.exists(config_path):
        return []

    config = configparser.ConfigParser()
    config.read(config_path)
    backup_dir = config.get("DIRECTORIES", "BACKUP_DIR", fallback="")
    backup_dir = os.path.expanduser(os.path.expandvars(backup_dir))

    if not os.path.isdir(backup_dir):
        return []

    files = os.listdir(backup_dir)
    archive_re = re.compile(rf"^{re.escape(backup_def)}_.+_\d{{4}}-\d{{2}}-\d{{2}}\.1\.dar$") if backup_def else re.compile(r".+_\d{4}-\d{2}-\d{2}\.1\.dar$")

    completions = [
        f.rsplit(".1.dar", 1)[0]
        for f in files
        if archive_re.match(f)
    ]

    completions = sorted(set(completions), key=sort_key)
    return completions or ["[no matching archives]"]



def sort_key(archive_name: str):
    """
    Sort by backup definition and then by date extracted from the archive name.
    Handles formats like: <def>_<TYPE>_<YYYY-MM-DD>.<N>.dar
    """
    try:
        base = archive_name.split('.')[0]  # remove .1.dar
        parts = base.split('_')
        if len(parts) < 3:
            return (archive_name, datetime.min)  # fallback for non-matching formats

        # Correct assumption: last two parts are TYPE and DATE
        def_name = '_'.join(parts[:-2])  # everything before _TYPE_DATE
        date_str = parts[-1]
        date = datetime.strptime(date_str, "%Y-%m-%d")
        completer_logger.debug(f"Archive: {archive_name}, Def: {def_name}, Date: {date}")
        return (def_name, date)
    except Exception:
        return (archive_name, datetime.min)




def archive_content_completer(prefix, parsed_args, **kwargs):
    """
    Completes archive names from all available *.db files.
    If --backup-def is given, only that one is used.
    Only entries found in the catalog database (via `dar_manager --list`) are shown.
    """

    from dar_backup.config_settings import ConfigSettings
    import subprocess
    import re
    import os
    from datetime import datetime

    # Expand config path
    config_file = expand_path(getattr(parsed_args, "config_file", "~/.config/dar-backup/dar-backup.conf"))
    config = ConfigSettings(config_file=config_file)
    #db_dir = expand_path((getattr(config, 'manager_db_dir', config.backup_dir)))   # use manager_db_dir if set, else backup_dir
    db_dir = expand_path(getattr(config, 'manager_db_dir', None) or config.backup_dir)

    # Which db files to inspect?
    backup_def = getattr(parsed_args, "backup_def", None)
    db_files = (
        [os.path.join( db_dir, f"{backup_def}.db")]
        if backup_def
        else [os.path.join( db_dir, f) for f in os.listdir( db_dir) if f.endswith(".db")]
    )

    completions = []

    for db_path in db_files:
        if not os.path.exists(db_path):
            continue

        try:
            result = subprocess.run(
                ["dar_manager", "--base", db_path, "--list"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=True
            )
        except subprocess.CalledProcessError:
            continue

        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 3:
                archive = parts[2].strip()
                if archive.startswith(prefix):
                    completions.append(archive)

    completions = sorted(set(completions), key=sort_key)
    return completions or ["[no matching archives]"]



def add_specific_archive_completer(prefix, parsed_args, **kwargs):
    """
    Autocompletes archives that are present in the BACKUP_DIR
    but not yet present in the <backup_def>.db catalog.
    If --backup-def is provided, restrict suggestions to that.
    """
    from dar_backup.config_settings import ConfigSettings
    import subprocess
    import re
    import os
    from datetime import datetime

    config_file = expand_path(getattr(parsed_args, "config_file", "~/.config/dar-backup/dar-backup.conf"))
    config = ConfigSettings(config_file=config_file)
    #db_dir = expand_path((getattr(config, 'manager_db_dir', config.backup_dir)))   # use manager_db_dir if set, else backup_dir
    db_dir = expand_path(getattr(config, 'manager_db_dir') or config.backup_dir)
    backup_dir = config.backup_dir
    backup_def = getattr(parsed_args, "backup_def", None)

    # Match pattern for archive base names: e.g. test_FULL_2025-04-01
    dar_pattern = re.compile(r"^(.*?_(FULL|DIFF|INCR)_(\d{4}-\d{2}-\d{2}))\.1\.dar$")

    # Step 1: scan backup_dir for .1.dar files
    all_archives = set()
    for fname in os.listdir(backup_dir):
        match = dar_pattern.match(fname)
        if match:
            base = match.group(1)
            if base.startswith(prefix):
                if not backup_def or base.startswith(f"{backup_def}_"):
                    all_archives.add(base)

    # Step 2: exclude ones already present in the .db
    db_path = os.path.join(db_dir, f"{backup_def}.db") if backup_def else None
    existing = set()

    if db_path and os.path.exists(db_path):
        try:
            result = subprocess.run(
                ["dar_manager", "--base", db_path, "--list"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=True
            )
            for line in result.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 3:
                    existing.add(parts[2].strip())
        except subprocess.CalledProcessError:
            pass

    # Step 3: return filtered list
    candidates = sorted(archive for archive in all_archives if archive not in existing)
    return candidates or ["[no new archives]"]




def patch_config_file(path: str, replacements: dict) -> None:
    """
    Replace specific key values in a config file in-place.

    Args:
        path: Path to the config file.
        replacements: Dictionary of keys to new values, e.g., {"LOGFILE_LOCATION": "/tmp/logfile.log"}.
    """
    with open(path, 'r') as f:
        lines = f.readlines()

    with open(path, 'w') as f:
        for line in lines:
            key = line.split('=')[0].strip()
            if key in replacements:
                f.write(f"{key} = {replacements[key]}\n")
            else:
                f.write(line)




console = Console()

def print_aligned_settings(
    settings: List[Tuple[str, str]],
    log: bool = True,
    header: str = "Startup Settings",
    quiet: bool = True,
    highlight_keywords: List[str] = None
) -> None:
    """
    Print and optionally log settings nicely, using rich for color.
    Highlights settings if dangerous keywords are found inside label or text,
    but only if text is not None or empty.
    """
    if not settings:
        return

    settings = [(str(label), "" if text is None else str(text)) for label, text in settings]
    logger = get_logger()

    max_label_length = max(len(label) for label, _ in settings)

    header_line = f"========== {header} =========="
    footer_line = "=" * len(header_line)

    not quiet and console.print(f"[bold cyan]{header_line}[/bold cyan]")
    if log and logger:
        logger.info(header_line)

    for label, text in settings:
        padded_label = f"{label:<{max_label_length}}"

        label_clean = label.rstrip(":").lower()
        text_clean = text.lower()

        # Skip highlighting if text is empty
        if not text_clean.strip():
            danger = False
        else:
            danger = False
            if highlight_keywords:
                combined_text = f"{label_clean} {text_clean}"
                danger = any(keyword.lower() in combined_text for keyword in highlight_keywords)

        # Build the line
        line_text = Text()
        line_text.append(padded_label, style="bold")
        line_text.append(" ", style="none")

        if danger:
            line_text.append("[!]", style="bold red")
            line_text.append(" ", style="none")

        line_text.append(text, style="white")

        not quiet and console.print(line_text)

        # Always log clean text (no [!] in log)
        final_line_for_log = f"{padded_label} {text}"
        if log and logger:
            logger.info(final_line_for_log)

    not quiet and console.print(f"[bold cyan]{footer_line}[/bold cyan]")
    if log and logger:
        logger.info(footer_line)




def normalize_dir(path: str) -> str:
    """
    Strip any trailing slash/backslash but leave root (“/” or “C:\\”) intact.
    """
    p = Path(path)
    # Path(__str__) drops any trailing separators
    normalized = str(p)
    return normalized



# Reusable pattern for archive file naming
archive_pattern = re.compile(
    r'^.+?_(FULL|DIFF|INCR)_(\d{4}-\d{2}-\d{2})\.\d+\.dar'
    r'(?:\.vol\d+(?:\+\d+)?\.par2|\.par2)?$'
)

def is_safe_filename(filename: str) -> bool:
    """
    Validates that the filename matches acceptable dar/par2 naming convention.
    """
    return archive_pattern.match(filename) is not None

def is_safe_path(path: str) -> bool:
    """
    Validates that the full path is absolute, has no '..'.
    """
    normalized = os.path.normpath(path)
    filename = os.path.basename(normalized)

    return (
        os.path.isabs(normalized)
        and '..' not in normalized.split(os.sep)
    )


