"""
util.py source code is here: https://github.com/per2jensen/dar-backup

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file
"""

import locale
import logging
import os
import re
import subprocess
import shlex
import sys
import traceback
from datetime import datetime

logger=None

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



def setup_logging(log_file, log_level):
    global logger
    try:
        TRACE_LEVEL_NUM = 5
        logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")

        def trace(self, message, *args, **kws):
            if self.isEnabledFor(TRACE_LEVEL_NUM):
                self._log(TRACE_LEVEL_NUM, message, args, **kws)

        logging.Logger.trace = trace

        # Create a custom logger
        logger = logging.getLogger(__name__)

        level_used = logging.INFO
        logger.setLevel(logging.INFO)
        if log_level == "debug":
            level_used = logging.DEBUG
            logger.setLevel(logging.DEBUG)
        elif log_level == "trace":
            level_used = TRACE_LEVEL_NUM
            logger.setLevel(TRACE_LEVEL_NUM)

        logging.basicConfig(filename=log_file, level=level_used,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    except Exception as e:
        print("logging not initialized, exiting.")
        traceback.print_exc()
        sys.exit(1)

    return logger




def run_command(command: list[str]) -> subprocess.CompletedProcess:
    """
    Executes a given command via subprocess and captures its output.

    Args:
        command (list): The command to be executed, represented as a list of strings.

    Returns:
        str: The standard output of the command.

    Raises:
        Exception: If the command exits with a non-zero return code, an exception is raised
                   with the error output and the failed command.
    """
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        logger.trace(stdout)
        if process.returncode != 0:
            logger.error(stderr)
            raise Exception(f"Command: {' '.join(map(shlex.quote, command))} failed with return code {process.returncode}: {stderr}")
    except Exception as e:
        logger.error(f"Error running command: {command}")
        raise

    return process


def run_command_package_path2(command: list[str], package_path: str)  -> str:
    """
    Executes a given command via subprocess and captures its output.

    Args:
        command (list): The command to be executed, represented as a list of strings.

    Returns:
        str: The standard output of the command if no errors 

    Raises:
        Exception: If the command exits with a non-zero return code, an exception is raised
                   with the error output and the failed command.
    """
    logger.info(f"package_path: {package_path}")
    current_pythonpath = os.environ.get('PYTHONPATH', '')
    os.environ['PYTHONPATH'] = f"{package_path}:{current_pythonpath}"
    logger.info(f"PYTHONPATH: {os.environ['PYTHONPATH']}")
    logger.info(f"Running command: {command}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    logger.info(f"stdout:  {stdout}")
    logger.error(f"stderr: {stderr}")   
    logger.trace(stdout)

    os.environ['PYTHONPATH'] = current_pythonpath

    logger.info(f"Now checking return code: {process.returncode}")
    if process.returncode != 0:
        logger.error(stderr)
        raise Exception(f"Command: {' '.join(map(shlex.quote, command))} failed with return code {process.returncode}: {stderr}")
    return stdout




def list_backups(backup_dir, backup_definition=None):
    """
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



