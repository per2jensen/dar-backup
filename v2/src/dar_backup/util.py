"""
util.py source code is here: https://github.com/per2jensen/dar-backup

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file
"""
import typing
import locale
import logging
import os
import re
import subprocess
import shlex
import shutil
import sys
import threading
import traceback
from datetime import datetime

from typing import NamedTuple, List

logger=None
secondary_logger=None   


def setup_logging(log_file: str, command_output_log_file: str, log_level: str = "info", log_to_stdout: bool = False) -> logging.Logger:
    """
    Sets up logging for the main program and a separate secondary logfile for command outputs.

    Args:
        log_file (str): The path to the main log file.
        command_output_log_file (str): The path to the secondary log file for command outputs.
        log_level (str): The log level to use. Can be "info", "debug", or "trace". Defaults to "info".
        log_to_stdout (bool): If True, log messages will be printed to the console. Defaults to False.

    Returns:
        None

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

        # Setup main logger
        logger = logging.getLogger("main_logger")
        logger.setLevel(logging.DEBUG if log_level == "debug" else TRACE_LEVEL_NUM if log_level == "trace" else logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Setup secondary logger for command outputs
        secondary_logger = logging.getLogger("command_output_logger")
        secondary_logger.setLevel(logging.DEBUG if log_level == "debug" else TRACE_LEVEL_NUM if log_level == "trace" else logging.INFO)
        sec_file_handler = logging.FileHandler(command_output_log_file)
        sec_file_handler.setFormatter(formatter)
        secondary_logger.addHandler(sec_file_handler)

        if log_to_stdout:
            stdout_handler = logging.StreamHandler(sys.stdout)
            stdout_handler.setFormatter(formatter)
            logger.addHandler(stdout_handler)
            secondary_logger.addHandler(stdout_handler)

        return logger
    except Exception as e:
        print("Logging initialization failed.")
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



def _stream_reader(pipe, log_funcs, output_accumulator: List[str]):
    """
    Reads lines from the subprocess pipe and logs them to multiple destinations.
    """
    with pipe:
        for line in iter(pipe.readline, ''):
            stripped_line = line.strip()
            output_accumulator.append(stripped_line)
            for log_func in log_funcs:
                log_func(stripped_line)  # Log the output in real-time



def run_command(command: List[str], timeout: int = 30, no_output_log: bool = False):
    """
    Executes a command and streams output only to the secondary log unless no_log is set to True.


    Returns:
        A CommandResult NamedTuple with the following properties:
        - process: subprocess.CompletedProcess
        - stdout: str: The full standard output of the command.
        - stderr: str: The full standard error of the command.
        - returncode: int: The return code of the command.
        - timeout: int: The timeout value in seconds used to run the command.
        - command: list[str]: The command executed.

    Logs:
        - Logs standard output (`stdout`) and standard error in real-time to the
          logger.secondary_log (that contains the command output).  
    
    Raises:
        subprocess.TimeoutExpired: If the command execution times out (see `timeout` parameter).
        Exception: If other exceptions occur during command execution.
        FileNotFoundError: If the command is not found.
    """
    stdout_lines, stderr_lines = [], []
    process = None
    stdout_thread, stderr_thread = None, None

    try:
        logger =         get_logger(command_output_logger=False)
        command_logger = get_logger(command_output_logger=True)

        if not shutil.which(command[0]):
            raise FileNotFoundError(f"Command not found: {command[0]}")
   
        logger.debug(f"Running command: {command}")
        command_logger.info(f"Running command: {command}")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        log_funcs = [command_logger.info] if not no_output_log else []
        err_log_funcs = [command_logger.error] if not no_output_log else []

        stdout_thread = threading.Thread(target=_stream_reader, args=(process.stdout, log_funcs,     stdout_lines))
        stderr_thread = threading.Thread(target=_stream_reader, args=(process.stderr, err_log_funcs, stderr_lines))
        
        stdout_thread.start()
        stderr_thread.start()

        process.wait(timeout=timeout)

    except FileNotFoundError as e:
        logger.error(f"Command not found: {command[0]}")
        return CommandResult(
            process=None,
            stdout="",
            stderr=str(e),
            returncode=127,
            timeout=timeout,
            command=command
        )
    except subprocess.TimeoutExpired:
        if process:
            process.terminate()
        logger.error(f"Command: '{command}' timed out and was terminated.")
        raise
    except Exception as e:
        logger.error(f"Error running command: {command}", exc_info=True)
        raise
    finally:
        if stdout_thread and stdout_thread.is_alive():
            stdout_thread.join()
        if stderr_thread and stderr_thread.is_alive():
            stderr_thread.join()
        if process:
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

    
    # Combine captured stdout and stderr lines into single strings
    stdout = "\n".join(stdout_lines)
    stderr = "\n".join(stderr_lines)

    print(f"run_command(): stdout: {stdout}")

    #Build the result object
    result = CommandResult(process=process, stdout=stdout, stderr=stderr, returncode=process.returncode, timeout=timeout, command=command)
    return result


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




def extract_error_lines(log_file_path: str, start_time: str, end_time: str):
    """
    Extracts error lines from a log file within a specific time range.

    Args:
        log_file_path (str): The path to the log file.
        start_time (str): The start time of the desired time range (unixtime).
        end_time (str): The end time of the desired time range (unixtime).

    Returns:
        list: A list of error lines within the specified time range.

    Raises:
        ValueError: If the start or end markers are not found in the log file.
    """
    with open(log_file_path, 'r') as log_file:
        lines = log_file.readlines()

    start_index = None
    end_index = None

    start_marker = f"START TIME: {start_time}"
    end_marker = f"END TIME: {end_time}"
    error_pattern = re.compile(r'ERROR')

    # Find the start and end index for the specific run
    for i, line in enumerate(lines):
        if start_marker in line:
            start_index = i
        elif end_marker in line and start_index is not None:
            end_index = i
            break

    if start_index is None or end_index is None:
        raise ValueError("Could not find start or end markers in the log file")

    error_lines = [line.rstrip("\n") for line in lines[start_index:end_index + 1] if error_pattern.search(line)]

    return error_lines


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



