#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
installer.py source code is here: https://github.com/per2jensen/dar-backup/tree/main/v2/src/dar_backup/installer.py
This script is part of dar-backup, a backup solution for Linux using dar and systemd.

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

This script can be used to control `dar` to backup parts of or the whole system.
"""



import argcomplete
import argparse
import filecmp

import os
import random
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import threading

from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path
from sys import exit
from sys import stderr
from sys import argv
from sys import version_info
from time import time
from rich.console import Console
from rich.text import Text
from threading import Event
from typing import List, Tuple

from . import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import list_backups
from dar_backup.util import setup_logging
from dar_backup.util import get_logger
from dar_backup.util import BackupError
from dar_backup.util import RestoreError
from dar_backup.util import requirements
from dar_backup.util import show_version
from dar_backup.util import get_invocation_command_line
from dar_backup.util import get_binary_info
from dar_backup.util import print_aligned_settings
from dar_backup.util import backup_definition_completer, list_archive_completer
from dar_backup.util import show_scriptname
from dar_backup.util import print_debug

from dar_backup.command_runner import CommandRunner   
from dar_backup.command_runner import CommandResult

from dar_backup.rich_progress import show_log_driven_bar

from argcomplete.completers import FilesCompleter

logger = None
runner = None

def generic_backup(type: str, command: List[str], backup_file: str, backup_definition: str, darrc: str,  config_settings: ConfigSettings, args: argparse.Namespace) -> List[str]:
    """
    Performs a backup using the 'dar' command.

    This function initiates a full backup operation by constructing and executing a command
    with the 'dar' utility. It checks if the backup file already exists to avoid overwriting
    previous backups. If the backup file does not exist, it proceeds with the backup operation.

    Args:
        type (str): The type of backup (FULL, DIFF, INCR).
        command (List[str]): The command to execute for the backup operation.
        backup_file (str): The base name of the backup file. The actual backup will be saved
                           as '{backup_file}.1.dar'.
        backup_definition (str): The path to the backup definition file. This file contains
                                 specific instructions for the 'dar' utility, such as which
                                 directories to include or exclude.
        darrc (str): The path to the '.darrc' configuration file.
        config_settings (ConfigSettings): An instance of the ConfigSettings class.


    Raises:
        BackupError: If an error leading to a bad backup occurs during the backup process.

    Returns:
        List of tuples (<msg>, <exit_code>) of errors not considered critical enough for raising an exception  
    """

    result: List[tuple] = []

    logger.info(f"===> Starting {type} backup for {backup_definition}")
    try:
        log_basename = os.path. dirname(config_settings.logfile_location)
        logfile = os.path.basename(config_settings.logfile_location)[:-4] + "-commands.log"
        log_path = os.path.join( log_basename, logfile)
        logger.debug(f"Commands log file: {log_path}")

        # wrap a progress bar around the dar command
        stop_event = Event()
        session_marker = f"=== START BACKUP SESSION: {int(time())} ==="
        get_logger(command_output_logger=True).info(session_marker)
        progress_thread = threading.Thread(
            target=show_log_driven_bar,
            args=(log_path, stop_event, session_marker),
            daemon=True
        )
        progress_thread.start()
        try:
            process = runner.run(command, timeout = config_settings.command_timeout_secs)
        except Exception as e:
            print(f"[!] Backup failed: {e}")
            raise
        finally:
            stop_event.set()
            progress_thread.join()

        if process.returncode == 0:
            logger.info(f"{type} backup completed successfully.")
        elif process.returncode == 5:
            logger.warning("Backup completed with some files not backed up, this can happen if files are changed/deleted during the backup.")
        else:
            raise Exception(str(process))

        if process.returncode == 0 or process.returncode == 5:
            add_catalog_command = ['manager', '--add-specific-archive' ,backup_file, '--config-file', args.config_file]
            command_result = runner.run(add_catalog_command, timeout = config_settings.command_timeout_secs)
            if command_result.returncode == 0:
                logger.info(f"Catalog for archive '{backup_file}' added successfully to its manager.")
            else:
                msg = f"Catalog for archive '{backup_file}' not added."
                logger.error(msg)
                result.append((msg, 1))

        return result

    except subprocess.CalledProcessError as e:
        logger.error(f"Backup command failed: {e}")
        raise BackupError(f"Backup command failed: {e}") from e
    except Exception as e:
        logger.exception(f"Unexpected error during backup")
        raise BackupError(f"Unexpected error during backup: {e}") from e
    


def find_files_with_paths(xml_doc: str):
    """
    Finds files within an XML element and returns a list of tuples (file path, size).

    Args:
        xml_root: str  The XML generated by dar -l <archive> -Txml.

    Returns:
        list: A list of tuples (file path, size).
    """
    #get_logger().debug("Generating list of tuples with file paths and sizes for File elements in dar xml output")
    xml_doc = re.sub(r'<!DOCTYPE[^>]*>', '', xml_doc)
    root = ET.fromstring(xml_doc)

    files_list = []

    def iterate_dir(element, current_path=""):
        for child in element:
            if child.tag == 'Directory':
                dir_name = child.get('name')
                new_path = f"{current_path}/{dir_name}" if current_path else dir_name
                iterate_dir(child, new_path)

            elif child.tag == 'File':
                file_name = child.get('name')
                file_size = child.get('size')
                file_path = f"{current_path}/{file_name}" if current_path else file_name
                files_list.append((file_path, file_size))

    iterate_dir(root)
    return files_list


def find_files_between_min_and_max_size(backed_up_files: list[(str, str)], config_settings: ConfigSettings):
    """Find files within a specified size range.

    This function takes a list of backed up files, a minimum size in megabytes, and a maximum size in megabytes.
    It iterates through the list of files, converts the file size from the XML to a number, and compares it to the
    specified size range. If a file's size falls within the range, it is added to the result list.

    Args:
        backed_up_files (list): A list of tuples representing backed up files. Each tuple should contain at least
            two elements, where the first element is the file name and the second element is the file size in the
            format "<number> <unit>". For example, ("file.txt", "10 Mio").
        min_size_verification_mb (int): The minimum file size in megabytes.
        max_size_verification_mb (int): The maximum file size in megabytes.

    Returns:
        list: A list of file names that fall within the specified size range.
    """
    logger.debug(f"Finding files in archive between min and max sizes: {config_settings.min_size_verification_mb}MB and {config_settings.max_size_verification_mb}MB")
    files = []
    max_size = config_settings.max_size_verification_mb
    min_size = config_settings.min_size_verification_mb
    dar_sizes = {
        "o"   : 1,
        "kio" : 1024,
        "Mio" : 1024 * 1024,
        "Gio" : 1024 * 1024 * 1024,
        "Tio" : 1024 * 1024 * 1024 * 1024
     }
    pattern = r'(\d+)\s*(\w+)'
    for tuple in backed_up_files:
        if tuple is not None and len(tuple) >= 2  and tuple[0] is not None and tuple[1] is not None:
            logger.trace("tuple from dar xml list: {tuple}")
            match = re.match(pattern, tuple[1])
            if match:
                number = int(match.group(1))
                unit = match.group(2).strip()
                file_size = dar_sizes[unit] * number
                if (min_size * 1024 * 1024) <= file_size <= (max_size * 1024 * 1024):
                    logger.trace(f"File found between min and max sizes: {tuple}")
                    files.append(tuple[0])
    return files


def verify(args: argparse.Namespace, backup_file: str, backup_definition: str, config_settings: ConfigSettings):
    """
    Verify the integrity of a DAR backup by performing the following steps:
    1. Run an archive integrity test on the backup file.
    2. Retrieve the list of backed up files.
    3. Find files within def perform_backup(args, ConfigSettings config_settings, backup_d, backup_dir, test_restore_dir, backup_type, min_size_verification_mb, max_size_verification_mb, no_files_verification):file and compare it with the original file.

    Args:
        args (object): Command-line arguments.
        backup_file (str): Path to the DAR backup file.
        backup_definition (str): Path to the backup definition file.
        ConfigSettings (object): An instance of the ConfigSettings class.

    Returns:
        True if the verification process completes successfully, False otherwise.

    Raises:
        Exception: If an error occurs during the verification process.
        PermissionError: If a permission error occurs while comparing files.
    """
    result = True
    command = ['dar', '-t', backup_file, '-N', '-Q']
 
 
    log_basename = os.path. dirname(config_settings.logfile_location)
    logfile = os.path.basename(config_settings.logfile_location)[:-4] + "-commands.log"
    log_path = os.path.join( log_basename, logfile)

    # wrap a progress bar around the dar command
    stop_event = Event()
    session_marker = f"=== START BACKUP SESSION: {int(time())} ==="
    get_logger(command_output_logger=True).info(session_marker)

    progress_thread = threading.Thread(
        target=show_log_driven_bar,
        args=(log_path, stop_event, session_marker),
        daemon=True
    )
    progress_thread.start()
    try:
        process = runner.run(command, timeout = config_settings.command_timeout_secs)
    except Exception as e:
        print(f"[!] Backup failed: {e}")
        raise
    finally:
        stop_event.set()
        progress_thread.join()


    if process.returncode == 0:
        logger.info("Archive integrity test passed.")
    else:
        raise Exception(str(process))

    if args.do_not_compare:
        return result

    backed_up_files = get_backed_up_files(backup_file, config_settings.backup_dir) 

    files = find_files_between_min_and_max_size(backed_up_files, config_settings)
    if len(files) == 0:
        logger.info(f"No files between {config_settings.min_size_verification_mb}MB and {config_settings.max_size_verification_mb}MB for verification, skipping")
        return result

    # find Root path in backup definition
    with open(backup_definition, 'r') as f:
        backup_definition_content = f.readlines()
        logger.debug(f"Backup definition: '{backup_definition}', content:\n{backup_definition_content}")
    root_path = None
    for line in backup_definition_content:
        line = line.strip()
        match = re.match(r'^\s*-R\s+(.*)', line)
        if match:
            root_path = match.group(1).strip()
            break
    if root_path is None:
        msg = f"No Root (-R) path found in the backup definition file: '{backup_definition}', restore verification skipped"
        raise BackupError(msg)



    no_files_verification = config_settings.no_files_verification
    if len(files) < config_settings.no_files_verification:
        no_files_verification = len(files)
    random_files = random.sample(files, no_files_verification)
    for restored_file_path in random_files:
        try:
            args.verbose and logger.info(f"Restoring file: '{restored_file_path}' from backup to: '{config_settings.test_restore_dir}' for file comparing")
            command = ['dar', '-x', backup_file, '-g', restored_file_path.lstrip("/"), '-R', config_settings.test_restore_dir, '--noconf',  '-Q', '-B', args.darrc, 'restore-options']
            args.verbose and logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
            process = runner.run(command, timeout = config_settings.command_timeout_secs)    
            if process.returncode != 0:
                raise Exception(str(process))

            if filecmp.cmp(os.path.join(config_settings.test_restore_dir, restored_file_path.lstrip("/")), os.path.join(root_path, restored_file_path.lstrip("/")), shallow=False):
                args.verbose and logger.info(f"Success: file '{restored_file_path}' matches the original")
            else:
                result = False
                logger.error(f"Failure: file '{restored_file_path}' did not match the original")
        except PermissionError:
            result = False
            logger.exception(f"Permission error while comparing files, continuing....")
            logger.error("Exception details:", exc_info=True)
    return result



def restore_backup(backup_name: str, config_settings: ConfigSettings, restore_dir: str, darrc: str, selection: str =None):
    """
    Restores a backup file to a specified directory.

    Args:
        backup_name (str): The base name of the backup file, without the "slice number.dar"
        backup_dir (str): The directory where the backup file is located.
        restore_dir (str): The directory where the backup should be restored to.
        selection (str, optional): A selection criteria to restore specific files or directories. Defaults to None.
    """
    results: List[tuple] = []
    try:
        backup_file = os.path.join(config_settings.backup_dir, backup_name)
        command = ['dar', '-x', backup_file, '-wa', '-/ Oo', '--noconf', '-Q']
        if "_FULL_" in backup_name:
            command.append('-D')
        if restore_dir:
            if not os.path.exists(restore_dir):
                os.makedirs(restore_dir)
            command.extend(['-R', restore_dir])
        else:
            raise RestoreError("Restore directory ('-R <dir>') not specified")
        if selection:
            selection_criteria = shlex.split(selection)
            command.extend(selection_criteria)
        command.extend(['-B', darrc,  'restore-options'])  # the .darrc `restore-options` section
        logger.info(f"Running restore command: {' '.join(map(shlex.quote, command))}")
        process = runner.run(command, timeout = config_settings.command_timeout_secs)
        if process.returncode == 0:
            logger.info(f"Restore completed successfully to: '{restore_dir}'")
        else:
            logger.error(f"Restore command failed: \n ==> stdout: {process.stdout}, \n ==> stderr: {process.stderr}")
            raise RestoreError(str(process))
    except subprocess.CalledProcessError as e:
        raise RestoreError(f"Restore command failed: {e}") from e
    except OSError as e:
        logger.error(f"Failed to create restore directory: {e}")
        raise RestoreError("Could not create restore directory")
    except Exception as e:
        raise RestoreError(f"Unexpected error during restore: {e}") from e

    return results


def get_backed_up_files(backup_name: str, backup_dir: str):
    """
    Retrieves the list of backed up files from a DAR archive.

    Args:
        backup_name (str): The name of the DAR archive.
        backup_dir (str): The directory where the DAR archive is located.

    Returns:
        list: A list of file paths for all backed up files in the DAR archive.
    """
    logger.debug(f"Getting backed up files in xml from DAR archive: '{backup_name}'")
    backup_path = os.path.join(backup_dir, backup_name)
    try:
        command = ['dar', '-l', backup_path, '--noconf', '-am', '-as', "-Txml" , '-Q']
        logger.debug(f"Running command: {' '.join(map(shlex.quote, command))}")
        command_result = runner.run(command)
        # Parse the XML data
        file_paths = find_files_with_paths(command_result.stdout)
        return file_paths
    except subprocess.CalledProcessError as e:
        logger.error(f"Error listing backed up files from DAR archive: '{backup_name}'")
        raise BackupError(f"Error listing backed up files from DAR archive: '{backup_name}'") from e
    except Exception as e:
        raise RuntimeError(f"Unexpected error listing backed up files from DAR archive: '{backup_name}'") from e


def list_contents(backup_name, backup_dir, selection=None):
    """
    Lists the contents of a backup.

    Args:
        backup_name (str): The name of the backup.
        backup_dir (str): The directory where the backup is located.
        selection (str, optional): The selection criteria for listing specific contents. Defaults to None.

    Returns:
        None
    """
    backup_path = os.path.join(backup_dir, backup_name)

    try:
        command = ['dar', '-l', backup_path, '--noconf',  '-am', '-as', '-Q']
        if selection:
            selection_criteria = shlex.split(selection)
            command.extend(selection_criteria)
        process = runner.run(command)
        stdout,stderr = process.stdout, process.stderr
        if process.returncode != 0:
            logger.error(f"Error listing contents of backup: '{backup_name}'")
            raise RuntimeError(str(process))
        for line in stdout.splitlines():
            if "[--- REMOVED ENTRY ----]" in line or "[Saved]" in line:
                print(line)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error listing contents of backup: '{backup_name}'")
        raise BackupError(f"Error listing contents of backup: '{backup_name}'") from e  
    except Exception as e:
        raise RuntimeError(f"Unexpected error listing contents of backup: '{backup_name}'") from e  




def create_backup_command(backup_type: str, backup_file: str, darrc: str, backup_definition_path: str, latest_base_backup: str = None) -> List[str]:
    """
    Generate the backup command for the specified backup type.

    Args:
        backup_type (str): The type of backup (FULL, DIFF, INCR).
        backup_file (str): The backup file path. Example: /path/to/example_2021-01-01_FULL
        darrc (str): Path to the .darrc configuration file.
        backup_definition_path (str): Path to the backup definition file.
        latest_base_backup (str, optional): Path to the latest base backup for DIFF or INCR types.

    Returns:
        List[str]: The constructed backup command.
    """
    base_command = ['dar', '-c', backup_file, "-N", '-B', darrc, '-B', backup_definition_path, '-Q', "compress-exclusion", "verbose"]
    
    if backup_type in ['DIFF', 'INCR']:
        if not latest_base_backup:
            raise ValueError(f"Base backup is required for {backup_type} backups.")
        base_command.extend(['-A', latest_base_backup])
    
    return base_command



def perform_backup(args: argparse.Namespace, config_settings: ConfigSettings, backup_type: str) -> List[str]:
    """
    Perform backup operation.

    Args:
        args: Command-line arguments.
        config_settings: An instance of the ConfigSettings class.
        backup_type: Type of backup (FULL, DIFF, INCR).

    Returns:
      List[tuples] - each tuple consists of (<str message>, <exit code>)
    """
    backup_definitions = []
    results: List[tuple] = []

    # Gather backup definitions
    if args.backup_definition:
        if '_' in args.backup_definition:
            msg = f"Skipping backup definition: '{args.backup_definition}' due to '_' in name"
            logger.error(msg)
            results.append((msg, 1))
            return results
        backup_definitions.append((os.path.basename(args.backup_definition).split('.')[0], os.path.join(config_settings.backup_d_dir, args.backup_definition)))
    else:
        for root, _, files in os.walk(config_settings.backup_d_dir):
            for file in files:
                if '_' in file:
                    msg = f"Skipping backup definition: '{file} due to '_' in: name"
                    logger.error(msg)
                    results.append((msg, 1))
                    continue
                backup_definitions.append((file.split('.')[0], os.path.join(root, file)))

    for backup_definition, backup_definition_path in backup_definitions:
        try:
            date = datetime.now().strftime('%Y-%m-%d')
            backup_file = os.path.join(config_settings.backup_dir, f"{backup_definition}_{backup_type}_{date}")

            if os.path.exists(backup_file + '.1.dar'):
                msg = f"Backup file {backup_file}.1.dar already exists. Skipping backup [1]."
                logger.error(msg)
                results.append((msg, 1))
                continue

            latest_base_backup = None
            if backup_type in ['DIFF', 'INCR']:
                base_backup_type = 'FULL' if backup_type == 'DIFF' else 'DIFF'

                if args.alternate_reference_archive:
                    latest_base_backup = os.path.join(config_settings.backup_dir, args.alternate_reference_archive)
                    logger.info(f"Using alternate reference archive: {latest_base_backup}")
                    if not os.path.exists(latest_base_backup + '.1.dar'):
                        msg = f"Alternate reference archive: \"{latest_base_backup}.1.dar\" does not exist, exiting..."
                        logger.error(msg)
                        results.append((msg, 1))
                        return results
                else:
                    base_backups = sorted(
                        [f for f in os.listdir(config_settings.backup_dir) if f.startswith(f"{backup_definition}_{base_backup_type}_") and f.endswith('.1.dar')],
                        key=lambda x: datetime.strptime(x.split('_')[-1].split('.')[0], '%Y-%m-%d')
                    )
                    if not base_backups:
                        msg = f"No {base_backup_type} backup found for {backup_definition}. Skipping {backup_type} backup."
                        results.append((msg, 1))
                        continue
                    latest_base_backup = os.path.join(config_settings.backup_dir, base_backups[-1].rsplit('.', 2)[0])

            # Generate the backup command
            command = create_backup_command(backup_type, backup_file, args.darrc, backup_definition_path, latest_base_backup)

            # Perform backup
            backup_result = generic_backup(backup_type, command, backup_file, backup_definition_path, args.darrc, config_settings, args)

            if not isinstance(backup_result, list) or not all(isinstance(i, tuple) and len(i) == 2 for i in backup_result):
                logger.error("Unexpected return format from generic_backup")
                backup_result = [("Unexpected return format from generic_backup", 1)]

            results.extend(backup_result)
            logger.info("Starting verification...")
            verify_result = verify(args, backup_file, backup_definition_path, config_settings)
            if verify_result:   
                logger.info("Verification completed successfully.")
            else:
                msg = f"Verification of '{backup_file}' failed."
                logger.error(msg)
                results.append((msg, 1))
            logger.info("Generate par2 redundancy files.")
            generate_par2_files(backup_file, config_settings, args)
            logger.info("par2 files completed successfully.")

        except Exception as e:
            results.append((repr(e), 1))
            logger.exception(f"Error during {backup_type} backup process, continuing to next backup definition.")

    logger.trace(f"perform_backup() results[]: {results}")
    return results

def generate_par2_files(backup_file: str, config_settings: ConfigSettings, args):
    """
    Generate PAR2 files for a given backup file in the specified backup directory.

    Args:
        backup_file (str): The name of the backup file.
        config_settings: The configuration settings object.
        args: The command-line arguments object.

    Raises:
        subprocess.CalledProcessError: If the par2 command fails to execute.

    Returns:
        None
    """
    # Regular expression to match DAR slice files
    dar_slice_pattern = re.compile(rf"{re.escape(os.path.basename(backup_file))}\.([0-9]+)\.dar")

    # List of DAR slice files to be processed
    dar_slices: List[str] = []

    for filename in os.listdir(config_settings.backup_dir):
        match = dar_slice_pattern.match(filename)
        if match:
            dar_slices.append(filename)

    # Sort the DAR slices based on the slice number
    dar_slices.sort(key=lambda x: int(dar_slice_pattern.match(x).group(1)))
    number_of_slices = len(dar_slices)
    counter = 1

    for slice_file in dar_slices:
        file_path = os.path.join(config_settings.backup_dir, slice_file)
    
        logger.info(f"{counter}/{number_of_slices}: Now generating par2 files for {file_path}")

        # Run the par2 command to generate redundancy files with error correction
        command = ['par2', 'create', f'-r{config_settings.error_correction_percent}', '-q', '-q', file_path]
        process = runner.run(command, timeout = config_settings.command_timeout_secs)

        if process.returncode == 0:
            logger.info(f"{counter}/{number_of_slices}: Done")
        else:
            logger.error(f"Error generating par2 files for {file_path}")
            raise subprocess.CalledProcessError(process.returncode, command)
        counter += 1



def filter_darrc_file(darrc_path):
    """
    Filters the .darrc file to remove lines containing the options: -vt, -vs, -vd, -vf, and -va.
    The filtered version is stored in a uniquely named file in the home directory of the user running the script.
    The file permissions are set to 440.
    
    Params:
      darrc_path: Path to the original .darrc file.
    
    Raises:
      RuntimeError if something went wrong

    Returns:
      Path to the filtered .darrc file.
    """
    # Define options to filter out
    options_to_remove = {"-vt", "-vs", "-vd", "-vf", "-va"}

    # Get the user's home directory
    home_dir = os.path.expanduser("~")

    # Create a unique file name in the home directory
    filtered_darrc_path = os.path.join(home_dir, f"filtered_darrc_{next(tempfile._get_candidate_names())}.darrc")

    try:
        with open(darrc_path, "r") as infile, open(filtered_darrc_path, "w") as outfile:
            for line in infile:
                # Check if any unwanted option is in the line
                if not any(option in line for option in options_to_remove):
                    outfile.write(line)
        
        # Set file permissions to 440 (read-only for owner and group, no permissions for others)
        os.chmod(filtered_darrc_path, 0o440)

        return filtered_darrc_path

    except Exception as e:
        # If anything goes wrong, clean up the temp file if it was created
        if os.path.exists(filtered_darrc_path):
            os.remove(filtered_darrc_path)
        raise RuntimeError(f"Error filtering .darrc file: {e}")




def show_examples():
    examples = """
FULL back of all backup definitions in backup.d:
  'python3 dar-backup.py  --full-backup'

FULL back of a single backup definition in backup.d
  'python3 dar-backup.py --full-backup -d <name of file in backup.d/>'

DIFF backup (differences to the latest FULL) of all backup definitions:
  'python3 dar-backup.py --differential-backup'

DIFF back of a single backup definition in backup.d
  'python3 dar-backup.py --differential-backup -d <name of file in backup.d/>'
  
INCR backup (differences to the latest DIFF) of all backup definitions:
  'python3 dar-backup.py --incremental-backup'

INCR back of a single backup definition in backup.d
  'python3 dar-backup.py --incremental-backup -d <name of file in backup.d/>'
  
--alternate-reference-archive (useful if the calculated archive is broken)
    Use this to specify a different reference archive for DIFF or INCR backups.
    The specified archive can be any regardsless of type,  name does not include the slice number.
    Example: 'python3 dar-backup.py --differential-backup --alternate-reference-archive <name of dar archive>'

--log-level
    "trace" logs output from programs (typically dar and par2) run in a subprocess
    "debug" logs various statuses and notices to better understand how to script works


--selection

    --selection takes dar file selection options inside a quoted string.
    
    💡 Shell quoting matters! Always wrap the entire selection string in double quotes to avoid shell splitting. 

    ✅ Use:   --selection="-I '*.NEF'"
    ❌ Avoid: --selection "-I '*.NEF'" → may break due to how your shell parses it.

    Examples:
    1)
    select file names with "Z50_" in file names:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-I '*Z50_*'"
    2)
    Filter out *.xmp files:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-X '*.xmp'"
    
    3)
    Include all files in a directory:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-g 'path/to/a/dir'"

    4)
    Exclude a directory:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-P 'path/to/a/dir'"

    See dar documentation on file selection: http://dar.linux.free.fr/doc/man/dar.html#COMMANDS%20AND%20OPTIONS
"""
    print(examples)



def print_markdown(source: str, from_string: bool = False, pretty: bool = True):
    """
    Print Markdown content either from a file or directly from a string.
    
    Args:
        source: Path to the file or Markdown string itself.
        from_string: If True, treat `source` as Markdown string instead of file path.
        pretty: If True, render with rich formatting if available.
    """
    import os
    import sys

    content = ""
    if from_string:
        content = source
    else:
        if not os.path.exists(source):
            print(f"❌ File not found: {source}")
            sys.exit(1)
        with open(source, "r", encoding="utf-8") as f:
            content = f.read()

    if pretty:
        try:
            from rich.console import Console
            from rich.markdown import Markdown
            console = Console()
            console.print(Markdown(content))
        except ImportError:
            print("⚠️ 'rich' not installed. Falling back to plain text.\n")
            print(content)
    else:
        print(content)



def print_changelog(path: str = None, pretty: bool = True):
    if path is None:
        path = Path(__file__).parent / "Changelog.md"
    print_markdown(str(path), pretty=pretty)


def print_readme(path: str = None, pretty: bool = True):
    if path is None:
        path = Path(__file__).parent / "README.md"
    print_markdown(str(path), pretty=pretty)



def main():
    global logger, runner
    results: List[(str,int)] = []  # a list op tuples (<msg>, <exit code>)

    MIN_PYTHON_VERSION = (3, 9)
    if version_info < MIN_PYTHON_VERSION:
        stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
        exit(1)

    parser = argparse.ArgumentParser(description="Backup, verify & redundancy using dar and par2.")
    parser.add_argument('-F', '--full-backup', action='store_true', help="Perform a full backup.")
    parser.add_argument('-D', '--differential-backup', action='store_true', help="Perform differential backup.")
    parser.add_argument('-I', '--incremental-backup', action='store_true', help="Perform incremental backup.")
    parser.add_argument('-d', '--backup-definition', help="Specific 'recipe' to select directories and files.").completer = backup_definition_completer
    parser.add_argument('--alternate-reference-archive', help="DIFF or INCR compared to specified archive.").completer = list_archive_completer
    parser.add_argument('-c', '--config-file', type=str, help="Path to 'dar-backup.conf'", default='~/.config/dar-backup/dar-backup.conf')
    parser.add_argument('--darrc', type=str, help='Optional path to .darrc')
    parser.add_argument('-l', '--list', action='store_true', help="List available archives.").completer = list_archive_completer
    parser.add_argument('--list-contents', help="List the contents of the specified archive.").completer = list_archive_completer
    parser.add_argument('--selection', type=str, help="Selection string to pass to 'dar', e.g. --selection=\"-I '*.NEF'\"")
#    parser.add_argument('-r', '--restore', nargs=1, type=str, help="Restore specified archive.")
    parser.add_argument('-r', '--restore', type=str, help="Restore specified archive.").completer = list_archive_completer
    parser.add_argument('--restore-dir',   type=str, help="Directory to restore files to.")
    parser.add_argument('--verbose', action='store_true', help="Print various status messages to screen")
    parser.add_argument('--suppress-dar-msg', action='store_true', help="cancel dar options in .darrc: -vt, -vs, -vd, -vf and -va")
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`", default="info")
    parser.add_argument('--log-stdout', action='store_true', help='also print log messages to stdout')
    parser.add_argument('--do-not-compare', action='store_true', help="do not compare restores to file system")
    parser.add_argument('--examples', action="store_true", help="Examples of using dar-backup.py.")
    parser.add_argument("--readme", action="store_true", help="Print README.md to stdout and exit.")
    parser.add_argument("--readme-pretty", action="store_true", help="Print README.md to stdout with Markdown styling and exit.")
    parser.add_argument("--changelog", action="store_true", help="Print Changelog.md to stdout and exit.")
    parser.add_argument("--changelog-pretty", action="store_true", help="Print Changelog.md to stdout with Markdown styling and exit.")
    parser.add_argument('-v', '--version', action='store_true', help="Show version and license information.")
    
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if args.version:
        show_version()
        exit(0)
    elif args.examples:
        show_examples()
        exit(0)
    elif args.readme:
        print_readme(None, pretty=False)
        exit(0)
    elif args.readme_pretty:
        print_readme(None, pretty=True)
        exit(0)
    elif args.changelog:
        print_changelog(None, pretty=False)
        exit(0)
    elif args.changelog_pretty:
        print_changelog(None, pretty=True)
        exit(0)



    if not args.config_file:
        print(f"Config file not specified, exiting", file=stderr)
        exit(1) 
    
    config_settings_path = os.path.expanduser(os.path.expandvars(args.config_file))
    if not os.path.exists(config_settings_path):
        print(f"Config file {args.config_file} does not exist.", file=stderr)
        exit(127)

    args.config_file = config_settings_path
    config_settings = ConfigSettings(args.config_file)

    command_output_log = config_settings.logfile_location.replace("dar-backup.log", "dar-backup-commands.log")
    if command_output_log == config_settings.logfile_location:
        print(f"Error: logfile_location in {args.config_file} does not end at 'dar-backup.log', exiting", file=stderr)

    logger = setup_logging(config_settings.logfile_location, command_output_log, args.log_level, args.log_stdout, logfile_max_bytes=config_settings.logfile_max_bytes, logfile_backup_count=config_settings.logfile_backup_count)
    command_logger = get_logger(command_output_logger = True)
    runner = CommandRunner(logger=logger, command_logger=command_logger)


    try:
        if not args.darrc:
            current_script_dir = os.path.dirname(os.path.abspath(__file__))
            args.darrc = os.path.join(current_script_dir, ".darrc")

        darrc_file = os.path.expanduser(os.path.expandvars(args.darrc))
        if os.path.exists(darrc_file) and os.path.isfile(darrc_file):
            logger.debug(f"Using .darrc: {args.darrc}")                
        else:
            logger.error(f"Supplied .darrc: '{args.darrc}' does not exist or is not a file, exiting", file=stderr)
            exit(127)

        if args.suppress_dar_msg:
            logger.info("Suppressing dar messages, do not use options: -vt, -vs, -vd, -vf, -va")
            args.darrc = filter_darrc_file(args.darrc)
            logger.debug(f"Filtered .darrc file: {args.darrc}")

        start_msgs: List[Tuple[str, str]] = []

        start_time=int(time())
        start_msgs.append((f"{show_scriptname()}:", about.__version__))
        logger.info(f"START TIME: {start_time}")
        logger.debug(f"Command line:\n{get_invocation_command_line()}")
        logger.debug(f"`Args`:\n{args}")
        logger.debug(f"`Config_settings`:\n{config_settings}")
        dar_properties = get_binary_info(command='dar')
        start_msgs.append(('dar path:', dar_properties['path']))
        start_msgs.append(('dar version:', dar_properties['version']))

        file_dir =  os.path.normpath(os.path.dirname(__file__))
        start_msgs.append(('Script directory:', os.path.abspath(file_dir)))
        start_msgs.append(('Config file:', os.path.abspath(args.config_file)))
        start_msgs.append((".darrc location:", args.darrc))

        args.full_backup         and start_msgs.append(("Type of backup:", "FULL"))
        args.differential_backup and start_msgs.append(("Type of backup:", "DIFF"))
        args.incremental_backup  and start_msgs.append(("Type of backup:", "INCR"))
        args.verbose and args.backup_definition   and start_msgs.append(("Backup definition:", args.backup_definition))
        if args.alternate_reference_archive:
            args.verbose and start_msgs.append(("Alternate ref archive:", args.alternate_reference_archive))
        args.verbose and start_msgs.append(("Backup.d dir:", config_settings.backup_d_dir))
        args.verbose and start_msgs.append(("Backup dir:", config_settings.backup_dir))

        restore_dir = args.restore_dir if args.restore_dir else config_settings.test_restore_dir
        args.verbose and start_msgs.append(("Restore dir:", restore_dir))

        args.verbose and start_msgs.append(("Logfile location:", config_settings.logfile_location))
        args.verbose and start_msgs.append(("Logfile max size (bytes):", config_settings.logfile_max_bytes))
        args.verbose and start_msgs.append(("Logfile backup count:", config_settings.logfile_backup_count))

        args.verbose and start_msgs.append(("PAR2 enabled:", config_settings.par2_enabled))
        args.verbose and start_msgs.append(("--do-not-compare:", args.do_not_compare))

        highlight_keywords = ["--do-not", "alternate"] # TODO: add more dangerous keywords
        print_aligned_settings(start_msgs, quiet=not args.verbose, highlight_keywords=highlight_keywords)

        # sanity check
        if args.backup_definition and not os.path.exists(os.path.join(config_settings.backup_d_dir, args.backup_definition)):
            logger.error(f"Backup definition: '{args.backup_definition}' does not exist, exiting")
            exit(127)
        if args.backup_definition and '_' in args.backup_definition:
            logger.error(f"Backup definition: '{args.backup_definition}' contains '_', exiting")
            exit(1)


        requirements('PREREQ', config_settings)

        if args.list:
            list_backups(config_settings.backup_dir, args.backup_definition)
        elif args.full_backup and not args.differential_backup and not args.incremental_backup:
            results.extend(perform_backup(args, config_settings, "FULL"))
        elif args.differential_backup and not args.full_backup and not args.incremental_backup:
            results.extend(perform_backup(args, config_settings, "DIFF"))
        elif args.incremental_backup  and not args.full_backup and not args.differential_backup:
            results.extend(perform_backup(args, config_settings, "INCR"))
            logger.debug(f"results from perform_backup(): {results}")
        elif args.list_contents:
            list_contents(args.list_contents, config_settings.backup_dir, args.selection)
        elif args.restore:
            logger.debug(f"Restoring {args.restore} to {restore_dir}")
            results.extend(restore_backup(args.restore, config_settings, restore_dir, args.darrc, args.selection))
        else:
            parser.print_help()

        logger.debug(f"results[]: {results}")

        requirements('POSTREQ', config_settings)


    except Exception as e:
        logger.error("Exception details:", exc_info=True)
        results.append((repr(e), 1))
    finally:
        end_time=int(time())
        logger.info(f"END TIME: {end_time}")
        # Clean up
        if os.path.exists(args.darrc) and (os.path.dirname(args.darrc) == os.path.expanduser("~")):
            if os.path.basename(args.darrc).startswith("filtered_darrc_"):
                if os.remove(args.darrc):
                    logger.debug(f"Removed filtered .darrc: {args.darrc}")


    # Determine exit code 
    error = False
    logger.debug(f"results[]: {results}")
    if results:
        i = 0
        for result in results:
            if isinstance(result, tuple) and len(result) == 2:
                msg, exit_code = result
                logger.debug(f"exit code: {exit_code}, msg: {msg}")
                if exit_code > 0:
                    error = True
                    args.verbose and print(msg)
            else:
                logger.error(f"not correct result type: {result}, which must be a tuple (<msg>, <exit_code>)")
            i=i+1
            
    console = Console()
    if error:
        if args.verbose:
            console.print(Text("Errors encountered", style="bold red"))
        exit(1)
    else:
        if args.verbose:
            console.print(Text("Success: all backups completed", style="bold green"))
        exit(0)

    
if __name__ == "__main__":
    main()
