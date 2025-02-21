#!/usr/bin/env python3

import argparse
import datetime
import filecmp

import os
import random
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET


from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path
from time import time
from typing import List

from . import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import list_backups
from dar_backup.util import run_command
from dar_backup.util import setup_logging
from dar_backup.util import BackupError
from dar_backup.util import RestoreError


logger = None

def generic_backup(type: str, command: List[str], backup_file: str, backup_definition: str, darrc: str,  config_settings: ConfigSettings, args: argparse.Namespace):
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
        BackupError: If an error occurs during the backup process.
    """
    logger.info(f"===> Starting {type} backup for {backup_definition}")
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        process = run_command(command, config_settings.command_timeout_secs)
        if process.returncode == 0:
            logger.info(f"{type} backup completed successfully.")
        elif process.returncode == 5:
            logger.warning("Backup completed with some files not backed up, this can happen if files are changed/deleted during the backup.")
        else:
            raise Exception(str(process))

        if process.returncode == 0 or process.returncode == 5:
            add_catalog_command = ['manager', '--add-specific-archive' ,backup_file, '--config-file', args.config_file]
            command_result = run_command(add_catalog_command, config_settings.command_timeout_secs)
            if command_result.returncode == 0:
                logger.info(f"Catalog for archive '{backup_file}' added successfully to its manager.")
            else:
                logger.error(f"Catalog for archive '{backup_file}' not added.")

    except subprocess.CalledProcessError as e:
        logger.error(f"Backup command failed: {e}")
        raise BackupError(f"Backup command failed: {e}") from e
    except Exception as e:
        logger.exception(f"Unexpected error during backup")
        raise BackupError(f"Unexpected error during backup: {e}") from e
 

# Function to recursively find <File> tags and build their full paths
def find_files_with_paths(element: ET, current_path=""):
    """
    Recursively finds files within a directory element and returns a list of file paths with their sizes.

    Args:
        element (Element): The directory element to search within.
        current_path (str, optional): The current path of the directory element. Defaults to "".

    Returns:
        list: A list of tuples containing file paths and their sizes.
    """
    logger.debug(f"Recursively generate list of tuples with file paths and sizes for File elements in dar xml output")
    files = []
    if element.tag == "Directory":
        current_path = f"{current_path}/{element.get('name')}"
    for child in element:
        if child.tag == "File":
            file_path = (f"{current_path}/{child.get('name')}", child.get('size'))  # tuple (filepath, size)
            files.append(file_path)
        elif child.tag == "Directory":
            files.extend(find_files_with_paths(child, current_path))
    return files



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
    command = ['dar', '-t', backup_file, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    process = run_command(command, config_settings.command_timeout_secs)
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

    with open(backup_definition, 'r') as f:
        backup_definition_content = f.readlines()
        logger.debug(f"Backup definition: '{backup_definition}', content:\n{backup_definition_content}")
    # Initialize a variable to hold the path after "-R"
    root_path = None
    for line in backup_definition_content:
        line = line.strip()
        if line.startswith("-R"):
            root_path = line.split("-R", 1)[1].strip()
            break
    if root_path is None:
        logger.warning("No Root (-R) path specified in the backup definition file.")

    no_files_verification = config_settings.no_files_verification
    if len(files) < config_settings.no_files_verification:
        no_files_verification = len(files)
    random_files = random.sample(files, no_files_verification)
    for restored_file_path in random_files:
        try:
            logger.info(f"Restoring file: '{restored_file_path}' from backup to: '{config_settings.test_restore_dir}' for file comparing")
            command = ['dar', '-x', backup_file, '-g', restored_file_path.lstrip("/"), '-R', config_settings.test_restore_dir, '-Q', '-B', args.darrc, 'restore-options']
            logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
            process = run_command(command, config_settings.command_timeout_secs)    
            if process.returncode != 0:
                raise Exception(str(process))

            if filecmp.cmp(os.path.join(config_settings.test_restore_dir, restored_file_path.lstrip("/")), os.path.join(root_path, restored_file_path.lstrip("/")), shallow=False):
                logger.info(f"Success: file '{restored_file_path}' matches the original")
            else:
                logger.error(f"Failure: file '{restored_file_path}' did not match the original")
                result = False
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
    backup_file = os.path.join(config_settings.backup_dir, backup_name)
    command = ['dar', '-x', backup_file, '-Q', '-D']
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
    try:
        process = run_command(command, config_settings.command_timeout_secs)
        if process.returncode == 0:
            logger.info(f"Restore completed successfully to: '{restore_dir}'")
        else:
            logger.error(f"Restore command failed: \n ==> stdout: {process.stdout}, \n ==> stderr: {process.stderr}")
            raise RestoreError(str(process))
    except subprocess.CalledProcessError as e:
        raise RestoreError(f"Restore command failed: {e}") from e
    except Exception as e:
        raise RestoreError(f"Unexpected error during restore: {e}") from e



def get_backed_up_files(backup_name: str, backup_dir: str):
    """
    Retrieves the list of backed up files from a DAR archive.

    Args:
        backup_name (str): The name of the DAR archive.
        backup_dir (str): The directory where the DAR archive is located.

    Returns:
        list: A list of file paths for all backed up files in the DAR archive.
    """
    logger.debug(f"Getting backed up files from DAR archive in xml: '{backup_name}'")
    backup_path = os.path.join(backup_dir, backup_name)
    try:
        command = ['dar', '-l', backup_path, '-am', '-as', "-Txml" , '-Q']
        logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
        process = run_command(command)
        # Parse the XML data
        root = ET.fromstring(process.stdout)
        output = None  # help gc
        # Extract full paths and file size for all <File> elements
        file_paths = find_files_with_paths(root)
        root = None # help gc
        logger.trace(str(process))
        logger.trace(file_paths)
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
        command = ['dar', '-l', backup_path, '-am', '-as', '-Q']
        if selection:
            selection_criteria = shlex.split(selection)
            command.extend(selection_criteria)
        logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
        process = run_command(command)
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



def perform_backup(args: argparse.Namespace, config_settings: ConfigSettings, backup_type: str):
    """
    Perform backup operation.

    Args:
        args: Command-line arguments.
        config_settings: An instance of the ConfigSettings class.
        backup_type: Type of backup (FULL, DIFF, INCR).
    """
    logger.debug(f"perform_backup({backup_type}) started")
    backup_definitions = []

    # Gather backup definitions
    if args.backup_definition:
        if '_' in args.backup_definition:
            logger.error(f"Skipping backup definition: '{args.backup_definition}' due to '_' in name")
            return
        backup_definitions.append((os.path.basename(args.backup_definition).split('.')[0], os.path.join(config_settings.backup_d_dir, args.backup_definition)))
    else:
        for root, _, files in os.walk(config_settings.backup_d_dir):
            for file in files:
                if '_' in file:
                    logger.error(f"Skipping backup definition: '{file}' due to '_' in name")
                    continue
                backup_definitions.append((file.split('.')[0], os.path.join(root, file)))

    for backup_definition, backup_definition_path in backup_definitions:
        try:
            date = datetime.now().strftime('%Y-%m-%d')
            backup_file = os.path.join(config_settings.backup_dir, f"{backup_definition}_{backup_type}_{date}")

            if os.path.exists(backup_file + '.1.dar'):
                logger.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
                continue

            latest_base_backup = None
            if backup_type in ['DIFF', 'INCR']:
                base_backup_type = 'FULL' if backup_type == 'DIFF' else 'DIFF'

                if args.alternate_reference_archive:
                    latest_base_backup = os.path.join(config_settings.backup_dir, args.alternate_reference_archive)
                    logger.info(f"Using alternate reference archive: {latest_base_backup}")
                    if not os.path.exists(latest_base_backup + '.1.dar'):
                        logger.error(f"Alternate reference archive: \"{latest_base_backup}.1.dar\" does not exist, exiting.")
                        sys.exit(1)
                else:
                    base_backups = sorted(
                        [f for f in os.listdir(config_settings.backup_dir) if f.startswith(f"{backup_definition}_{base_backup_type}_") and f.endswith('.1.dar')],
                        key=lambda x: datetime.strptime(x.split('_')[-1].split('.')[0], '%Y-%m-%d')
                    )
                    if not base_backups:
                        logger.warning(f"No {base_backup_type} backup found for {backup_definition}. Skipping {backup_type} backup.")
                        continue
                    latest_base_backup = os.path.join(config_settings.backup_dir, base_backups[-1].rsplit('.', 2)[0])

            # Generate the backup command
            command = create_backup_command(backup_type, backup_file, args.darrc, backup_definition_path, latest_base_backup)

            # Perform backup
            generic_backup(backup_type, command, backup_file, backup_definition_path, args.darrc, config_settings, args)

            logger.info("Starting verification...")
            verify_result = verify(args, backup_file, backup_definition_path, config_settings)
            if verify_result:   
                logger.info("Verification completed successfully.")
            else:
                logger.error("Verification failed.")

            
            logger.info("Generate par2 redundancy files.")
            generate_par2_files(backup_file, config_settings, args)
            logger.info("par2 files completed successfully.")
            

        except Exception as e:
            logger.exception(f"Error during {backup_type} backup process, continuing to next backup definition.")



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
        process = run_command(command, config_settings.command_timeout_secs)

        if process.returncode == 0:
            logger.info(f"{counter}/{number_of_slices}: Done")
        else:
            logger.error(f"Error generating par2 files for {file_path}")
            raise subprocess.CalledProcessError(process.returncode, command)
        counter += 1



def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {about.__version__}") 
    print(f"dar-backup.py source code is here: https://github.com/per2jensen/dar-backup")
    print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')


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
    --selection takes dar selection parameters between a pair of `"`. 

    Example: select file names with this date in file names "2024-07-01" in the
    directory "path/to/a/dir" where the path is relative to root of the backup.

    python3 dar-backup.py --restore <name of dar archive>  --selection "-I '*2024-07-01*' -g path/to/a/dir"

    See dar documentation on file selection: http://dar.linux.free.fr/doc/man/dar.html#COMMANDS%20AND%20OPTIONS
"""
    print(examples)



def requirements(type: str, config_setting: ConfigSettings):
    """
    Perform PREREQ or POSTREQ requisites.

    Args:
        type (str): The type of prereq (PREREQ, POSTREQ).
        config_settings (ConfigSettings): An instance of the ConfigSettings class.

    Raises:
        RuntimeError: If a subprocess invoked during the backup process exits with a non-zero status.
    """
    if str is None or config_setting is None:
        logger.error(f"requirements: {type} or config_setting is None, existing")
        raise RuntimeError(f"requirements: {type} or config_setting is None, existing")


    logger.info(f"Performing  {type}")
    if type in config_setting.config:
        for key in sorted(config_setting.config[type].keys()):
            script = config_setting.config[type][key]
            try:
                result = subprocess.run(script, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, check=True)
                logger.info(f"{type} {key}: '{script}' run, return code: {result.returncode}")
                logger.info(f"{type} stdout:\n{result.stdout}")
                if result.returncode != 0:
                    logger.error(f"{type} stderr:\n{result.stderr}")
                    raise RuntimeError(f"{type} {key}: '{script}' failed, return code: {result.returncode}")    
            except subprocess.CalledProcessError as e:
                logger.error(f"Error executing {key}: '{script}': {e}")
                raise e


def main():
    global logger 

    MIN_PYTHON_VERSION = (3, 9)
    if sys.version_info < MIN_PYTHON_VERSION:
        sys.stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Backup and verify using dar backup definitions.")
    parser.add_argument('-F', '--full-backup', action='store_true', help="Perform a full backup.")
    parser.add_argument('-D', '--differential-backup', action='store_true', help="Perform differential backup.")
    parser.add_argument('-I', '--incremental-backup', action='store_true', help="Perform incremental backup.")
    parser.add_argument('-d', '--backup-definition', help="Specific 'recipe' to select directories and files.")
    parser.add_argument('--alternate-reference-archive', help="DIFF or INCR compared to specified archive.")
    parser.add_argument('-c', '--config-file', type=str, help="Path to 'dar-backup.conf'", default='~/.config/dar-backup/dar-backup.conf')
    parser.add_argument('--darrc', type=str, help='Optional path to .darrc')
    parser.add_argument('--examples', action="store_true", help="Examples of using dar-backup.py.")
    parser.add_argument('-l', '--list', action='store_true', help="List available archives.")
    parser.add_argument('--list-contents', help="List the contents of the specified archive.")
    parser.add_argument('--selection', help="dar file selection for listing/restoring specific files/directories.")
#    parser.add_argument('-r', '--restore', nargs=1, type=str, help="Restore specified archive.")
    parser.add_argument('-r', '--restore', type=str, help="Restore specified archive.")
    parser.add_argument('--restore-dir',   type=str, help="Directory to restore files to.")
    parser.add_argument('--verbose', action='store_true', help="Print various status messages to screen")
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`", default="info")
    parser.add_argument('--log-stdout', action='store_true', help='also print log messages to stdout')
    parser.add_argument('--do-not-compare', action='store_true', help="do not compare restores to file system")
    parser.add_argument('-v', '--version', action='store_true', help="Show version and license information.")
    args = parser.parse_args()

    args.config_file = os.path.expanduser(args.config_file)
    config_settings = ConfigSettings(args.config_file)

    if args.version:
        show_version()
        sys.exit(0)
    elif args.examples:
        show_examples()
        sys.exit(0)

    logger = setup_logging(config_settings.logfile_location, args.log_level, args.log_stdout)

    if not args.darrc:
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        args.darrc = os.path.join(current_script_dir, ".darrc")

    if os.path.exists(args.darrc) and os.path.isfile(args.darrc):
        logger.debug(f"Using .darrc: {args.darrc}")                
    else:
        logger.error(f"Supplied .darrc: '{args.darrc}' does not exist or is not a file")


    try:
        start_time=int(time())
        logger.info(f"=====================================")
        logger.info(f"dar-backup.py started, version: {about.__version__}")
        logger.info(f"START TIME: {start_time}")
        logger.debug(f"`args`:\n{args}")
        logger.debug(f"`config_settings`:\n{config_settings}")

        file_dir =  os.path.normpath(os.path.dirname(__file__))
        args.verbose and (print(f"Script directory:  {file_dir}"))
        args.verbose and (print(f"Config file:       {args.config_file}"))
        args.verbose and args.full_backup         and (print(f"Type of backup: FULL"))
        args.verbose and args.differential_backup and (print(f"Type of backup: DIFF"))
        args.verbose and args.incremental_backup  and (print(f"Type of backup: INCR"))
        args.verbose and args.backup_definition   and (print(f"Backup definition: '{args.backup_definition}'"))
        if args.alternate_reference_archive:
            args.verbose and (print(f"Alternate ref archive: {args.alternate_reference_archive}"))
        args.verbose and (print(f"Backup.d dir:      {config_settings.backup_d_dir}"))
        args.verbose and (print(f"Backup dir:        {config_settings.backup_dir}"))

        restore_dir = args.restore_dir if args.restore_dir else config_settings.test_restore_dir
        args.verbose and (print(f"Restore dir:       {restore_dir}"))

        args.verbose and (print(f"Logfile location:  {config_settings.logfile_location}"))
        args.verbose and (print(f".darrc location:   {args.darrc}"))
        args.verbose and (print(f"PAR2 enabled:      {config_settings.par2_enabled}"))
        args.verbose and (print(f"--do-not-compare:  {args.do_not_compare}"))


        # sanity check
        if args.backup_definition and not os.path.exists(os.path.join(config_settings.backup_d_dir, args.backup_definition)):
            logger.error(f"Backup definition: '{args.backup_definition}' does not exist, exiting")
            sys.exit(1)
        if args.backup_definition and '_' in args.backup_definition:
            logger.error(f"Backup definition: '{args.backup_definition}' contains '_', exiting")
            sys.exit(1)


        requirements('PREREQ', config_settings)

        if args.list:
            list_backups(config_settings.backup_dir, args.backup_definition)
        elif args.full_backup and not args.differential_backup and not args.incremental_backup:
            perform_backup(args, config_settings, "FULL")
        elif args.differential_backup and not args.full_backup and not args.incremental_backup:
            perform_backup(args, config_settings, "DIFF")
        elif args.incremental_backup  and not args.full_backup and not args.differential_backup:
            perform_backup(args, config_settings, "INCR")
        elif args.list_contents:
            list_contents(args.list_contents, config_settings.backup_dir, args.selection)
        elif args.restore:
            logger.debug(f"Restoring {args.restore} to {restore_dir}")
            restore_backup(args.restore, config_settings, restore_dir, args.darrc, args.selection)
        else:
            parser.print_help()

        requirements('POSTREQ', config_settings)

        args.verbose and print("\033[1m\033[32mSUCCESS\033[0m No errors encountered")
        sys.exit(0)
    except Exception as e:
        logger.exception("An error occurred")
        logger.error("Exception details:", exc_info=True)
        args.verbose and print("\033[1m\033[31mErrors\033[0m encountered")
        sys.exit(1) 
    finally:
        end_time=int(time())
        logger.info(f"END TIME: {end_time}")

#    error_lines = extract_error_lines(config_settings.logfile_location, start_time, end_time)


if __name__ == "__main__":
    main()
