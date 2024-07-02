import argparse
import datetime
import subprocess
import sys
import os
import random
import filecmp
import logging
import shlex
import configparser
import functools
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

VERSION = "alpha-0.2"
ERRORS_ENCOUNTERED=[]
TRACE_LEVEL_NUM = 5
logger=None


# Check Python version compatibility
MIN_PYTHON_VERSION = (3, 7)
if sys.version_info < MIN_PYTHON_VERSION:
    sys.stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
    sys.exit(1)


def setup_logging(log_file, log_level):
    global logger

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

    logger.info("=======================")
    logger.info("`dar-backup.py` started")




def run_command(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        logger.trace(stdout)
        if process.returncode != 0:
            logger.error(stderr)
            raise Exception(f"Command: {" ".join(map(shlex.quote, command))} failed with return code {process.returncode}: {stderr}")
        else:
            logger.info(stderr)
        return stdout
    except Exception as e:
        logger.exception(f"Error running command:  {' '.join(map(shlex.quote, command))}: {e}")
        raise

def read_config(config_file):
    config = configparser.ConfigParser()
    try:
        config.read(config_file)
        logfile_location = config['MISC']['LOGFILE_LOCATION']
        max_size_verification_mb = config['MISC']['MAX_SIZE_VERIFICATION_MB']
        no_files_verification = config['MISC']['NO_FILES_VERIFICATION']

        backup_dir = config['DIRECTORIES']['BACKUP_DIR']
        Path(backup_dir).mkdir(parents=True, exist_ok=True)
        test_restore_dir = config['DIRECTORIES']['TEST_RESTORE_DIR']
        Path(test_restore_dir).mkdir(parents=True, exist_ok=True)
        backup_d = config['DIRECTORIES']['BACKUP.D_DIR']
        Path(backup_d).mkdir(parents=True, exist_ok=True)
    except KeyError as e:
        logger.error(f"Missing mandatory configuration field: {e}")
        sys.stderr.write(f"Error: Missing mandatory configuration field: {e}\n")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Error reading config file {config_file}: {e}")
        sys.stderr.write(f"Error: Unable to read the config file {config_file}: {e}\n")
        sys.exit(1)
    return logfile_location, backup_dir, test_restore_dir, backup_d, max_size_verification_mb, no_files_verification

def backup(backup_file, backup_definition):
    if os.path.exists(backup_file + '.1.dar'):
        logger.info(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logger.info("Backup completed successfully.")
    except Exception as e:
        ERRORS_ENCOUNTERED.append(f"Error processing FULL backup definition '{backup_definition}'")
        raise


def differential_backup(backup_file, backup_definition, base_backup_file):
    if os.path.exists(backup_file + '.1.dar'):
        logger.info(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-A', base_backup_file, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logger.info("Differential backup completed successfully.")
    except Exception as e:
        ERRORS_ENCOUNTERED.append(f"Error processing DIFF backup definition '{backup_definition}'")
        raise
    

def incremental_backup(backup_file, backup_definition, base_backup_file):
    if os.path.exists(backup_file + '.1.dar'):
        logger.info(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-A', base_backup_file, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logger.info("Incremental backup completed successfully.")
    except Exception as e:
        ERRORS_ENCOUNTERED.append(f"Error processing INCR backup definition '{backup_definition}'")
        raise


def find_files_under_xxMB(backed_up_files, max_size_verification_mb):
    files = []
    max_sixe = int(max_size_verification_mb)
    for file_path in backed_up_files:
        try:
            file_size = os.path.getsize(file_path)
            if file_size < max_sixe * 1024 * 1024:
                logger.trace(f"File under {max_sixe}MB: {file_path}")
                files.append(file_path)
        except Exception as e:
            logger.exception(f"Error accessing file {file_path}: {e}")
    return files


def verify(backup_file, backup_definition, test_restore_dir, backup_dir, max_size_verification_mb, no_files_verification):
    test_command = ['dar', '-t', backup_file, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, test_command))}")
    try:
        run_command(test_command)
        logger.info("Archive integrity test passed.")
    except Exception as e:
        ERRORS_ENCOUNTERED.append(f"Archive integrity test failed for {backup_file}")
        raise

    backed_up_files = get_backed_up_files(backup_file, backup_dir) 

    files = find_files_under_xxMB(backed_up_files, max_size_verification_mb)
    if len(files) == 0:
        logger.info(f"No files under {max_size_verification_mb}MB for verification, skipping")
        return

    with open(backup_definition, 'r') as f:
        backup_definition_content = f.readlines()
        logger.debug(f"Backup definition: '{backup_definition}', content:\n{backup_definition_content}")
    # Initialize a variable to hold the path after "-R"
    root_path = None
    # Iterate over the lines
    for line in backup_definition_content:
        line = line.strip()
        if line.startswith("-R"):
            # Capture the path which is after the space following "-R"
            root_path = line.split("-R", 1)[1].strip()
            break

    random_files = random.sample(files, int(no_files_verification))
    for restored_file_path in random_files:
        try:
            os.makedirs(os.path.dirname(restored_file_path), exist_ok=True)
        except Exception as e:
            logger.exception(f"Error creating directory for {restored_file_path}: {e}")
            continue
        

        command = ['dar', '-x', backup_file, '-g', restored_file_path.lstrip("/"), '-R', test_restore_dir, '-O', '-Q']
        logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
        try:
            run_command(command)
        except Exception as e:
            logger.exception(f"Error restoring file '{restored_file_path}' from backup {backup_file}: {e}")
            raise

        logger.info("Comparing backed-up file: " + os.path.join(test_restore_dir, restored_file_path.lstrip("/")) + " with " + os.path.join(root_path, restored_file_path.lstrip("/")))
        if not filecmp.cmp(                         os.path.join(test_restore_dir, restored_file_path.lstrip("/")),             os.path.join(root_path, restored_file_path.lstrip("/")), shallow=False):
           logger.error(f"File '{restored_file_path}' did not match the original after restoration.")
           ERRORS_ENCOUNTERED.append(f"Restore compare failure of {os.path.join(test_restore_dir, restored_file_path.lstrip("/"))}")

    
    logger.info("Verification of 3 random files under 10MB completed successfully.")


def list_backups(backup_dir, backup_definition=None):
    try:
        backups = set(f.rsplit('.', 2)[0] for f in os.listdir(backup_dir) if f.endswith('.dar'))
        if not backups:
            print("No backups available.")
            return

        if backup_definition:
            backups = [b for b in backups if b.startswith(backup_definition)]
        
        backups = sorted(backups, key=lambda x: datetime.strptime(x.split('_')[-1], '%Y-%m-%d'))

        for backup in backups:
            print(backup)
    except Exception as e:
        logger.exception(f"Error listing backups in directory {backup_dir}: {e}")
        sys.stderr.write(f"Error: Unable to list backups in directory {backup_dir}: {e}\n")


def restore_backup(backup_name, backup_dir, restore_dir, selection=None):
    backup_file = os.path.join(backup_dir, backup_name)
    command = ['dar', '-x', backup_file, '-O', '-Q', '-D']
    if restore_dir:
        if not os.path.exists(restore_dir):
            try:
                os.makedirs(restore_dir)
            except Exception as e:
                logger.exception(f"Error creating restore directory {restore_dir}: {e}")
                sys.stderr.write(f"Error: Unable to create restore directory {restore_dir}: {e}\n")
                sys.exit(1)
        command.extend(['-R', restore_dir])
    if selection:
        selection_criteria = shlex.split(selection)
        command.extend(selection_criteria)
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
    except Exception as e:
        logger.exception(f"Error during restore of {backup_name} to {restore_dir}: {e}. Exiting.")
        sys.stderr.write(f"Error: Restore operation failed for {backup_name}: {e}\n")
        sys.exit(1)


# Function to recursively find <File> tags and build their full paths
def find_files_with_paths(element, current_path=""):
    files = []
    if element.tag == "Directory":
        current_path = f"{current_path}/{element.get('name')}"
    for child in element:
        if child.tag == "File":
            file_path = f"{current_path}/{child.get('name')}"
            files.append(file_path)
        elif child.tag == "Directory":
            files.extend(find_files_with_paths(child, current_path))
    return files


def get_backed_up_files(backup_name, backup_dir):
    backup_path = os.path.join(backup_dir, backup_name)
    command = ['dar', '-l', backup_path, '-am', '-as', "-Txml" , '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        output = run_command(command)
        # Parse the XML data
        root = ET.fromstring(output)
        output = None  # help gc
        # Extract full paths for all <File> elements
        file_paths = find_files_with_paths(root)
        root = None # help gc
        logger.trace(f"Backed up files in dar archive: '{backup_name}'")
        logger.trace(file_paths)
        return file_paths
    except Exception as e:
        logger.exception(f"Error listing contents of archive {backup_name}: {e}")
        print(f"Error listing contents of the archive: {backup_name}")
        ERRORS_ENCOUNTERED.append(f"Error listing contents of the archive: {backup_name}")


def list_contents(backup_name, backup_dir, selection=None):
    backup_path = os.path.join(backup_dir, backup_name)
    command = ['dar', '-l', backup_path, '-am', '-as', '-Q']
    if selection:
        selection_criteria = shlex.split(selection)
        command.extend(selection_criteria)
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        output = run_command(command)
        print(output)
    except Exception as e:
        logger.exception(f"Error listing contents of archive {backup_name}: {e}")
        print(f"Error listing contents of the archive: {e}")
        sys.exit(1)


def perform_backup(args, backup_d, backup_dir, test_restore_dir, backup_type, max_size_verification_mb, no_files_verification):
    logger.debug(f"perform_backup({backup_type}) started")
    backup_definitions = []

    if args.backup_definition:
        backup_definitions.append((os.path.basename(args.backup_definition).split('.')[0], os.path.join(backup_d, args.backup_definition)))
    else:
        for root, _, files in os.walk(backup_d):
            for file in files:
                backup_definitions.append((file.split('.')[0], os.path.join(root, file)))

    for backup_definition, backup_definition_path in backup_definitions:
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d')
            backup_file = os.path.join(backup_dir, f"{backup_definition}_{backup_type}_{timestamp}")

            if os.path.exists(backup_file + '.1.dar'):
                logger.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
                continue

            if backup_type == 'FULL':
                backup(backup_file, backup_definition_path)
            else:
                base_backup_type = 'FULL' if backup_type == 'DIFF' else 'DIFF'
                base_backups = sorted(
                    [f for f in os.listdir(backup_dir) if f.startswith(f"{backup_definition}_{base_backup_type}_") and f.endswith('.1.dar')],
                    key=lambda x: datetime.strptime(x.split('_')[-1].split('.')[0], '%Y-%m-%d')
                )
                if not base_backups:
                    logger.error(f"No {base_backup_type} backup found for {backup_definition}. Skipping {backup_type} backup.")
                    continue

                latest_base_backup = os.path.join(backup_dir, base_backups[-1].rsplit('.', 2)[0])
                if backup_type == 'DIFF':
                    differential_backup(backup_file, backup_definition_path, latest_base_backup)
                elif backup_type == 'INCR':
                    incremental_backup(backup_file, backup_definition_path, latest_base_backup)

            logger.info("Starting verification...")
            verify(backup_file, backup_definition_path, test_restore_dir, backup_dir, max_size_verification_mb, no_files_verification)
            logger.info("Verification completed successfully.")
            logger.info("Generate par2 redundancy files")
            generate_par2_files(backup_file, backup_dir)
            logger.info("par2 files completed successfully.")
        except Exception as e:
            logger.exception(f"Error during {backup_type} backup process: {e}")


def generate_par2_files(backup_file, backup_dir):
    try:
        for filename in os.listdir(backup_dir):
            if os.path.basename(backup_file) in filename:
                # Construct the full path to the file
                file_path = os.path.join(backup_dir, filename)
                # Run the par2 command to generate redundancy files with 5% error correction
                command = ['par2', 'create', '-r5', '-q', '-q', file_path]
                subprocess.run(command, check=True)
                logger.debug(f"par2 files generated for {file_path}")
    except subprocess.CalledProcessError as e:
        ERRORS_ENCOUNTERED.append(f"Error generating par2 files for {file_path}")
        raise
    except Exception as e:
        ERRORS_ENCOUNTERED.append(f"Error generating par2 files for {file_path}")
        raise


def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {VERSION}")
    print(f"dar-backup.py source code is here: https://github.com/per2jensen/dar-backup")
    print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')


def show_examples():
    examples = """
FULL back of all backup definitions in backup.d:
  'python3 dar-backup.py'

FULL back of a single backup definition in backup.d
  'python3 dar-backup.py -d <name of file in backup.d/>'

DIFF backup (differences to the latest FULL) of all backup definitions:
  'python3 dar-backup.py --differential-backup'

DIFF back of a single backup definition in backup.d
  'python3 dar-backup.py --differential-backup -d <name of file in backup.d/>'
  
INCR backup (differences to the latest DIFF) of all backup definitions:
  'python3 dar-backup.py --incremental-backup'

INCR back of a single backup definition in backup.d
  'python3 dar-backup.py --incremental-backup -d <name of file in backup.d/>'
  

File selection in `--selection`
--selection takes dar selection parameters between a pair of `"`. 

Example: select file names with this date in file names "2024-07-01" in the
directory "path/to/a/dir" where the path is relative to root of the backup.

python3 dar-backup.py --restore <name of dar archive>  --selection "-I '*2024-07-01*' -g path/to/a/dir"

See dar documentation on fileselection: http://dar.linux.free.fr/doc/man/dar.html#COMMANDS%20AND%20OPTIONS
"""
    print(examples)

def main():
    parser = argparse.ArgumentParser(description="Backup and verify using dar backup definitions.")
    parser.add_argument('--full-backup', action='store_true', help="Perform a full backup.")
    parser.add_argument('--differential-backup', action='store_true', help="Perform differential backup.")
    parser.add_argument('--incremental-backup', action='store_true', help="Perform incremental backup.")
    parser.add_argument('-d', '--backup-definition', help="Specific 'recipe' to select directories and files.")
    parser.add_argument('--config-file', '-c', type=str, help="Path to 'dar-backup.conf'", default=os.path.join(os.path.dirname(__file__), '../conf/dar-backup.conf'))
    parser.add_argument('--examples', action="store_true", help="Examples of using dar-backup.py.")
    parser.add_argument('--list', action='store_true', help="List available backups.")
    parser.add_argument('--list-contents', help="List the contents of a specific backup file.")
    parser.add_argument('--selection', help="dar file selection for listing/restoring specific files.")
    parser.add_argument('--restore', help="Restore files and/or directories.")
    parser.add_argument('--restore-dir', help="Directory to restore files to.")
    parser.add_argument('--verbose', action='store_true', help="Print various status messages to screen")
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`")
    parser.add_argument('--version', '-v', action='store_true', help="Show version information.")
    args = parser.parse_args()
    args.verbose and print("Current directory: " + os.path.normpath(os.path.dirname(__file__)))

    if args.version:
        show_version()
        sys.exit(0)

    if args.examples:
        show_examples()
        sys.exit(0)

    logfile_location, backup_dir, test_restore_dir, backup_d, max_size_verification_mb, no_files_verification = read_config(args.config_file)

    setup_logging(logfile_location, args.log_level)
    logger.debug(f"`args`:\n{args}")

    if not backup_d.startswith("/"):
        backup_d = os.path.normpath(os.path.join(os.path.dirname(__file__), backup_d))
    current_dir =  os.path.normpath(os.path.dirname(__file__))
    args.verbose and (print(f"Current directory: {current_dir}")      or logger.info(f"Current directory: {backup_d}"))
    args.verbose and (print(f"Backup.d:          {backup_d}") or         logger.info(f"Backup.d:          {backup_d}"))
    args.verbose and (print(f"Backup dir:        {backup_dir}") or       logger.info(f"Backup dir:        {backup_dir}"))
    args.verbose and (print(f"Test restore dir:  {test_restore_dir}") or logger.info(f"Test restore dir:  {test_restore_dir}"))
    args.verbose and (print(f"Logfile location:  {logfile_location}") or logger.info(f"Logfile location:  {logfile_location}"))
    
    if args.full_backup and not args.differential_backup and not args.incremental_backup:
        perform_backup(args, backup_d, backup_dir, test_restore_dir, "FULL", max_size_verification_mb, no_files_verification)
    elif args.differential_backup and not args.full_backup and not args.incremental_backup:
        perform_backup(args, backup_d, backup_dir,  test_restore_dir, "DIFF", max_size_verification_mb, no_files_verification)
    elif args.incremental_backup  and not args.full_backup and not args.differential_backup:
        perform_backup(args, backup_d, backup_dir, test_restore_dir, "INCR", max_size_verification_mb, no_files_verification)
    elif args.list:
        list_backups(backup_dir, args.backup_definition)
    elif args.list_contents:
        list_contents(args.list_contents, backup_dir, args.selection)
    elif args.restore:
        restore_dir = args.restore_dir if args.restore_dir else test_restore_dir
        restore_backup(args.restore, backup_dir, restore_dir, args.selection)


    if len(ERRORS_ENCOUNTERED) > 0:
        args.verbose and print("Errors encountered:")
        args.verbose and [print(error) for error in ERRORS_ENCOUNTERED]
        sys.exit(1)
    else:
        args.verbose and print("No errors encountered")
        sys.exit(0)


if __name__ == "__main__":
    main()
