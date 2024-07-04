import argparse
import configparser
import datetime
import filecmp
import logging
import os
import random
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET

from datetime import datetime
from pathlib import Path
from time import time

VERSION = "alpha-0.2"
logger=None


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

        logger.info("=======================")
        logger.info("`dar-backup.py` started")
    except Exception:
        print("dar-backup logging not initialized, exiting.")
        sys.exit(1)




def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    logger.trace(stdout)
    if process.returncode != 0:
        logger.error(stderr)
        raise Exception(f"Command: {" ".join(map(shlex.quote, command))} failed with return code {process.returncode}: {stderr}")
    return stdout

def read_config(config_file):
    config = configparser.ConfigParser()
    try:
        config.read(config_file)
        logfile_location = config['MISC']['LOGFILE_LOCATION']
        max_size_verification_mb = int(config['MISC']['MAX_SIZE_VERIFICATION_MB'])
        min_size_verification_mb = int(config['MISC']['MIN_SIZE_VERIFICATION_MB'])
        no_files_verification = int(config['MISC']['NO_FILES_VERIFICATION'])

        backup_dir = config['DIRECTORIES']['BACKUP_DIR']
        Path(backup_dir).mkdir(parents=True, exist_ok=True)
        test_restore_dir = config['DIRECTORIES']['TEST_RESTORE_DIR']
        Path(test_restore_dir).mkdir(parents=True, exist_ok=True)
        backup_d = config['DIRECTORIES']['BACKUP.D_DIR']
        Path(backup_d).mkdir(parents=True, exist_ok=True)
    except KeyError as e:
        logger.error(f"Missing mandatory configuration key: {e}")
        sys.stderr.write(f"Error: Missing mandatory configuration key: {e}\n")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Error reading config file {config_file}: {e}")
        sys.stderr.write(f"Error: Unable to read the config file {config_file}: {e}\n")
        sys.exit(1)
    return logfile_location, backup_dir, test_restore_dir, backup_d, min_size_verification_mb, max_size_verification_mb, no_files_verification

def backup(backup_file, backup_definition):
    if os.path.exists(backup_file + '.1.dar'):
        logger.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    run_command(command)
    logger.info("Backup completed successfully.")


def differential_backup(backup_file, backup_definition, base_backup_file):
    if os.path.exists(backup_file + '.1.dar'):
        logger.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return
    command = ['dar', '-c', backup_file, '-B', backup_definition, '-A', base_backup_file, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    run_command(command)
    logger.info("Differential backup completed successfully.")


def incremental_backup(backup_file, backup_definition, base_backup_file):
    if os.path.exists(backup_file + '.1.dar'):
        logger.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-A', base_backup_file, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    run_command(command)
    logger.info("Incremental backup completed successfully.")



def find_files_under_xxMB(backed_up_files, min_size_verification_mb, max_size_verification_mb):
    """Convert dar file size from the xml to a number and compare..."""
    files = []
    max_size = max_size_verification_mb
    min_size = min_size_verification_mb
    dar_sizes = {
        "o"   : 1,
        "kio" : 1024,
        "Mio" : 1024 * 1024,
        "Gio" : 1024 * 1024 * 1024,
        "Tio" : 1024 * 1024 * 1024 * 1024
     }
    pattern = r'(\d+)\s*(\w+)'
    for tuple in backed_up_files:
        print(f"tuple: {tuple}")
        match = re.match(pattern, tuple[1])
        if match:
            number = int(match.group(1))
            unit = match.group(2).strip()
            file_size = dar_sizes[unit] * number
        if (min_size_verification_mb  * 1024 * 1024) < file_size <= (max_size * 1024 * 1024):
            logger.trace(f"File found between min and max sizes: {tuple}")
            files.append(tuple[0])
    return files


def verify(args, backup_file, backup_definition, test_restore_dir, backup_dir, min_size_verification_mb, max_size_verification_mb, no_files_verification):
    test_command = ['dar', '-t', backup_file, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, test_command))}")
    run_command(test_command)
    logger.info("Archive integrity test passed.")

    if args.do_not_compare:
        return

    backed_up_files = get_backed_up_files(backup_file, backup_dir) 

    files = find_files_under_xxMB(backed_up_files, min_size_verification_mb, max_size_verification_mb)
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

    if len(files) < no_files_verification:
        no_files_verification = len(files)
    random_files = random.sample(files, no_files_verification)
    for restored_file_path in random_files:
        os.makedirs(os.path.dirname(restored_file_path), exist_ok=True)

        command = ['dar', '-x', backup_file, '-g', restored_file_path.lstrip("/"), '-R', test_restore_dir, '-O', '-Q']
        logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
        run_command(command)
        if filecmp.cmp(os.path.join(test_restore_dir, restored_file_path.lstrip("/")), os.path.join(root_path, restored_file_path.lstrip("/")), shallow=False):
           logger.info(f"File '{restored_file_path}' matches the original")   
        else:
           logger.error(f"File '{restored_file_path}' did not match the original")



def list_backups(backup_dir, backup_definition=None):
    backups = set(f.rsplit('.', 2)[0] for f in os.listdir(backup_dir) if f.endswith('.dar'))
    if not backups:
        print("No backups available.")
        return

    if backup_definition:
        backups = [b for b in backups if b.startswith(backup_definition)]
    
    backups = sorted(backups, key=lambda x: datetime.strptime(x.split('_')[-1], '%Y-%m-%d'))

    for backup in backups:
        print(backup)


def restore_backup(backup_name, backup_dir, restore_dir, selection=None):
    backup_file = os.path.join(backup_dir, backup_name)
    command = ['dar', '-x', backup_file, '-O', '-Q', '-D']
    if restore_dir:
        if not os.path.exists(restore_dir):
            os.makedirs(restore_dir)
        command.extend(['-R', restore_dir])
    if selection:
        selection_criteria = shlex.split(selection)
        command.extend(selection_criteria)
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    run_command(command)


# Function to recursively find <File> tags and build their full paths
def find_files_with_paths(element, current_path=""):
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


def get_backed_up_files(backup_name, backup_dir):
    backup_path = os.path.join(backup_dir, backup_name)
    command = ['dar', '-l', backup_path, '-am', '-as', "-Txml" , '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
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


def list_contents(backup_name, backup_dir, selection=None):
    backup_path = os.path.join(backup_dir, backup_name)
    command = ['dar', '-l', backup_path, '-am', '-as', '-Q']
    if selection:
        selection_criteria = shlex.split(selection)
        command.extend(selection_criteria)
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    output = run_command(command)
    print(output)


def perform_backup(args, backup_d, backup_dir, test_restore_dir, backup_type, min_size_verification_mb, max_size_verification_mb, no_files_verification):
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
            verify(args, backup_file, backup_definition_path, test_restore_dir, backup_dir, min_size_verification_mb, max_size_verification_mb, no_files_verification)
            logger.info("Verification completed successfully.")
            logger.info("Generate par2 redundancy files")
            generate_par2_files(backup_file, backup_dir)
            logger.info("par2 files completed successfully.")
        # we want to continue with other backup definitions, there only logging an error
        except Exception as e:
            logger.exception(f"Error during {backup_type} backup process: {e}")


def generate_par2_files(backup_file, backup_dir):
    for filename in os.listdir(backup_dir):
        if os.path.basename(backup_file) in filename:
            # Construct the full path to the file
            file_path = os.path.join(backup_dir, filename)
            # Run the par2 command to generate redundancy files with 5% error correction
            command = ['par2', 'create', '-r5', '-q', '-q', file_path]
            subprocess.run(command, check=True)
            logger.debug(f"par2 files generated for {file_path}")


def extract_error_lines(log_file_path, start_time, end_time):
    with open(log_file_path, 'r') as log_file:
        lines = log_file.readlines()

    start_index = None
    end_index = None

    start_marker = f"START TIME: {start_time}"
    end_marker   = f"END TIME: {end_time}"
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
  'python3 dar-backup.py  --full-backup'

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
  

--log-level
    "trace" logs output from programs (typically dar and par2) run in a subprocess
    "debug" logs various statuses and notices to better understand how to script works


File selection in `--selection`
--selection takes dar selection parameters between a pair of `"`. 

Example: select file names with this date in file names "2024-07-01" in the
directory "path/to/a/dir" where the path is relative to root of the backup.

python3 dar-backup.py --restore <name of dar archive>  --selection "-I '*2024-07-01*' -g path/to/a/dir"

See dar documentation on file selection: http://dar.linux.free.fr/doc/man/dar.html#COMMANDS%20AND%20OPTIONS
"""
    print(examples)

def main():
    MIN_PYTHON_VERSION = (3, 7)
    if sys.version_info < MIN_PYTHON_VERSION:
        sys.stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Backup and verify using dar backup definitions.")
    parser.add_argument('--full-backup', action='store_true', help="Perform a full backup.")
    parser.add_argument('--differential-backup', action='store_true', help="Perform differential backup.")
    parser.add_argument('--incremental-backup', action='store_true', help="Perform incremental backup.")
    parser.add_argument('-d', '--backup-definition', help="Specific 'recipe' to select directories and files.")
    parser.add_argument('--config-file', '-c', type=str, help="Path to 'dar-backup.conf'", default=os.path.join(os.path.dirname(__file__), '../conf/dar-backup.conf'))
    parser.add_argument('--examples', action="store_true", help="Examples of using dar-backup.py.")
    parser.add_argument('--list', action='store_true', help="List available archives.")
    parser.add_argument('--list-contents', help="List the contents of the specified archive.")
    parser.add_argument('--selection', help="dar file selection for listing/restoring specific files/directories.")
    parser.add_argument('--restore', help="Restore specified archive.")
    parser.add_argument('--restore-dir', help="Directory to restore files to.")
    parser.add_argument('--verbose', action='store_true', help="Print various status messages to screen")
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`")
    parser.add_argument('--do-not-compare', action='store_true', help="do not compare restores to file system")
    parser.add_argument('--version', '-v', action='store_true', help="Show version information.")
    args = parser.parse_args()
    args.verbose and print("Current directory: " + os.path.normpath(os.path.dirname(__file__)))

    if args.version:
        show_version()
        sys.exit(0)

    if args.examples:
        show_examples()
        sys.exit(0)

    logfile_location, backup_dir, test_restore_dir, backup_d, min_size_verification_mb, max_size_verification_mb, no_files_verification = read_config(args.config_file)

    setup_logging(logfile_location, args.log_level)

    try:
        start_time=int(time())
        logger.info(f"START TIME: {start_time}")
        logger.debug(f"`args`:\n{args}")

        if not backup_d.startswith("/"):
            backup_d = os.path.normpath(os.path.join(os.path.dirname(__file__), backup_d))
        current_dir =  os.path.normpath(os.path.dirname(__file__))
        args.verbose and (print(f"Current directory: {current_dir}"))
        args.verbose and (print(f"Backup.d:          {backup_d}"))
        args.verbose and (print(f"Backup dir:        {backup_dir}"))
        args.verbose and (print(f"Test restore dir:  {test_restore_dir}"))
        args.verbose and (print(f"Logfile location:  {logfile_location}"))
        args.verbose and (print(f"--do-not-compare:  {args.do_not_compare}"))
    
        if args.full_backup and not args.differential_backup and not args.incremental_backup:
            perform_backup(args, backup_d, backup_dir, test_restore_dir, "FULL", min_size_verification_mb, max_size_verification_mb, no_files_verification)
        elif args.differential_backup and not args.full_backup and not args.incremental_backup:
            perform_backup(args, backup_d, backup_dir,  test_restore_dir, "DIFF", min_size_verification_mb, max_size_verification_mb, no_files_verification)
        elif args.incremental_backup  and not args.full_backup and not args.differential_backup:
            perform_backup(args, backup_d, backup_dir, test_restore_dir, "INCR", min_size_verification_mb, max_size_verification_mb, no_files_verification)
        elif args.list:
            list_backups(backup_dir, args.backup_definition)
        elif args.list_contents:
            list_contents(args.list_contents, backup_dir, args.selection)
        elif args.restore:
            restore_dir = args.restore_dir if args.restore_dir else test_restore_dir
            restore_backup(args.restore, backup_dir, restore_dir, args.selection)
        else:
            parser.print_help()
    except Exception:
        pass

    end_time=int(time())
    logger.info(f"END TIME: {end_time}")

    error_lines = extract_error_lines(logfile_location, start_time, end_time)
    if len(error_lines) > 0:
        args.verbose and print("Errors encountered")
        for line in error_lines:
            print(line)
        sys.exit(1)
    else:
        args.verbose and print("No errors encountered")
        sys.exit(0)


if __name__ == "__main__":
    main()
