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
import xml.etree.ElementTree as ET
from datetime import datetime

VERSION = "alpha-0.2"

# Check Python version compatibility
MIN_PYTHON_VERSION = (3, 7)
if sys.version_info < MIN_PYTHON_VERSION:
    sys.stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
    sys.exit(1)

def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        logging.info(stdout)
        if process.returncode != 0:
            logging.error(stderr)
            raise Exception(f"Command: '{" ".join(map(shlex.quote, command))}' failed with return code {process.returncode}: {stderr}")
        else:
            logging.info(stderr)
        return stdout
    except Exception as e:
        logging.exception(f"Error running command:  '{' '.join(map(shlex.quote, command))}': {e}")
        raise

def read_config(config_file):
    config = configparser.ConfigParser()
    try:
        config.read(config_file)
        logfile_location = config['DEFAULT']['LOGFILE_LOCATION']
        backup_dir = config['DIRECTORIES']['BACKUP_DIR']
        test_restore_dir = config['DIRECTORIES']['TEST_RESTORE_DIR']
        backup_d = config['DIRECTORIES']['BACKUP.D_DIR']
    except KeyError as e:
        logging.error(f"Missing mandatory configuration field: {e}")
        sys.stderr.write(f"Error: Missing mandatory configuration field: {e}\n")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"Error reading config file {config_file}: {e}")
        sys.stderr.write(f"Error: Unable to read the config file: {e}\n")
        sys.exit(1)
    return logfile_location, backup_dir, test_restore_dir, backup_d

def backup(backup_file, backup_definition):
    if os.path.exists(backup_file + '.1.dar'):
        logging.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-Q']
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logging.info("Backup completed successfully.")
    except Exception as e:
        logging.exception(f"Error during backup with backup definition {backup_definition}: {e}. Continuing to next backup definition.")
        return

def differential_backup(backup_file, backup_definition, base_backup_file):
    if os.path.exists(backup_file + '.1.dar'):
        logging.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-A', base_backup_file, '-Q']
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logging.info("Differential backup completed successfully.")
    except Exception as e:
        logging.exception(f"Error during differential backup with backup definition {backup_definition}: {e}. Continuing to next backup definition.")
        return

def incremental_backup(backup_file, backup_definition, base_backup_file):
    if os.path.exists(backup_file + '.1.dar'):
        logging.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-A', base_backup_file, '-Q']
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logging.info("Incremental backup completed successfully.")
    except Exception as e:
        logging.exception(f"Error during incremental backup with backup definition {backup_definition}: {e}. Continuing to next backup definition.")
        return

def find_files_under_10MB(backed_up_files):
    files_under_10MB = []
    for file_path in backed_up_files:
        try:
            file_size = os.path.getsize(file_path)
            logging.debug(f"Found file: {file_path}, Size: {file_size} bytes")
            if file_size < 10 * 1024 * 1024:
                logging.info(f"File under 10MB: {file_path}")
                files_under_10MB.append(file_path)
        except Exception as e:
            logging.exception(f"Error accessing file {file_path}: {e}")
    return files_under_10MB

def verify(backup_file, backup_definition, test_restore_dir, backup_dir):
    test_command = ['dar', '-t', backup_file, '-Q']
    logging.info(f"Running command: {' '.join(map(shlex.quote, test_command))}")
    try:
        run_command(test_command)
        logging.info("Archive integrity test passed.")
    except Exception as e:
        logging.exception(f"Archive integrity test failed for {backup_file}: {e}")
        raise

    backed_up_files = get_backed_up_files(backup_file, backup_dir) 

    files_under_10MB = find_files_under_10MB(backed_up_files)
    if len(files_under_10MB) < 3:
        logging.info("Not enough files under 10MB for verification, skipping")
        return

    with open(backup_definition, 'r') as f:
        backup_definition_content = f.readlines()
        logging.debug(f"Backup definition: '{backup_definition}', content:\n{backup_definition_content}")
    # Initialize a variable to hold the path after "-R"
    root_path = None
    # Iterate over the lines
    for line in backup_definition_content:
        line = line.strip()
        if line.startswith("-R"):
            # Capture the path which is after the space following "-R"
            root_path = line.split("-R", 1)[1].strip()
            break

    random_files = random.sample(files_under_10MB, 3)
    for restored_file_path in random_files:
        try:
            os.makedirs(os.path.dirname(restored_file_path), exist_ok=True)
        except Exception as e:
            logging.exception(f"Error creating directory for {restored_file_path}: {e}")
            continue
        

        command = ['dar', '-x', backup_file, '-g', restored_file_path.lstrip("/"), '-R', test_restore_dir, '-O', '-Q']
        logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
        try:
            run_command(command)
        except Exception as e:
            logging.exception(f"Error restoring file '{restored_file_path}' from backup {backup_file}: {e}")
            raise

        if not filecmp.cmp(os.path.join(root_path, restored_file_path), os.path.join(test_restore_dir, restored_file_path), shallow=False):
            logging.error(f"File '{restored_file_path}' did not match the original after restoration.")
    
    logging.info("Verification of 3 random files under 10MB completed successfully.")

def list_backups(backup_dir, selection=None, backup_definition=None):
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
            if selection:
                list_contents(backup, backup_dir, selection)
    except Exception as e:
        logging.exception(f"Error listing backups in directory {backup_dir}: {e}")
        sys.stderr.write(f"Error: Unable to list backups in directory {backup_dir}: {e}\n")
        sys.exit(1)

def restore_backup(backup_name, backup_dir, restore_dir, selection=None):
    backup_file = os.path.join(backup_dir, backup_name)
    command = ['dar', '-x', backup_file, '-O', '-Q', '-D']
    if restore_dir:
        if not os.path.exists(restore_dir):
            try:
                os.makedirs(restore_dir)
            except Exception as e:
                logging.exception(f"Error creating restore directory {restore_dir}: {e}")
                sys.stderr.write(f"Error: Unable to create restore directory {restore_dir}: {e}\n")
                sys.exit(1)
        command.extend(['-R', restore_dir])
    if selection:
        selection_criteria = shlex.split(selection)
        command.extend(selection_criteria)
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
    except Exception as e:
        logging.exception(f"Error during restore of {backup_name} to {restore_dir}: {e}. Exiting.")
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
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        output = run_command(command)
        # Parse the XML data
        root = ET.fromstring(output)
        output = None  # help gc
        # Extract full paths for all <File> elements
        file_paths = find_files_with_paths(root)
        root = None # help gc
        logging.debug(f"Backed up files in dar archive: '{backup_name}'")
        logging.debug(file_paths)
        return file_paths
    except Exception as e:
        logging.exception(f"Error listing contents of archive {backup_name}: {e}")
        print(f"Error listing contents of the archive: {e}")
        sys.exit(1)


def list_contents(backup_name, backup_dir, selection=None):
    backup_path = os.path.join(backup_dir, backup_name)
    command = ['dar', '-l', backup_path, '-am', '-as', '-Q']
    if selection:
        selection_criteria = shlex.split(selection)
        command.extend(selection_criteria)
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        output = run_command(command)
        print(output)
    except Exception as e:
        logging.exception(f"Error listing contents of archive {backup_name}: {e}")
        print(f"Error listing contents of the archive: {e}")
        sys.exit(1)

def perform_backup(args, backup_d, backup_dir, test_restore_dir):
    backup_definitions = []

    if args.backup_definition:
        backup_definitions.append((os.path.basename(args.backup_definition).split('.')[0], os.path.join(backup_d, args.backup_definition)))
    else:
        for root, _, files in os.walk(backup_d):
            for file in files:
                backup_definitions.append((file.split('.')[0], os.path.join(root, file)))

    try:
        for backup_definition, backup_definition_path in backup_definitions:
            timestamp = datetime.now().strftime('%Y-%m-%d')
            backup_file = os.path.join(backup_dir, f"{backup_definition}_FULL_{timestamp}")

            if os.path.exists(backup_file + '.1.dar'):
                logging.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
                continue

            backup(backup_file, backup_definition_path)

            logging.info("Starting verification...")
            verify(backup_file, backup_definition_path, test_restore_dir, backup_dir)
            logging.info("Verification completed successfully.")
    except Exception as e:
        logging.exception(f"Error during backup process: {e}")
        sys.stderr.write(f"Error: Backup process failed: {e}\n")

def perform_differential_backup(args, backup_d, backup_dir, test_restore_dir):
    backup_definitions = []
    if args.backup_definition:
        backup_definitions.append((args.backup_definition, os.path.join(backup_d, args.backup_definition)))
    else:
        for root, _, files in os.walk(backup_d):
            for file in files:
                backup_definitions.append((file.split('.')[0], os.path.join(root, file)))

    try:
        for backup_definition, backup_definition_path in backup_definitions:
            timestamp = datetime.now().strftime('%Y-%m-%d')
            backup_file = os.path.join(backup_dir, f"{backup_definition}_DIFF_{timestamp}")

            full_backups = sorted(
                [f for f in os.listdir(backup_dir) if f.startswith(f"{backup_definition}_FULL_") and f.endswith('.1.dar')],
                key=lambda x: datetime.strptime(x.split('_')[-1].split('.')[0], '%Y-%m-%d')
            )
            if not full_backups:
                logging.error(f"No FULL backup found for {backup_definition}. Skipping differential backup.")
                continue

            latest_full_backup_base = os.path.join(backup_dir, full_backups[-1].rsplit('.', 2)[0])
            logging.info(f"Latest FULL backup for '{backup_definition}': {latest_full_backup_base}")

            differential_backup(backup_file, backup_definition_path, latest_full_backup_base)
 
            logging.info("Starting verification...")
            verify(backup_file, backup_definition_path, test_restore_dir, backup_dir)
            logging.info("Verification completed successfully.")
    except Exception as e:
        logging.exception(f"Error during differential backup process: {e}")
        sys.stderr.write(f"Error: Differential backup process failed: {e}\n")

def perform_incremental_backup(args, backup_d, backup_dir, test_restore_dir):
    backup_definitions = []
    if args.backup_definition:
        backup_definitions.append((args.backup_definition, os.path.join(backup_d, args.backup_definition)))
    else:
        for root, _, files in os.walk(backup_d):
            for file in files:
                backup_definitions.append((file.split('.')[0], os.path.join(root, file)))

    try:
        for backup_definition, backup_definition_path in backup_definitions:
            timestamp = datetime.now().strftime('%Y-%m-%d')
            backup_file = os.path.join(backup_dir, f"{backup_definition}_INCR_{timestamp}")

            diff_backups = sorted(
                [f for f in os.listdir(backup_dir) if f.startswith(f"{backup_definition}_DIFF_") and f.endswith('.1.dar')],
                key=lambda x: datetime.strptime(x.split('_')[-1].split('.')[0], '%Y-%m-%d')
            )
            if not diff_backups:
                logging.error(f"No DIFF backup found for {backup_definition}. Skipping incremental backup.")
                continue

            latest_diff_backup_base = os.path.join(backup_dir, diff_backups[-1].rsplit('.', 2)[0])
            logging.info(f"Latest DIFF backup for '{backup_definition}': {latest_diff_backup_base}")

            incremental_backup(backup_file, backup_definition_path, latest_diff_backup_base)
            logging.info("Starting verification...")
            verify(backup_file, backup_definition_path, test_restore_dir, backup_dir)
            logging.info("Verification completed successfully.")
    except Exception as e:
        logging.exception(f"Error during incremental backup process: {e}")
        sys.stderr.write(f"Error: Incremental backup process failed: {e}\n")

def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {VERSION}")
    print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')

def main():
    parser = argparse.ArgumentParser(description="Backup and verify using dar with config snippets.")
    parser.add_argument('-d', '--backup-definition', help="Specific config snippet file to use.")
    parser.add_argument('--list', action='store_true', help="List available backups.")
    parser.add_argument('--restore', help="Restore a specific backup file.")
    parser.add_argument('--restore-dir', help="Directory to restore files to.")
    parser.add_argument('--selection', help="Selection criteria for restoring specific files.")
    parser.add_argument('--list-contents', help="List the contents of a specific backup file.")
    parser.add_argument('--differential-backup', action='store_true', help="Perform differential backup.")
    parser.add_argument('--incremental-backup', action='store_true', help="Perform incremental backup.")
    parser.add_argument('--version', '-v', action='store_true', help="Show version information.")
    parser.add_argument('--config-file', '-c', type=str, help="Path to the configuration file", default=os.path.join(os.path.dirname(__file__), '../conf/backup_script.conf'))
    args = parser.parse_args()

    if args.version:
        show_version()
        sys.exit(0)

    logfile_location, backup_dir, test_restore_dir, backup_d = read_config(args.config_file)
    setup_logging(logfile_location)

    if args.list:
        list_backups(backup_dir, args.selection, args.backup_definition)
        sys.exit(0)

    if args.restore:
        restore_dir = args.restore_dir if args.restore_dir else test_restore_dir
        restore_backup(args.restore, backup_dir, restore_dir, args.selection)
        sys.exit(0)

    if args.list_contents:
        list_contents(args.list_contents, backup_dir, args.selection)
        sys.exit(0)

    if args.incremental_backup:
        perform_incremental_backup(args, backup_d, backup_dir, test_restore_dir)
    elif args.differential_backup:
        perform_differential_backup(args, backup_d, backup_dir,  test_restore_dir)
    else:
        perform_backup(args, backup_d, backup_dir, test_restore_dir)

if __name__ == "__main__":
    main()
