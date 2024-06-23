#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import random
import filecmp
import logging
import shlex
import configparser
from datetime import datetime

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
            raise Exception(f"Command failed with return code {process.returncode}: {stderr}")
        else:
            logging.info(stderr)
        return stdout
    except Exception as e:
        logging.error(f"Error running command {' '.join(map(shlex.quote, command))}: {e}")
        raise

def read_config():
    config = configparser.ConfigParser()
    config_file = os.path.join(os.path.dirname(__file__), '../conf/backup_script.conf')
    try:
        config.read(config_file)
        logfile_location = config['DEFAULT']['LOGFILE_LOCATION']
        backup_dir = config['DEFAULT']['BACKUP_DIR']
        test_restore_dir = config['DEFAULT']['TEST_RESTORE_DIR']
        backup_d = config['DEFAULT']['BACKUP.D']
    except Exception as e:
        logging.error(f"Error reading config file {config_file}: {e}")
        sys.exit(1)
    return logfile_location, backup_dir, test_restore_dir, backup_d

def backup(backup_file, config_file):
    if os.path.exists(backup_file + '.1.dar'):
        logging.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', config_file, '-Q']
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logging.info("Backup completed successfully.")
    except Exception as e:
        logging.error(f"Error during backup with config file {config_file}: {e}. Continuing to next config snippet.")
        return

def differential_backup(backup_file, config_file, base_backup_file):
    if os.path.exists(backup_file + '.1.dar'):
        logging.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', config_file, '-A', base_backup_file, '-Q']
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logging.info("Differential backup completed successfully.")
    except Exception as e:
        logging.error(f"Error during differential backup with config file {config_file}: {e}. Continuing to next config snippet.")
        return

def find_files_under_10MB(root_dir, relative_dirs):
    files_under_10MB = []
    root_dir = root_dir.strip()
    for relative_dir in relative_dirs:
        directory = os.path.join(root_dir, relative_dir.strip())
        logging.info(f"Searching in directory: {directory}")
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    file_size = os.path.getsize(file_path)
                    logging.debug(f"Found file: {file_path}, Size: {file_size} bytes")
                    if file_size < 10 * 1024 * 1024:
                        logging.info(f"File under 10MB: {file_path}")
                        files_under_10MB.append(file_path)
                except Exception as e:
                    logging.error(f"Error accessing file {file_path}: {e}")
    return files_under_10MB

def verify(backup_file, config_file, test_restore_dir):
    # Test the archive integrity first
    test_command = ['dar', '-t', backup_file, '-Q']
    logging.info(f"Running command: {' '.join(map(shlex.quote, test_command))}")
    try:
        run_command(test_command)
        logging.info("Archive integrity test passed.")
    except Exception as e:
        logging.error(f"Archive integrity test failed for {backup_file}: {e}")
        return

    with open(config_file, 'r') as f:
        config_snippet = f.readlines()

    root_dir = [arg.split(' ')[1] for arg in config_snippet if arg.startswith('-R')][0].strip()
    relative_dirs = [arg.split(' ')[1] for arg in config_snippet if arg.startswith('-g')]

    if not relative_dirs:
        logging.info("No include or specific files found in the config snippet.")
        return
    
    files_under_10MB = find_files_under_10MB(root_dir, relative_dirs)
    if len(files_under_10MB) < 3:
        logging.info("Not enough files under 10MB for verification in directories: " + ', '.join(relative_dirs))
        return

    random_files = random.sample(files_under_10MB, 3)
    for file in random_files:
        relative_path = os.path.relpath(file, root_dir)
        restored_file_path = os.path.join(test_restore_dir, relative_path)
        try:
            os.makedirs(os.path.dirname(restored_file_path), exist_ok=True)
        except Exception as e:
            logging.error(f"Error creating directory for {restored_file_path}: {e}")
            continue
        
        command = ['dar', '-x', backup_file, '-g', relative_path, '-R', test_restore_dir, '-O', '-Q']
        logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
        try:
            run_command(command)
        except Exception as e:
            logging.error(f"Error restoring file {relative_path} from backup {backup_file}: {e}")
            continue

        if not filecmp.cmp(file, restored_file_path, shallow=False):
            logging.error(f"File {relative_path} did not match the original after restoration.")
    
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
        logging.error(f"Error listing backups in directory {backup_dir}: {e}")
        sys.exit(1)

def restore_backup(backup_name, backup_dir, restore_dir, selection=None):
    backup_file = os.path.join(backup_dir, backup_name)
    command = ['dar', '-x', backup_file, '-O', '-Q', '-D']
    if restore_dir:
        if not os.path.exists(restore_dir):
            try:
                os.makedirs(restore_dir)
            except Exception as e:
                logging.error(f"Error creating restore directory {restore_dir}: {e}")
                sys.exit(1)
        command.extend(['-R', restore_dir])
    if selection:
        selection_criteria = shlex.split(selection)
        command.extend(selection_criteria)
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
    except Exception as e:
        logging.error(f"Error during restore of {backup_name} to {restore_dir}: {e}. Exiting.")
        sys.exit(1)

def list_contents(backup_name, backup_dir, selection=None):
    backup_path = os.path.join(backup_dir, backup_name)
    command = ['dar', '-l', backup_path, '-am', '-Q']
    if selection:
        selection_criteria = shlex.split(selection)
        command.extend(selection_criteria)
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        output = run_command(command)
        print(output)
    except Exception as e:
        logging.error(f"Error listing contents of archive {backup_name}: {e}")
        print(f"Error listing contents of the archive: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Backup and verify using dar with config snippets.")
    parser.add_argument('-d', '--backup-definition', help="Specific config snippet file to use.")
    parser.add_argument('--list', action='store_true', help="List available backups.")
    parser.add_argument('--restore', help="Restore a specific backup file.")
    parser.add_argument('--restore-dir', help="Directory to restore files to.")
    parser.add_argument('--selection', help="Selection criteria for restoring specific files.")
    parser.add_argument('--list-contents', help="List the contents of a specific backup file.")
    parser.add_argument('--differential-backup', action='store_true', help="Perform differential backup.")

    args = parser.parse_args()

    logfile_location, backup_dir, test_restore_dir, backup_d = read_config()
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

    if args.differential_backup:
        config_files = []
        if args.backup_definition:
            config_files.append((args.backup_definition, os.path.join(backup_d, args.backup_definition)))
        else:
            for root, _, files in os.walk(backup_d):
                for file in files:
                    config_files.append((file.split('.')[0], os.path.join(root, file)))

        try:
            for snippet_name, config_file in config_files:
                timestamp = datetime.now().strftime('%Y-%m-%d')
                backup_file = os.path.join(backup_dir, f"{snippet_name}_DIFF_{timestamp}")

                # Find the latest FULL backup for the snippet
                full_backups = sorted(
                    [f for f in os.listdir(backup_dir) if f.startswith(f"{snippet_name}_FULL_") and f.endswith('.1.dar')],
                    key=lambda x: datetime.strptime(x.split('_')[-1].split('.')[0], '%Y-%m-%d')
                )
                if not full_backups:
                    logging.error(f"No FULL backup found for {snippet_name}. Skipping differential backup.")
                    continue

                latest_full_backup_base = os.path.join(backup_dir, full_backups[-1].rsplit('.', 2)[0])
                logging.info(f"Latest FULL backup for {snippet_name}: {latest_full_backup_base}")

                differential_backup(backup_file, config_file, latest_full_backup_base)
        except Exception as e:
            logging.error(f"Error during differential backup process: {e}")
            sys.exit(1)
    else:
        config_files = []

        if args.backup_definition:
            config_files.append((os.path.basename(args.backup_definition).split('.')[0], os.path.join(backup_d, args.backup_definition)))
        else:
            for root, _, files in os.walk(backup_d):
                for file in files:
                    config_files.append((file.split('.')[0], os.path.join(root, file)))

        try:
            for snippet_name, config_file in config_files:
                timestamp = datetime.now().strftime('%Y-%m-%d')
                backup_file = os.path.join(backup_dir, f"{snippet_name}_FULL_{timestamp}")

                if os.path.exists(backup_file + '.1.dar'):
                    logging.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
                    continue

                logging.info(f"Starting backup with config file {config_file}...")
                backup(backup_file, config_file)

                logging.info("Starting verification...")
                verify(backup_file, config_file, test_restore_dir)
                logging.info("Verification completed successfully.")
        except Exception as e:
            logging.error(f"Error during backup process: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()