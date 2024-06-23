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
        logging.error(f"Error running command: {e}")
        raise

def read_config():
    config = configparser.ConfigParser()
    config_file = os.path.join(os.path.dirname(__file__), '../conf/backup_script.conf')
    try:
        config.read(config_file)
        logfile_location = config['DEFAULT']['LOGFILE_LOCATION']
        backup_dir = config['DEFAULT']['BACKUP_DIR']
        test_restore_dir = config['DEFAULT']['TEST_RESTORE_DIR']
    except Exception as e:
        logging.error(f"Error reading config file: {e}")
        sys.exit(1)
    return logfile_location, backup_dir, test_restore_dir

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
        logging.error(f"Error during backup: {e}. Continuing to next config snippet.")
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
        os.makedirs(os.path.dirname(restored_file_path), exist_ok=True)
        
        command = ['dar', '-x', backup_file, '-g', relative_path, '-R', test_restore_dir, '-O', '-Q']
        logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
        run_command(command)

        if not filecmp.cmp(file, restored_file_path, shallow=False):
            raise Exception(f"File {relative_path} did not match the original after restoration.")
    
    logging.info("Verification of 3 random files under 10MB completed successfully.")

def list_backups(backup_dir, selection=None):
    try:
        backups = set(f.rsplit('.', 2)[0] for f in os.listdir(backup_dir) if f.endswith('.dar'))
        if not backups:
            print("No backups available.")
        else:
            for backup in backups:
                print(backup)
                if selection:
                    list_contents(backup, backup_dir, selection)
    except Exception as e:
        logging.error(f"Error listing backups: {e}")
        sys.exit(1)

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
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
    except Exception as e:
        logging.error(f"Error during restore: {e}. Exiting.")
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
        logging.error(f"Error listing contents of the archive: {e}")
        print(f"Error listing contents of the archive: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Backup and verify using dar with config snippets.")
    parser.add_argument('--config-dir', help="Directory containing config snippets.")
    parser.add_argument('--config-file', help="Specific config snippet file to use.")
    parser.add_argument('--list', action='store_true', help="List available backups.")
    parser.add_argument('--restore', help="Restore a specific backup file.")
    parser.add_argument('--restore-dir', help="Directory to restore files to.")
    parser.add_argument('--selection', help="Selection criteria for restoring specific files.")
    parser.add_argument('--list-contents', help="List the contents of a specific backup file.")

    args = parser.parse_args()

    logfile_location, backup_dir, test_restore_dir = read_config()
    setup_logging(logfile_location)

    if args.list:
        list_backups(backup_dir, args.selection)
        sys.exit(0)

    if args.restore:
        restore_dir = args.restore_dir if args.restore_dir else test_restore_dir
        restore_backup(args.restore, backup_dir, restore_dir, args.selection)
        sys.exit(0)

    if args.list_contents:
        list_contents(args.list_contents, backup_dir, args.selection)
        sys.exit(0)

    config_files = []

    if args.config_file:
        config_files.append((os.path.basename(args.config_file).split('.')[0], args.config_file))
    elif args.config_dir:
        for root, _, files in os.walk(args.config_dir):
            for file in files:
                config_files.append((file.split('.')[0], os.path.join(root, file)))
    else:
        logging.error("Error: Either --config-dir or --config-file must be specified.")
        sys.exit(1)

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
        logging.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
