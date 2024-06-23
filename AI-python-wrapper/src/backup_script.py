#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import random
import filecmp
import tempfile
import logging
import shlex

def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        logging.info(stdout)
        logging.error(stderr)
        if process.returncode != 0:
            raise Exception(f"Command failed with return code {process.returncode}: {stderr}")
    except Exception as e:
        logging.error(f"Error running command: {e}")
        raise

def backup(backup_file, log_file, config_file):
    command = ['dar', '-c', backup_file, '-B', config_file]
    logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    run_command(command)

def find_files_under_10MB(root_dir, relative_dirs):
    files_under_10MB = []
    root_dir = root_dir.strip()  # Strip any trailing whitespace
    for relative_dir in relative_dirs:
        directory = os.path.join(root_dir, relative_dir.strip())  # Strip any trailing whitespace from relative_dirs
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

def verify(backup_file, config_file):
    with open(config_file, 'r') as f:
        config_snippet = f.readlines()

    root_dir = [arg.split(' ')[1] for arg in config_snippet if arg.startswith('-R')][0].strip()
    relative_dirs = [arg.split(' ')[1] for arg in config_snippet if arg.startswith('-g')]

    if not relative_dirs:
        raise Exception("No include or specific files found in the config snippet.")
    
    files_under_10MB = find_files_under_10MB(root_dir, relative_dirs)
    if len(files_under_10MB) < 3:
        raise Exception("Not enough files under 10MB for verification in directories: " + ', '.join(relative_dirs))

    random_files = random.sample(files_under_10MB, 3)
    with tempfile.TemporaryDirectory() as tmpdirname:
        for file in random_files:
            relative_path = os.path.relpath(file, root_dir)
            restored_file_path = os.path.join(tmpdirname, relative_path)
            os.makedirs(os.path.dirname(restored_file_path), exist_ok=True)
            
            # Create command without adding -B to avoid using config snippet during restore
            command = ['dar', '-x', backup_file, '-g', relative_path, '-R', tmpdirname]
            logging.info(f"Running command: {' '.join(map(shlex.quote, command))}")
            run_command(command)

            if not filecmp.cmp(file, restored_file_path, shallow=False):
                raise Exception(f"File {relative_path} did not match the original after restoration.")
    
    logging.info("Verification of 3 random files under 10MB completed successfully.")

def main():
    parser = argparse.ArgumentParser(description="Backup and verify using dar with config snippets.")
    parser.add_argument('--backup-dir', required=True, help="Directory to save the backup file.")
    parser.add_argument('--log-file', required=True, help="Log file to capture dar output.")
    parser.add_argument('--config-dir', help="Directory containing config snippets.")
    parser.add_argument('--config-file', help="Specific config snippet file to use.")
    
    args = parser.parse_args()

    setup_logging(args.log_file)

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
            backup_file = os.path.join(args.backup_dir, f"{snippet_name}.dar")
            logging.info(f"Starting backup with config file {config_file}...")
            backup(backup_file, args.log_file, config_file)
            logging.info("Backup completed successfully.")

            logging.info("Starting verification...")
            verify(backup_file, config_file)
            logging.info("Verification completed successfully.")
    except Exception as e:
        logging.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
