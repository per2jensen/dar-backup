#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import random
import filecmp
import tempfile

def run_command(command, log_file):
    with open(log_file, 'a') as log:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        print(stdout)
        print(stderr, file=sys.stderr)
        log.write(stdout)
        log.write(stderr)
        if process.returncode != 0:
            raise Exception(f"Command failed with return code {process.returncode}: {stderr}")

def backup(backup_file, log_file, config_file):
    command = ['dar', '-c', backup_file, '-B', config_file]
    print(f"Running command: {' '.join(command)}")  # Debug output
    run_command(command, log_file)

def find_files_under_10MB(root_dir, relative_dirs):
    files_under_10MB = []
    for relative_dir in relative_dirs:
        directory = os.path.join(root_dir, relative_dir)
        print(f"Searching in directory: {directory}")  # Debug output
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_size = os.path.getsize(file_path)
                print(f"Found file: {file_path}, Size: {file_size} bytes")  # Debug output
                if file_size < 10 * 1024 * 1024:  # 10MB
                    print(f"File under 10MB: {file_path}")  # Debug output
                    files_under_10MB.append(file_path)
    return files_under_10MB

def verify(backup_file, log_file, config_file):
    # Extract the root directory and relative directories from the config snippet
    with open(config_file, 'r') as f:
        config_snippet = f.readlines()

    root_dir = [arg.split(' ')[1] for arg in config_snippet if arg.startswith('-R')][0]
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
            
            command = ['dar', '-x', backup_file, '-g', relative_path, '-R', tmpdirname, '-B', config_file]
            print(f"Running command: {' '.join(command)}")  # Debug output
            run_command(command, log_file)

            if not filecmp.cmp(file, restored_file_path, shallow=False):
                raise Exception(f"File {relative_path} did not match the original after restoration.")
    
    with open(log_file, 'a') as log:
        log.write("Verification of 3 random files under 10MB completed successfully.\n")

def main():
    parser = argparse.ArgumentParser(description="Backup and verify using dar with config snippets.")
    parser.add_argument('--backup-dir', required=True, help="Directory to save the backup file.")
    parser.add_argument('--log-file', required=True, help="Log file to capture dar output.")
    parser.add_argument('--config-dir', help="Directory containing config snippets.")
    parser.add_argument('--config-file', help="Specific config snippet file to use.")
    
    args = parser.parse_args()

    log_file = args.log_file

    config_files = []

    if args.config_file:
        config_files.append((os.path.basename(args.config_file).split('.')[0], args.config_file))
    elif args.config_dir:
        for root, _, files in os.walk(args.config_dir):
            for file in files:
                config_files.append((file.split('.')[0], os.path.join(root, file)))
    else:
        print("Error: Either --config-dir or --config-file must be specified.")
        sys.exit(1)

    try:
        for snippet_name, config_file in config_files:
            backup_file = f"{args.backup_dir}/{snippet_name}.dar"
            print(f"Starting backup with config file {config_file}...")
            backup(backup_file, log_file, config_file)
            print("Backup completed successfully.")

            print("Starting verification...")
            verify(backup_file, log_file, config_file)
            print("Verification completed successfully.")
    except Exception as e:
        print(f"Error: {e}")
        with open(log_file, 'a') as log:
            log.write(f"Error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
