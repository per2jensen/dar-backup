#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import random
import filecmp
import tempfile

DEFAULT_RC_FILE = os.path.expanduser('~/.darrc')

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

def backup(backup_file, log_file, rc_file, config_snippet):
    command = ['dar', '-K', rc_file, '-c', backup_file] + config_snippet
    run_command(command, log_file)

def find_files_under_10MB(directory):
    files_under_10MB = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.getsize(file_path) < 10 * 1024 * 1024:  # 10MB
                files_under_10MB.append(file_path)
    return files_under_10MB

def verify(backup_file, log_file, rc_file, config_snippet):
    # Extract the root directory from the config snippet
    root_dirs = [arg.split(' ')[1] for arg in config_snippet if arg.startswith('-g')]
    if not root_dirs:
        raise Exception("No include or specific files found in the config snippet.")
    
    for root_dir in root_dirs:
        files_under_10MB = find_files_under_10MB(root_dir)
        if len(files_under_10MB) < 3:
            raise Exception("Not enough files under 10MB for verification in directory: " + root_dir)

        random_files = random.sample(files_under_10MB, 3)
        with tempfile.TemporaryDirectory() as tmpdirname:
            for file in random_files:
                relative_path = os.path.relpath(file, root_dir)
                restored_file_path = os.path.join(tmpdirname, relative_path)
                os.makedirs(os.path.dirname(restored_file_path), exist_ok=True)
                
                command = ['dar', '-K', rc_file, '-x', backup_file, '-R', tmpdirname, '-g', relative_path]
                run_command(command, log_file)

                if not filecmp.cmp(file, restored_file_path, shallow=False):
                    raise Exception(f"File {relative_path} did not match the original after restoration.")
    
    with open(log_file, 'a') as log:
        log.write("Verification of 3 random files under 10MB completed successfully.\n")

def read_config_snippet(file_path):
    with open(file_path, 'r') as file:
        return file.read().splitlines()

def main():
    parser = argparse.ArgumentParser(description="Backup and verify using dar with config snippets.")
    parser.add_argument('--backup-dir', required=True, help="Directory to save the backup file.")
    parser.add_argument('--log-file', required=True, help="Log file to capture dar output.")
    parser.add_argument('--rc-file', default=DEFAULT_RC_FILE, help="Path to the dar configuration file (default: ~/.darrc).")
    parser.add_argument('--config-dir', help="Directory containing config snippets.")
    parser.add_argument('--config-file', help="Specific config snippet file to use.")
    
    args = parser.parse_args()

    log_file = args.log_file
    rc_file = args.rc_file

    config_snippets = []

    if args.config_file:
        config_snippets.append((os.path.basename(args.config_file), read_config_snippet(args.config_file)))
    elif args.config_dir:
        for root, _, files in os.walk(args.config_dir):
            for file in files:
                config_snippets.append((file, read_config_snippet(os.path.join(root, file))))
    else:
        print("Error: Either --config-dir or --config-file must be specified.")
        sys.exit(1)

    try:
        for snippet_name, snippet in config_snippets:
            backup_file = f"{args.backup_dir}/{snippet_name}.dar"
            print(f"Starting backup with config snippet {snippet_name}...")
            backup(backup_file, log_file, rc_file, snippet)
            print("Backup completed successfully.")

            print("Starting verification...")
            verify(backup_file, log_file, rc_file, snippet)
            print("Verification completed successfully.")
    except Exception as e:
        print(f"Error: {e}")
        with open(log_file, 'a') as log:
            log.write(f"Error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
