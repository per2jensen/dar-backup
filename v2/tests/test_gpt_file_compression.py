import pytest
import re
import os
import shutil
from pathlib import Path
from dar_backup.util import run_command
from tests.envdata import EnvData

def create_test_files(env):
    """Creates test files with different cases and compression types."""
    file_types = [
        "gz", "bz2", "xz", "zip", "rar", "7z", "tar", "tgz", "tbz2", "txz",
        "jpg", "jpeg", "png", "gif", "bmp", "tiff", "svg",
        "mp4", "avi", "mkv", "mov", "wmv", "flv", "mpeg", "mpg"
    ]
    test_data = b"TestData" * 1000  # 10KB of test data
    
    for ext in file_types:
        for case in ["lower", "upper"]:
            filename = f"test_file.{ext}" if case == "lower" else f"TEST_FILE.{ext.upper()}"
            file_path = os.path.join(env.data_dir, filename)
            with open(file_path, "wb") as f:
                f.write(test_data)
    

def test_dar_backup_compression_exclusion(setup_environment, env):
    """Tests that dar excludes specified file types from compression and restores them correctly."""
    create_test_files(env)
    
    # Run full backup
    backup_name = f"example_FULL_{env.datestamp}"
    backup_file = os.path.join(env.backup_dir, f"{backup_name}.1.dar")
    run_command(['dar-backup', '-F', '-d', "example", '--verbose', '--log-stdout', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout'], timeout=600)
    
    assert os.path.exists(backup_file), "Backup file was not created!"
    
    # Restore backup
    restore_command = ["dar-backup", "--restore", backup_name, '--verbose', '--log-stdout', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    result = run_command(restore_command, timeout=600)
    assert result.returncode == 0, "Restore command failed!"
    
    # Verify restored files
    for root, _, files in os.walk(env.data_dir):
        for file in files:
            restored_file = os.path.join(env.restore_dir, env.data_dir, file)
            assert os.path.exists(restored_file), f"Missing restored file: {file}"
            assert os.path.getsize(restored_file) > 0, f"Restored file is empty: {file}"
    
    # Verify `dar` did not compress files
    compression_check_failed = False
    backed_up_files = {f'test_file.{ext}': False for ext in [
        "gz", "bz2", "xz", "zip", "rar", "7z", "tar", "tgz", "tbz2", "txz",
        "jpg", "jpeg", "png", "gif", "bmp", "tiff", "svg",
        "mp4", "avi", "mkv", "mov", "wmv", "flv", "mpeg", "mpg"
    ]}
    backed_up_files.update({f'TEST_FILE.{ext.upper()}': False for ext in backed_up_files})
    list_command = ["dar", "-l", backup_file, "-am", "-as", "-Q"]
    list_result = run_command(list_command)
    


    # Ensure no compression percentage exists in the output
    for line in list_result.stdout.splitlines():
        env.logger.debug(f"line: {line}")
        columns = line.split()
        #env.logger.debug(f"split line: {columns} ")
        match = None
        if len(columns) > 1:
            filename = os.path.basename(columns[-1])
        #env.logger.debug(f"filename: {filename}") 

        if len(columns) > 1 and filename in backed_up_files:
            match = re.search(r'\[([0-9]+%)\]', line)  # extracts percentage if present
            if match:
                env.logger.debug(f"match: {match}")
        columns = line.split()
        if match and filename in backed_up_files:
            compression_check_failed = True
            env.logger.error(f"Compression detected in line: {line}")
    
    assert not compression_check_failed, "Some files were compressed when they should not have been!"
    
    for ext in [
        "gz", "bz2", "xz", "zip", "rar", "7z", "tar", "tgz", "tbz2", "txz",
        "jpg", "jpeg", "png", "gif", "bmp", "tiff", "svg",
        "mp4", "avi", "mkv", "mov", "wmv", "flv", "mpeg", "mpg"
    ]:
        assert f"test_file.{ext}" in list_result.stdout or f"TEST_FILE.{ext.upper()}" in list_result.stdout, \
            f"{ext} files may have been compressed incorrectly!"
    
    env.logger.info("DAR correctly excluded file types from compression and restored them successfully.")

    assert False, "Test not implemented"