import pytest
import re
import os
import shutil
from pathlib import Path
from dar_backup.util import run_command
from tests.envdata import EnvData


file_types = [
    "gz", "bz2", "xz", "zip", "rar", "7z", "tar", "tgz", "tbz2", "txz",
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "svg",
    "mp4", "avi", "mkv", "mov", "wmv", "flv", "mpeg", "mpg"
]


def create_test_files(env):
    """Creates test files with different cases and compression types."""
    test_data = b"TestData" * 1000  # 10KB of test data
    
    for ext in file_types:
        for case in ["lower", "upper"]:
            filename = f"test_file.{ext}" if case == "lower" else f"TEST_FILE.{ext.upper()}"
            file_path = os.path.join(env.data_dir, filename)
            with open(file_path, "wb") as f:
                f.write(test_data)
    

def check_no_compression(list_result, backed_up_files, env):
    """Ensure no compression percentage exists in the output for the test files.
    
    Args:
        list_result (str): Output of the `dar -l` command.
        backed_up_files (dict): Dictionary of test files and their compression status.
        env (EnvData): Environment data.

    Returns:
        bool: True if no compression of files were discovered, False otherwise.
    """
    compression_not_found = True
    env.logger.debug(f"backed_up_files: {backed_up_files}")
    for line in list_result.splitlines():
        #env.logger.debug(f"---------\nline: {line}")
        columns = line.split()
        #env.logger.debug(f"split line: {columns} ")
        match = None
        match = re.search(r'\[\s*(\d+%)\s*\]', line)  # extracts percentage if present
        #env.logger.debug(f"match: {match}")
        if match:
            if len(columns) > 1:
                backed_up_file = os.path.basename(columns[-1])
                #env.logger.debug(f"filename: {backed_up_file}")   
                if backed_up_file in backed_up_files:
                    #env.logger.debug(f"match found for file: {backed_up_file}")
                    compression_not_found = False
                    env.logger.error(f"Erroneous compression detected in line: {line}")
    return compression_not_found


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
    backed_up_files = {f'test_file.{ext}': False for ext in file_types}
    backed_up_files.update({f'TEST_FILE.{ext.upper()}': False for ext in file_types})
    list_command = ["dar", "-l", backup_file, "-am", "-as", "-Q"]
    list_result = run_command(list_command)
    compression_check = check_no_compression(list_result.stdout, backed_up_files, env)
    assert compression_check, "Some files were compressed when they should not have been!"

    fake_list_result = """
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxrwxrwt   root	root	390 kio	Sat Feb 22 11:12:36 2025	tmp
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	390 kio	Sat Feb 22 11:12:36 2025	tmp/unit-test
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	390 kio	Sat Feb 22 11:12:36 2025	tmp/unit-test/test_dar_backup_compression_exclusion
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	390 kio	Sat Feb 22 11:12:36 2025	tmp/unit-test/test_dar_backup_compression_exclusion/data
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   pj	pj	7 kio	Sat Feb 22 11:12:36 2025	tmp/unit-test/test_dar_backup_compression_exclusion/data/test_file.gz
[Saved][ ]       [-L-][   0%][ ]  -rw-rw-r--   pj	pj	7 kio	Sat Feb 22 11:12:36 2025	tmp/unit-test/test_dar_backup_compression_exclusion/data/TEST_FILE.GZ
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   pj	pj	7 kio	Sat Feb 22 11:12:36 2025	tmp/unit-test/test_dar_backup_compression_exclusion/data/test_file.bz2
[Saved][ ]       [-L-][1111%][ ]  -rw-rw-r--   pj	pj	7 kio	Sat Feb 22 11:12:36 2025	tmp/unit-test/test_dar_backup_compression_exclusion/data/TEST_FILE.BZ2
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   pj	pj	7 kio	Sat Feb 22 11:12:36 2025	tmp/unit-test/test_dar_backup_compression_exclusion/data/test_file.xz
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   pj	pj	7 kio	Sat Feb 22 11:12:36 2025	tmp/unit-test/test_dar_backup_compression_exclusion/data/TEST_FILE.XZ
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   pj	pj	7 kio	Sat Feb 22 11:12:36 2025	tmp/unit-test/test_dar_backup_compression_exclusion/data/test_file.zip
"""

    compression_check_fails = check_no_compression(fake_list_result, backed_up_files, env)
    env.logger.debug(f"'compression_check_must_fail' : {compression_check_fails}")
    assert not compression_check_fails, "Some files were compressed when they should not have been!"

    # Verify all files were restored    
    for ext in file_types:
        assert f"test_file.{ext}" in list_result.stdout and f"TEST_FILE.{ext.upper()}" in list_result.stdout, \
            f"{ext} files may have been backed up or restored incorrectly"
    
    env.logger.info("DAR correctly excluded file types from compression and restored them successfully.")
