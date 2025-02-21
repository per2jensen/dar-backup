import pytest
import os
import shutil
from pathlib import Path
from dar_backup.util import run_command
from tests.envdata import EnvData
from testdata_verification import (
    create_test_files, verify_backup_contents, 
    verify_restore_contents, test_files, run_backup_script
)

def test_restore_functionality(setup_environment, env):
    """
    Tests restoring backups and verifying integrity.
    """
    try:
        create_test_files(env)
        run_backup_script("--full-backup", env)
        backup_name = f"example_FULL_{env.datestamp}"
        
        # Ensure restore directory exists
        restore_path = Path(env.restore_dir)
        if restore_path.exists():
            shutil.rmtree(restore_path)
        restore_path.mkdir(parents=True, exist_ok=True)
        
        # Restore backup
        restore_command = ['dar', '-x', os.path.join(env.backup_dir, backup_name), '-R', env.restore_dir, '-Q']
        result = run_command(restore_command)
        
        assert result.returncode == 0, "Restore command failed!"
        
        # Verify restored content
        verify_restore_contents(test_files, backup_name, env)
        env.logger.info("Restore verification succeeded")
    except Exception as e:
        env.logger.exception("Restore functionality test failed")
        pytest.fail("Restore test encountered an exception")

def test_invalid_backup_handling(setup_environment, env):
    """
    Ensures the system handles invalid backup scenarios properly.
    """
    try:
        invalid_backup_name = "nonexistent_backup"
        restore_command = ['dar', '-x', os.path.join(env.backup_dir, invalid_backup_name), '-R', env.restore_dir, '-Q']
        result = run_command(restore_command)
        
        assert result.returncode != 0, "Expected failure on restoring nonexistent backup"
        env.logger.info("Handled invalid backup correctly")
    except Exception as e:
        env.logger.exception("Invalid backup handling test failed")
        pytest.fail("Invalid backup test encountered an exception")

def test_backup_with_large_files(setup_environment, env):
    """
    Tests backup process with large files to ensure stability.
    """
    try:
        large_file_path = os.path.join(env.test_dir, 'data', 'large_file.bin')
        with open(large_file_path, 'wb') as f:
            f.write(os.urandom(500 * 1024 * 1024))  # 500MB file
        
        run_backup_script("--full-backup", env)
        
        backup_name = f"example_FULL_{env.datestamp}"
        verify_backup_contents(['data/large_file.bin'], backup_name, env)
        env.logger.info("Backup with large files verification succeeded")
    except Exception as e:
        env.logger.exception("Large file backup test failed")
        pytest.fail("Large file backup test encountered an exception")

def test_multiple_incremental_backups(setup_environment, env):
    """
    Ensures that multiple incremental backups are handled correctly.
    """
    try:
        create_test_files(env)
        run_backup_script("--full-backup", env)
        run_backup_script("--differential-backup", env)  # Ensure DIFF backup exists
        
        modified_file_path = os.path.join(env.test_dir, 'data', 'file2.txt')
        for i in range(3):  # Perform multiple incremental backups
            with open(modified_file_path, 'a') as f:
                f.write(f"\nChange {i+1}")
            run_backup_script("--incremental-backup", env)
        
        backup_name = f"example_INCR_{env.datestamp}"
        backup_file_path = os.path.join(env.backup_dir, f"{backup_name}.1.dar")
        
        # Ensure backup file exists before verification
        assert os.path.exists(backup_file_path), f"Incremental backup file {backup_file_path} is missing!"
        
        verify_backup_contents(['data/file2.txt'], backup_name, env)
        env.logger.info("Multiple incremental backup verification succeeded")
    except Exception as e:
        env.logger.exception("Multiple incremental backup test failed")
        pytest.fail("Multiple incremental backup test encountered an exception")
