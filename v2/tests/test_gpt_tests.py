import pytest
import os
import shutil
import re
import random
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
        restore_command = ['dar', '-x', os.path.join(env.backup_dir, backup_name), '-R', env.restore_dir, '-Q', '-B', env.dar_rc,  'restore-options']
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
        restore_command = ['dar', '-x', os.path.join(env.backup_dir, invalid_backup_name), '-R', env.restore_dir, '-Q', '-B', env.dar_rc,  'restore-options']
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

def test_par2_repair_bit_rot(setup_environment, env):
    """
    Tests whether par2 can successfully repair an archive with simulated bit rot using dar-backup's generated PAR2 files.
    """
    try:
        create_test_files(env)
        run_backup_script("--full-backup", env)
        backup_name = f"example_FULL_{env.datestamp}"
        backup_file = os.path.join(env.backup_dir, f"{backup_name}.1.dar")
        par2_files = [f for f in os.listdir(env.backup_dir) if f.startswith(backup_name) and f.endswith(".par2")]
        
        assert par2_files, "No PAR2 files were generated by dar-backup!"
        par2_file = os.path.join(env.backup_dir, par2_files[0])
        
        # Simulate bit rot by corrupting a small portion (less than 5%) of the archive
        file_size = os.path.getsize(backup_file)
        corruption_size = int(file_size * 0.04)  # Corrupt only 4% of the file
        
        with open(backup_file, 'r+b') as f:
            for _ in range(corruption_size // 512):  # Distribute corruption in small chunks
                f.seek(os.urandom(1)[0] % file_size)  # Randomly position within file
                f.write(os.urandom(512))  # Corrupt 512 bytes
        
        # Attempt repair with PAR2
        repair_command = ['par2', 'repair', par2_file]
        result = run_command(repair_command)
        assert result.returncode == 0, "PAR2 failed to repair the archive!"
        
        # Verify restoration after repair
        restore_command = ['dar', '-x', backup_file, '-R', env.restore_dir, '-Q', '-B', env.dar_rc,  'restore-options']
        result = run_command(restore_command)
        assert result.returncode == 0, "Restore failed after PAR2 repair!"
        
        env.logger.info("PAR2 successfully repaired bit rot corruption using dar-backup's generated files")
    except Exception as e:
        env.logger.exception("PAR2 repair test failed")
        pytest.fail("PAR2 repair test encountered an exception")


def test_par2_insufficient_redundancy(setup_environment, env):
    """
    Tests if PAR2 fails when bit rot exceeds available redundancy.
    """
    try:
        create_test_files(env)
        run_backup_script("--full-backup", env)
        backup_name = f"example_FULL_{env.datestamp}"
        backup_file = os.path.join(env.backup_dir, f"{backup_name}.1.dar")
        par2_files = [f for f in os.listdir(env.backup_dir) if f.startswith(backup_name) and f.endswith(".par2")]
        
        assert par2_files, "No PAR2 files were generated by dar-backup!"
        par2_file = os.path.join(env.backup_dir, par2_files[0])
        
        # Corrupt more than 5% of the file in structured chunks
        file_size = os.path.getsize(backup_file)
        corruption_size = int(file_size * 0.06)  # Corrupt 6% of the file
        chunk_size = corruption_size // 3
        
        with open(backup_file, 'r+b') as f:
            f.seek(0)
            f.write(os.urandom(chunk_size))  # Corrupt start
            
            f.seek(file_size // 2)
            f.write(os.urandom(chunk_size))  # Corrupt middle
            
            f.seek(file_size - chunk_size)
            f.write(os.urandom(chunk_size))  # Corrupt end
        
        # Attempt repair with PAR2
        repair_command = ['par2', 'repair', par2_file]
        result = run_command(repair_command)
        assert result.returncode != 0, "PAR2 unexpectedly succeeded despite excessive corruption!"
        
        env.logger.info("PAR2 correctly failed due to insufficient redundancy")
    except Exception as e:
        env.logger.exception("PAR2 excessive corruption test failed")
        pytest.fail("PAR2 excessive corruption test encountered an exception")



def test_extreme_restore_failure(setup_environment, env):
    """
    Attempts to make dar fail by severely corrupting an archive beyond recovery.
    """
    try:
        create_test_files(env)
        run_backup_script("--full-backup", env)
        backup_name = f"example_FULL_{env.datestamp}"
        backup_file = os.path.join(env.backup_dir, f"{backup_name}.1.dar")
        
        # Corrupt the entire file by overwriting with random data
        with open(backup_file, 'wb') as f:
            f.write(os.urandom(os.path.getsize(backup_file)))
        
        # Attempt to restore
        restore_command = ['dar', '-x', backup_file, '-R', env.restore_dir, '-Q', '-B', env.dar_rc,  'restore-options']
        result = run_command(restore_command)
        
        assert result.returncode != 0, "dar unexpectedly succeeded despite extreme corruption!"
        env.logger.info("dar correctly failed due to extreme corruption")
    except Exception as e:
        env.logger.exception("Extreme restore failure test failed")
        pytest.fail("Extreme restore failure test encountered an exception")


def test_metadata_corruption_failure(setup_environment, env):
    """
    Attempts to make dar fail by corrupting only the metadata portion of the archive.
    """
    try:
        create_test_files(env)
        run_backup_script("--full-backup", env)
        backup_name = f"example_FULL_{env.datestamp}"
        backup_file = os.path.join(env.backup_dir, f"{backup_name}.1.dar")
        
        # Corrupt only the first 4KB of the file, which likely contains metadata
        with open(backup_file, 'r+b') as f:
            f.seek(0)
            f.write(os.urandom(4096))
        
        # Attempt to restore
        restore_command = ['dar', '-x', backup_file, '-R', env.restore_dir, '-Q', '-B', env.dar_rc,  'restore-options']
        result = run_command(restore_command)
        
        assert result.returncode != 0, "dar unexpectedly succeeded despite metadata corruption!"
        env.logger.info("dar correctly failed due to metadata corruption")
    except Exception as e:
        env.logger.exception("Metadata corruption failure test failed")
        pytest.fail("Metadata corruption failure test encountered an exception")


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
        restore_command = ['dar', '-x', os.path.join(env.backup_dir, backup_name), '-R', env.restore_dir, '-Q', '-B', env.dar_rc,  'restore-options']
        result = run_command(restore_command)
        
        assert result.returncode == 0, "Restore command failed!"
        
        # Verify restored content
        verify_restore_contents(test_files, backup_name, env)
        env.logger.info("Restore verification succeeded")
    except Exception as e:
        env.logger.exception("Restore functionality test failed")
        pytest.fail("Restore test encountered an exception")

