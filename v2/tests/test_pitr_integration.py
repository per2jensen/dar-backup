#!/usr/bin/env python3

import os
import shutil
import sys
import time
from datetime import datetime, timedelta

# Add src to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner
from tests.testdata_verification import run_backup_script

def test_pitr_integration_flow(setup_environment, env):
    """
    Integration test for Point-in-Time Recovery.
    1. Create file (Version 1).
    2. Full Backup.
    3. Modify file (Version 2).
    4. Incremental Backup.
    5. Restore at T < Backup2 -> Expect Version 1.
    6. Restore at T > Backup2 -> Expect Version 2.
    """
    
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    data_file = os.path.join(env.data_dir, "pitr_test_file.txt")
    
    # --- Step 1: Version 1 ---
    env.logger.info("Creating Version 1 of file")
    with open(data_file, "w") as f:
        f.write("Version 1 content")
    
    # Sleep to ensure file mtime is clearly before the backup time
    time.sleep(2)
    
    # --- Step 2: Full Backup ---
    env.logger.info("Running FULL backup")
    run_backup_script("--full-backup", env)
    
    # Capture timestamp *after* full backup but *before* modification
    # This will be our target time for restoring Version 1
    # We add a small buffer to ensure we are "after" the backup creation
    time.sleep(2)
    restore_time_v1 = datetime.now()
    env.logger.info(f"Target Restore Time for V1: {restore_time_v1}")
    time.sleep(2)

    # --- Step 3: Version 2 ---
    env.logger.info("Creating Version 2 of file (modification)")
    with open(data_file, "w") as f:
        f.write("Version 2 content")
        
    time.sleep(2)
    
    # --- Step 4: Differential Backup ---
    env.logger.info("Running DIFFERENTIAL backup")
    run_backup_script("--differential-backup", env)
    
    time.sleep(2)
    restore_time_v2 = datetime.now()
    env.logger.info(f"Target Restore Time for V2: {restore_time_v2}")
    
    # --- Step 5: Restore V1 ---
    restore_dir_v1 = os.path.join(env.test_dir, "restore_v1")
    os.makedirs(restore_dir_v1, exist_ok=True)
    
    # Relative path for restore (as stored in backup)
    # dar stores absolute paths relative to root, but -R rebases them.
    # If we backed up env.data_dir (e.g., /tmp/unit-test/.../data),
    # the file in backup is /tmp/unit-test/.../data/pitr_test_file.txt
    # We must pass the full path to --restore-path
    
    restore_path = data_file.lstrip("/")
    
    # Format time for the CLI
    time_str_v1 = restore_time_v1.strftime("%Y-%m-%d %H:%M:%S")
    
    # Debug: List archive contents to verify path storage
    full_archive = os.path.join(env.backup_dir, f"example_FULL_{datetime.now().strftime('%Y-%m-%d')}.1.dar")
    env.logger.info(f"Listing contents of {full_archive}")
    runner.run(["dar", "-l", full_archive.replace(".1.dar", ""), "-Q"])

    # Debug: Check if file exists in DB
    db_path = os.path.join(env.backup_dir, "example.db")
    env.logger.info(f"Checking for file in DB: {db_path}")
    runner.run(["dar_manager", "-B", db_path, "-f", restore_path])
    
    # Debug: List archives in DB
    env.logger.info("Listing archives in DB:")
    runner.run(["dar_manager", "-B", db_path, "-l"])

    env.logger.info(f"Attempting restore of V1 to {restore_dir_v1} at {time_str_v1}")
    
    cmd_v1 = [
        "manager",
        "--config-file", env.config_file,
        "--backup-def", "example",  # 'example' is created by conftest
        "--restore-path", restore_path,
        "--when", time_str_v1,
        "--target", restore_dir_v1,
        "--log-stdout",
        "--verbose"
    ]
    
    result_v1 = runner.run(cmd_v1)
    
    if result_v1.returncode != 0:
        env.logger.error(f"V1 Restore failed: {result_v1.stderr}")
        assert False, f"V1 Restore failed: {result_v1.stderr}"
        
    # Verify content V1
    # The restored file structure mirrors the absolute path: 
    # restore_dir_v1 + data_file (which is absolute)
    # Wait, if data_file is /tmp/..., and we use -R /restore, 
    # it typically restores to /restore/tmp/...
    
    # Debug: List contents of restore directory to verify path
    env.logger.info(f"Listing contents of {restore_dir_v1}:")
    for root, dirs, files in os.walk(restore_dir_v1):
        for name in files:
            env.logger.info(os.path.join(root, name))

    restored_file_v1 = os.path.join(restore_dir_v1, data_file.lstrip("/"))
    assert os.path.exists(restored_file_v1), f"Restored file not found at {restored_file_v1}"
    
    with open(restored_file_v1, "r") as f:
        content = f.read()
        assert content == "Version 1 content", f"Expected 'Version 1 content', got '{content}'"
        
    env.logger.info("Version 1 verification passed!")

    # --- Step 6: Restore V2 ---
    restore_dir_v2 = os.path.join(env.test_dir, "restore_v2")
    os.makedirs(restore_dir_v2, exist_ok=True)
    
    time_str_v2 = restore_time_v2.strftime("%Y-%m-%d %H:%M:%S")
    env.logger.info(f"Attempting restore of V2 to {restore_dir_v2} at {time_str_v2}")

    cmd_v2 = [
        "manager",
        "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", restore_path,
        "--when", time_str_v2,
        "--target", restore_dir_v2,
        "--log-stdout"
    ]
    
    result_v2 = runner.run(cmd_v2)
    
    if result_v2.returncode != 0:
        env.logger.error(f"V2 Restore failed: {result_v2.stderr}")
        assert False, f"V2 Restore failed: {result_v2.stderr}"
        
    restored_file_v2 = os.path.join(restore_dir_v2, data_file.lstrip("/"))
    assert os.path.exists(restored_file_v2), f"Restored file not found at {restored_file_v2}"
    
    with open(restored_file_v2, "r") as f:
        content = f.read()
        assert content == "Version 2 content", f"Expected 'Version 2 content', got '{content}'"
        
    env.logger.info("Version 2 verification passed!")