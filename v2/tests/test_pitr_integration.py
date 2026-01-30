#!/usr/bin/env python3

import glob
import os
import random
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
    4. Differential Backup.
    5. Restore at T < Backup2 -> Expect Version 1.
    6. Restore at T > Backup2 -> Expect Version 2.
    7. Modify file (Version 3).
    8. Incremental Backup.
    9. Restore at T > Backup3 -> Expect Version 3.
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

    # --- Step 7: Version 3 ---
    env.logger.info("Creating Version 3 of file (modification)")
    with open(data_file, "w") as f:
        f.write("Version 3 content")

    time.sleep(2)

    # --- Step 8: Incremental Backup ---
    env.logger.info("Running INCREMENTAL backup")
    run_backup_script("--incremental-backup", env)

    time.sleep(2)
    restore_time_v3 = datetime.now()
    env.logger.info(f"Target Restore Time for V3: {restore_time_v3}")

    # --- Step 9: Restore V3 ---
    restore_dir_v3 = os.path.join(env.test_dir, "restore_v3")
    os.makedirs(restore_dir_v3, exist_ok=True)

    time_str_v3 = restore_time_v3.strftime("%Y-%m-%d %H:%M:%S")
    env.logger.info(f"Attempting restore of V3 to {restore_dir_v3} at {time_str_v3}")

    cmd_v3 = [
        "manager",
        "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", restore_path,
        "--when", time_str_v3,
        "--target", restore_dir_v3,
        "--log-stdout"
    ]

    result_v3 = runner.run(cmd_v3)

    if result_v3.returncode != 0:
        env.logger.error(f"V3 Restore failed: {result_v3.stderr}")
        assert False, f"V3 Restore failed: {result_v3.stderr}"

    restored_file_v3 = os.path.join(restore_dir_v3, data_file.lstrip("/"))
    assert os.path.exists(restored_file_v3), f"Restored file not found at {restored_file_v3}"

    with open(restored_file_v3, "r") as f:
        content = f.read()
        assert content == "Version 3 content", f"Expected 'Version 3 content', got '{content}'"

    env.logger.info("Version 3 verification passed!")


def test_pitr_integration_tree_structure(setup_environment, env):
    """
    Integration test for PITR with a larger tree:
    - 3 top-level directories, each with 3 levels of subdirectories
    - >=50 entries at start
    - >=50 entries added after FULL
    - >=50 entries modified/deleted after DIFF
    - verify tree structure after FULL, DIFF, and INCR via PITR restores
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    # Clean out any default test data from fixture setup
    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    expected = {}

    def _norm(rel_path: str) -> str:
        return rel_path.replace(os.sep, "/")

    def add_dir(rel_path: str):
        parts = rel_path.split(os.sep)
        current = ""
        for part in parts:
            current = os.path.join(current, part) if current else part
            current_norm = _norm(current)
            if current_norm not in expected:
                expected[current_norm] = ("dir", None)
                os.makedirs(os.path.join(env.data_dir, current), exist_ok=True)

    def add_file(rel_path: str, content: str):
        parent = os.path.dirname(rel_path)
        if parent:
            add_dir(parent)
        expected[_norm(rel_path)] = ("file", content)
        with open(os.path.join(env.data_dir, rel_path), "w") as f:
            f.write(content)

    def add_symlink(rel_path: str, target: str):
        parent = os.path.dirname(rel_path)
        if parent:
            add_dir(parent)
        expected[_norm(rel_path)] = ("link", target)
        os.symlink(target, os.path.join(env.data_dir, rel_path))

    def remove_entry(rel_path: str):
        rel_norm = _norm(rel_path)
        abs_path = os.path.join(env.data_dir, rel_path)
        if os.path.islink(abs_path) or os.path.isfile(abs_path):
            os.remove(abs_path)
        elif os.path.isdir(abs_path):
            shutil.rmtree(abs_path)
        for key in list(expected.keys()):
            if key == rel_norm or key.startswith(rel_norm + "/"):
                expected.pop(key, None)

    def modify_file(rel_path: str, content: str):
        abs_path = os.path.join(env.data_dir, rel_path)
        with open(abs_path, "w") as f:
            f.write(content)
        expected[_norm(rel_path)] = ("file", content)

    def snapshot_tree(base_dir: str):
        actual = {}
        for root, dirs, files in os.walk(base_dir):
            # Handle directories (including symlinked dirs)
            for d in list(dirs):
                path = os.path.join(root, d)
                rel = os.path.relpath(path, base_dir)
                rel_norm = _norm(rel)
                if os.path.islink(path):
                    actual[rel_norm] = ("link", os.readlink(path))
                    dirs.remove(d)
                else:
                    actual[rel_norm] = ("dir", None)
            for f in files:
                path = os.path.join(root, f)
                rel = os.path.relpath(path, base_dir)
                rel_norm = _norm(rel)
                if os.path.islink(path):
                    actual[rel_norm] = ("link", os.readlink(path))
                else:
                    with open(path, "r") as fh:
                        actual[rel_norm] = ("file", fh.read())
        return actual

    def restore_and_verify(restore_time: datetime, restore_dir: str, restore_paths):
        os.makedirs(restore_dir, exist_ok=True)
        cmd = [
            "manager",
            "--config-file", env.config_file,
            "--backup-def", "example",
            "--restore-path",
        ]
        cmd.extend(restore_paths)
        cmd.extend([
            "--when", restore_time.strftime("%Y-%m-%d %H:%M:%S"),
            "--target", restore_dir,
            "--log-stdout",
        ])
        result = runner.run(cmd)
        if result.returncode != 0:
            env.logger.error(f"Restore failed: {result.stderr}")
            assert False, f"Restore failed: {result.stderr}"

        restored_root = os.path.join(restore_dir, env.data_dir.lstrip("/"))
        actual = snapshot_tree(restored_root)
        assert actual == expected, "Restored tree does not match expected structure"

    # --- Step 1: build initial tree ---
    top_dirs = ["alpha", "beta", "gamma"]
    restore_roots = [os.path.join(env.data_dir.lstrip("/"), top) for top in top_dirs]
    deep_files = []
    symlinks = []
    empty_dirs = []

    for top in top_dirs:
        deep_dir = os.path.join(top, "l1", "l2", "l3")
        add_dir(deep_dir)
        for i in range(1, 21):
            rel = os.path.join(deep_dir, f"file_{top}_{i:02d}.txt")
            add_file(rel, f"{top} v1 {i:02d}")
            deep_files.append(rel)
        for i in range(1, 4):
            empty_dir = os.path.join(top, f"empty_{i}")
            add_dir(empty_dir)
            empty_dirs.append(empty_dir)
        for i in range(1, 4):
            link_rel = os.path.join(deep_dir, f"link_file_{i}.lnk")
            target = f"file_{top}_{i:02d}.txt"
            add_symlink(link_rel, target)
            symlinks.append(link_rel)
        link_dir = os.path.join(top, "link_to_deep.lnk")
        add_symlink(link_dir, "l1/l2/l3")
        symlinks.append(link_dir)

    assert len(expected) >= 50

    # --- Step 2: FULL backup ---
    env.logger.info("Running FULL backup for tree structure test")
    run_backup_script("--full-backup", env)
    time.sleep(2)
    restore_time_v1 = datetime.now()

    restore_and_verify(restore_time_v1, os.path.join(env.test_dir, "restore_tree_v1"), restore_roots)

    # --- Step 3: add >=50 entries after FULL ---
    added_count = 0
    new_files = []
    new_symlinks = []
    new_dirs = []
    for top in top_dirs:
        deep_dir = os.path.join(top, "l1", "l2", "l3")
        for i in range(1, 11):
            rel = os.path.join(deep_dir, f"file_{top}_new_{i:02d}.txt")
            add_file(rel, f"{top} v2 {i:02d}")
            new_files.append(rel)
            added_count += 1
    for i in range(1, 11):
        rel = os.path.join(top_dirs[i % 3], f"added_dir_{i:02d}")
        add_dir(rel)
        new_dirs.append(rel)
        added_count += 1
    for i in range(1, 11):
        link_rel = os.path.join(top_dirs[i % 3], "l1", "l2", "l3", f"link_new_{i:02d}.lnk")
        target = f"file_{top_dirs[i % 3]}_new_{i:02d}.txt"
        add_symlink(link_rel, target)
        new_symlinks.append(link_rel)
        added_count += 1

    assert added_count >= 50

    # --- Step 4: DIFF backup ---
    env.logger.info("Running DIFFERENTIAL backup for tree structure test")
    run_backup_script("--differential-backup", env)
    time.sleep(2)
    restore_time_v2 = datetime.now()

    restore_and_verify(restore_time_v2, os.path.join(env.test_dir, "restore_tree_v2"), restore_roots)

    # --- Step 5: modify/delete >=50 entries after DIFF ---
    modified = 0
    deleted = 0

    for rel in deep_files[:15] + new_files[:15]:
        modify_file(rel, f"v3 modified {rel}")
        modified += 1
    for rel in new_files[15:25]:
        remove_entry(rel)
        deleted += 1
    for rel in symlinks[:5]:
        remove_entry(rel)
        deleted += 1
    for rel in new_dirs[:5]:
        remove_entry(rel)
        deleted += 1

    assert modified + deleted >= 50

    time.sleep(2)

    # --- Step 6: INCR backup ---
    env.logger.info("Running INCREMENTAL backup for tree structure test")
    run_backup_script("--incremental-backup", env)
    time.sleep(2)
    restore_time_v3 = datetime.now()

    restore_and_verify(restore_time_v3, os.path.join(env.test_dir, "restore_tree_v3"), restore_roots)


def test_pitr_integration_torture_chain(setup_environment, env):
    """
    Torture test:
    - same dir/link/file setup as tree structure test
    - FULL, DIFF, INCR, INCR, DIFF, INCR, INCR
    - after each backup: add/modify/delete >=25 entries
    - delete 2 randomly selected archives
    - attempt restores for timestamps between backups
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    # Clean out any default test data from fixture setup
    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    expected = {}
    all_files = []
    all_links = []
    empty_dirs = []

    def _norm(rel_path: str) -> str:
        return rel_path.replace(os.sep, "/")

    def add_dir(rel_path: str):
        parts = rel_path.split(os.sep)
        current = ""
        for part in parts:
            current = os.path.join(current, part) if current else part
            current_norm = _norm(current)
            if current_norm not in expected:
                expected[current_norm] = ("dir", None)
                os.makedirs(os.path.join(env.data_dir, current), exist_ok=True)

    def add_file(rel_path: str, content: str):
        parent = os.path.dirname(rel_path)
        if parent:
            add_dir(parent)
        expected[_norm(rel_path)] = ("file", content)
        with open(os.path.join(env.data_dir, rel_path), "w") as f:
            f.write(content)
        if rel_path not in all_files:
            all_files.append(rel_path)

    def add_symlink(rel_path: str, target: str):
        parent = os.path.dirname(rel_path)
        if parent:
            add_dir(parent)
        expected[_norm(rel_path)] = ("link", target)
        os.symlink(target, os.path.join(env.data_dir, rel_path))
        if rel_path not in all_links:
            all_links.append(rel_path)

    def remove_entry(rel_path: str):
        rel_norm = _norm(rel_path)
        abs_path = os.path.join(env.data_dir, rel_path)
        if os.path.islink(abs_path) or os.path.isfile(abs_path):
            os.remove(abs_path)
        elif os.path.isdir(abs_path):
            shutil.rmtree(abs_path)
        for key in list(expected.keys()):
            if key == rel_norm or key.startswith(rel_norm + "/"):
                expected.pop(key, None)
        if rel_path in all_files:
            all_files.remove(rel_path)
        if rel_path in all_links:
            all_links.remove(rel_path)
        if rel_path in empty_dirs:
            empty_dirs.remove(rel_path)

    def modify_file(rel_path: str, content: str):
        abs_path = os.path.join(env.data_dir, rel_path)
        with open(abs_path, "w") as f:
            f.write(content)
        expected[_norm(rel_path)] = ("file", content)

    def snapshot_tree(base_dir: str):
        actual = {}
        for root, dirs, files in os.walk(base_dir):
            for d in list(dirs):
                path = os.path.join(root, d)
                rel = os.path.relpath(path, base_dir)
                rel_norm = _norm(rel)
                if os.path.islink(path):
                    actual[rel_norm] = ("link", os.readlink(path))
                    dirs.remove(d)
                else:
                    actual[rel_norm] = ("dir", None)
            for f in files:
                path = os.path.join(root, f)
                rel = os.path.relpath(path, base_dir)
                rel_norm = _norm(rel)
                if os.path.islink(path):
                    actual[rel_norm] = ("link", os.readlink(path))
                else:
                    with open(path, "r") as fh:
                        actual[rel_norm] = ("file", fh.read())
        return actual

    def restore_and_check(restore_time: datetime, restore_dir: str, restore_paths, expected_snapshot, should_succeed: bool):
        os.makedirs(restore_dir, exist_ok=True)
        cmd = [
            "manager",
            "--config-file", env.config_file,
            "--backup-def", "example",
            "--restore-path",
        ]
        cmd.extend(restore_paths)
        cmd.extend([
            "--when", restore_time.strftime("%Y-%m-%d %H:%M:%S"),
            "--target", restore_dir,
            "--log-stdout",
        ])
        result = runner.run(cmd)
        if result.returncode != 0:
            if should_succeed:
                raise AssertionError(f"Restore failed but should have succeeded: {result.stderr}")
            env.logger.info(f"Restore failed as expected (missing archives): {result.stderr}")
            return False
        if not should_succeed:
            raise AssertionError("Restore succeeded but should have failed due to missing archives.")
        restored_root = os.path.join(restore_dir, env.data_dir.lstrip("/"))
        actual = snapshot_tree(restored_root)
        assert actual == expected_snapshot, "Restored tree does not match expected structure"
        return True

    def create_archive(backup_type: str, seq: int, base_archive: str = None):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        archive_base = os.path.join(env.backup_dir, f"example_{backup_type}_{timestamp}_{seq:02d}")
        cmd = [
            "dar", "-c", archive_base,
            "-N",
            "-B", env.dar_rc,
            "-B", backup_def_path,
            "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        result = runner.run(cmd, timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f"dar backup failed: {result.stderr}")
        add_cmd = [
            "manager",
            "--add-specific-archive", archive_base,
            "--config-file", env.config_file,
            "--log-stdout",
        ]
        add_result = runner.run(add_cmd, timeout=300)
        if add_result.returncode != 0:
            raise RuntimeError(f"manager add-specific-archive failed: {add_result.stderr}")
        return archive_base, datetime.now()

    def apply_mutations(round_id: int):
        added = 0
        modified = 0
        deleted = 0
        for top in top_dirs:
            deep_dir = os.path.join(top, "l1", "l2", "l3")
            for i in range(1, 5):
                rel = os.path.join(deep_dir, f"file_{top}_r{round_id}_{i:02d}.txt")
                add_file(rel, f"{top} round {round_id} {i:02d}")
                added += 1
        for i in range(1, 4):
            empty_dir = os.path.join(top_dirs[(round_id + i) % 3], f"empty_r{round_id}_{i}")
            add_dir(empty_dir)
            empty_dirs.append(empty_dir)
            added += 1
        for i in range(1, 4):
            top = top_dirs[(round_id + i) % 3]
            link_rel = os.path.join(top, "l1", "l2", "l3", f"link_r{round_id}_{i}.lnk")
            target = f"file_{top}_r{round_id}_{i:02d}.txt"
            add_symlink(link_rel, target)
            added += 1

        for idx, rel in enumerate(all_files[:10]):
            modify_file(rel, f"modified r{round_id} {idx}")
            modified += 1

        for rel in list(all_files[10:15]):
            remove_entry(rel)
            deleted += 1
        for rel in list(all_links[:3]):
            remove_entry(rel)
            deleted += 1
        for rel in list(empty_dirs[:2]):
            remove_entry(rel)
            deleted += 1

        assert added + modified + deleted >= 25

    # --- initial tree (same as previous test) ---
    top_dirs = ["alpha", "beta", "gamma"]
    restore_roots = [os.path.join(env.data_dir.lstrip("/"), top) for top in top_dirs]

    for top in top_dirs:
        deep_dir = os.path.join(top, "l1", "l2", "l3")
        add_dir(deep_dir)
        for i in range(1, 21):
            rel = os.path.join(deep_dir, f"file_{top}_{i:02d}.txt")
            add_file(rel, f"{top} v1 {i:02d}")
        for i in range(1, 4):
            empty_dir = os.path.join(top, f"empty_{i}")
            add_dir(empty_dir)
            empty_dirs.append(empty_dir)
        for i in range(1, 4):
            link_rel = os.path.join(deep_dir, f"link_file_{i}.lnk")
            target = f"file_{top}_{i:02d}.txt"
            add_symlink(link_rel, target)
        link_dir = os.path.join(top, "link_to_deep.lnk")
        add_symlink(link_dir, "l1/l2/l3")

    assert len(expected) >= 50

    archives = []
    expected_states = []
    restore_times = []

    latest_full = None
    latest_diff = None

    # FULL
    time.sleep(1)
    full_archive, full_time = create_archive("FULL", 1)
    latest_full = full_archive
    archives.append(("FULL", full_archive))
    expected_states.append(expected.copy())
    restore_times.append(full_time)

    apply_mutations(1)
    time.sleep(1)

    # DIFF
    diff1, diff_time = create_archive("DIFF", 2, base_archive=latest_full)
    latest_diff = diff1
    archives.append(("DIFF", diff1))
    expected_states.append(expected.copy())
    restore_times.append(diff_time)

    apply_mutations(2)
    time.sleep(1)

    # INCR
    incr1, incr_time = create_archive("INCR", 3, base_archive=latest_diff)
    archives.append(("INCR", incr1))
    expected_states.append(expected.copy())
    restore_times.append(incr_time)

    apply_mutations(3)
    time.sleep(1)

    # INCR
    incr2, incr_time2 = create_archive("INCR", 4, base_archive=latest_diff)
    archives.append(("INCR", incr2))
    expected_states.append(expected.copy())
    restore_times.append(incr_time2)

    apply_mutations(4)
    time.sleep(1)

    # DIFF
    diff2, diff_time2 = create_archive("DIFF", 5, base_archive=latest_full)
    latest_diff = diff2
    archives.append(("DIFF", diff2))
    expected_states.append(expected.copy())
    restore_times.append(diff_time2)

    apply_mutations(5)
    time.sleep(1)

    # INCR
    incr3, incr_time3 = create_archive("INCR", 6, base_archive=latest_diff)
    archives.append(("INCR", incr3))
    expected_states.append(expected.copy())
    restore_times.append(incr_time3)

    apply_mutations(6)
    time.sleep(1)

    # INCR
    incr4, incr_time4 = create_archive("INCR", 7, base_archive=latest_diff)
    archives.append(("INCR", incr4))
    expected_states.append(expected.copy())
    restore_times.append(incr_time4)

    # delete two random non-FULL archives
    rng = random.Random(42)
    non_full_archives = [a for a in archives if a[0] != "FULL"]
    to_delete = rng.sample(non_full_archives, 2)
    deleted_bases = {base for _, base in to_delete}
    for _, base in to_delete:
        for path in glob.glob(f"{base}.*.dar"):
            os.remove(path)

    def expected_chain_for_index(idx: int):
        last_full_idx = None
        for j in range(idx + 1):
            entry_type, _ = archives[j]
            if entry_type == "FULL":
                last_full_idx = j
        if last_full_idx is None:
            return []

        last_diff_idx = None
        for j in range(last_full_idx + 1, idx + 1):
            entry_type, _ = archives[j]
            if entry_type == "DIFF":
                last_diff_idx = j

        base_idx = last_diff_idx if last_diff_idx is not None else last_full_idx
        last_incr_idx = None
        for j in range(base_idx + 1, idx + 1):
            entry_type, _ = archives[j]
            if entry_type == "INCR":
                last_incr_idx = j

        chain = [archives[last_full_idx][1]]
        if last_diff_idx is not None:
            chain.append(archives[last_diff_idx][1])
        if last_incr_idx is not None:
            chain.append(archives[last_incr_idx][1])
        return chain

    expected_success = []
    for idx in range(len(restore_times)):
        chain = expected_chain_for_index(idx)
        should_succeed = not any(base in deleted_bases for base in chain)
        expected_success.append(should_succeed)

    assert any(expected_success)
    assert any(not ok for ok in expected_success)

    success = 0
    failures = 0
    for idx, restore_time in enumerate(restore_times):
        restore_dir = os.path.join(env.test_dir, f"restore_torture_{idx}")
        ok = restore_and_check(
            restore_time,
            restore_dir,
            restore_roots,
            expected_states[idx],
            expected_success[idx],
        )
        if ok:
            success += 1
        else:
            failures += 1

    assert success >= 1
    assert failures >= 1


def test_pitr_integration_rename_mtime_torture(setup_environment, env):
    """
    Torture test:
    - rename storms and file moves between FULL and DIFF
    - mtime trap: directories touched after FULL but restored to a time before changes
    - content-only edits between DIFF and INCR
    - PITR restores must match expected tree at each time point
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    # Clean out any default test data from fixture setup
    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    expected = {}
    all_files = []
    all_links = []
    empty_dirs = []

    def _norm(rel_path: str) -> str:
        return rel_path.replace(os.sep, "/")

    def add_dir(rel_path: str):
        parts = rel_path.split(os.sep)
        current = ""
        for part in parts:
            current = os.path.join(current, part) if current else part
            current_norm = _norm(current)
            if current_norm not in expected:
                expected[current_norm] = ("dir", None)
                os.makedirs(os.path.join(env.data_dir, current), exist_ok=True)

    def add_file(rel_path: str, content: str):
        parent = os.path.dirname(rel_path)
        if parent:
            add_dir(parent)
        expected[_norm(rel_path)] = ("file", content)
        with open(os.path.join(env.data_dir, rel_path), "w") as f:
            f.write(content)
        if rel_path not in all_files:
            all_files.append(rel_path)

    def add_symlink(rel_path: str, target: str):
        parent = os.path.dirname(rel_path)
        if parent:
            add_dir(parent)
        expected[_norm(rel_path)] = ("link", target)
        os.symlink(target, os.path.join(env.data_dir, rel_path))
        if rel_path not in all_links:
            all_links.append(rel_path)

    def remove_entry(rel_path: str):
        rel_norm = _norm(rel_path)
        abs_path = os.path.join(env.data_dir, rel_path)
        if os.path.islink(abs_path) or os.path.isfile(abs_path):
            os.remove(abs_path)
        elif os.path.isdir(abs_path):
            shutil.rmtree(abs_path)
        for key in list(expected.keys()):
            if key == rel_norm or key.startswith(rel_norm + "/"):
                expected.pop(key, None)
        if rel_path in all_files:
            all_files.remove(rel_path)
        if rel_path in all_links:
            all_links.remove(rel_path)
        if rel_path in empty_dirs:
            empty_dirs.remove(rel_path)

    def modify_file(rel_path: str, content: str):
        abs_path = os.path.join(env.data_dir, rel_path)
        with open(abs_path, "w") as f:
            f.write(content)
        expected[_norm(rel_path)] = ("file", content)

    def rename_entry(old_rel: str, new_rel: str):
        old_abs = os.path.join(env.data_dir, old_rel)
        new_abs = os.path.join(env.data_dir, new_rel)
        parent = os.path.dirname(new_rel)
        if parent:
            add_dir(parent)
        os.rename(old_abs, new_abs)
        old_norm = _norm(old_rel)
        new_norm = _norm(new_rel)
        updated = {}
        for key, val in expected.items():
            if key == old_norm:
                updated[new_norm] = val
            elif key.startswith(old_norm + "/"):
                updated[new_norm + key[len(old_norm):]] = val
            else:
                updated[key] = val
        expected.clear()
        expected.update(updated)

        def _update_list(paths):
            for idx, path in enumerate(list(paths)):
                if path == old_rel:
                    paths[idx] = new_rel
                elif path.startswith(old_rel + os.sep):
                    paths[idx] = new_rel + path[len(old_rel):]

        _update_list(all_files)
        _update_list(all_links)
        _update_list(empty_dirs)

    def snapshot_tree(base_dir: str):
        actual = {}
        for root, dirs, files in os.walk(base_dir):
            for d in list(dirs):
                path = os.path.join(root, d)
                rel = os.path.relpath(path, base_dir)
                rel_norm = _norm(rel)
                if os.path.islink(path):
                    actual[rel_norm] = ("link", os.readlink(path))
                    dirs.remove(d)
                else:
                    actual[rel_norm] = ("dir", None)
            for f in files:
                path = os.path.join(root, f)
                rel = os.path.relpath(path, base_dir)
                rel_norm = _norm(rel)
                if os.path.islink(path):
                    actual[rel_norm] = ("link", os.readlink(path))
                else:
                    with open(path, "r") as fh:
                        actual[rel_norm] = ("file", fh.read())
        return actual

    def create_archive(backup_type: str, seq: int, base_archive: str = None):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        archive_base = os.path.join(env.backup_dir, f"example_{backup_type}_{timestamp}_{seq:02d}")
        cmd = [
            "dar", "-c", archive_base,
            "-N",
            "-B", env.dar_rc,
            "-B", backup_def_path,
            "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        result = runner.run(cmd, timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f"dar backup failed: {result.stderr}")
        add_cmd = [
            "manager",
            "--add-specific-archive", archive_base,
            "--config-file", env.config_file,
            "--log-stdout",
        ]
        add_result = runner.run(add_cmd, timeout=300)
        if add_result.returncode != 0:
            raise RuntimeError(f"manager add-specific-archive failed: {add_result.stderr}")
        return archive_base, datetime.now()

    def restore_and_verify(restore_time: datetime, restore_dir: str, restore_paths, expected_snapshot):
        os.makedirs(restore_dir, exist_ok=True)
        cmd = [
            "manager",
            "--config-file", env.config_file,
            "--backup-def", "example",
            "--restore-path",
        ]
        cmd.extend(restore_paths)
        cmd.extend([
            "--when", restore_time.strftime("%Y-%m-%d %H:%M:%S"),
            "--target", restore_dir,
            "--log-stdout",
        ])
        result = runner.run(cmd)
        if result.returncode != 0:
            raise AssertionError(f"Restore failed: {result.stderr}")
        restored_root = os.path.join(restore_dir, env.data_dir.lstrip("/"))
        actual = snapshot_tree(restored_root)
        assert actual == expected_snapshot, "Restored tree does not match expected structure"

    # --- initial tree ---
    top_dirs = ["alpha", "beta", "gamma"]
    restore_roots = [os.path.join(env.data_dir.lstrip("/"), top) for top in top_dirs]

    for top in top_dirs:
        deep_dir = os.path.join(top, "l1", "l2", "l3")
        add_dir(deep_dir)
        for i in range(1, 11):
            rel = os.path.join(deep_dir, f"file_{top}_{i:02d}.txt")
            add_file(rel, f"{top} v1 {i:02d}")
        for i in range(1, 6):
            rel = os.path.join(top, f"top_file_{i:02d}.txt")
            add_file(rel, f"{top} top v1 {i:02d}")
        for i in range(1, 4):
            empty_dir = os.path.join(top, f"empty_{i}")
            add_dir(empty_dir)
            empty_dirs.append(empty_dir)
        for i in range(1, 3):
            link_rel = os.path.join(deep_dir, f"link_file_{i}.lnk")
            target = f"file_{top}_{i:02d}.txt"
            add_symlink(link_rel, target)
        link_dir = os.path.join(top, "link_to_deep.lnk")
        add_symlink(link_dir, "l1/l2/l3")

    assert len(expected) >= 60

    # --- FULL backup ---
    env.logger.info("Running FULL backup for rename/mtime torture test")
    full_archive, restore_time_full = create_archive("FULL", 1)
    expected_full = expected.copy()

    # --- rename storms + mtime trap before DIFF ---
    for top in top_dirs:
        old_deep = os.path.join(top, "l1", "l2", "l3")
        new_deep = os.path.join(top, "l1", "l2", "l3r")
        rename_entry(old_deep, new_deep)

        # Update link to deep dir to new target
        link_path = os.path.join(top, "link_to_deep.lnk")
        remove_entry(link_path)
        add_symlink(link_path, "l1/l2/l3r")

        # Rename one deep file per top
        old_file = os.path.join(top, "l1", "l2", "l3r", f"file_{top}_01.txt")
        new_file = os.path.join(top, "l1", "l2", "l3r", f"file_{top}_01_renamed.txt")
        rename_entry(old_file, new_file)

    # Move a file across top-level dirs
    move_src = os.path.join("alpha", "l1", "l2", "l3r", "file_alpha_02.txt")
    move_dst = os.path.join("beta", "l1", "l2", "l3r", "file_alpha_02_moved.txt")
    rename_entry(move_src, move_dst)

    # Create and delete temp files to bump directory mtimes
    for top in top_dirs:
        temp_path = os.path.join(top, "temp_mtime.tmp")
        add_file(temp_path, f"temp {top}")
        remove_entry(temp_path)

    time.sleep(2)

    # --- DIFF backup ---
    env.logger.info("Running DIFFERENTIAL backup for rename/mtime torture test")
    diff_archive, restore_time_diff = create_archive("DIFF", 2, base_archive=full_archive)
    expected_diff = expected.copy()

    # --- content-only edits + churn before INCR ---
    for idx, rel in enumerate(all_files[:5]):
        modify_file(rel, f"content updated {idx}")

    for top in top_dirs:
        added_dir = os.path.join(top, "added_after_diff", "deep")
        add_dir(added_dir)
        add_file(os.path.join(added_dir, f"new_{top}_01.txt"), f"{top} new after diff")

    if all_links:
        link_path = all_links[0]
        remove_entry(link_path)
        add_symlink(link_path, "l1/l2/l3r/file_beta_02.txt")

    for rel in list(all_files[-3:]):
        remove_entry(rel)

    time.sleep(2)

    # --- INCR backup ---
    env.logger.info("Running INCREMENTAL backup for rename/mtime torture test")
    _, restore_time_incr = create_archive("INCR", 3, base_archive=diff_archive)
    expected_incr = expected.copy()

    # --- restores for each time point ---
    restore_and_verify(restore_time_full, os.path.join(env.test_dir, "restore_rename_full"), restore_roots, expected_full)
    restore_and_verify(restore_time_diff, os.path.join(env.test_dir, "restore_rename_diff"), restore_roots, expected_diff)
    restore_and_verify(restore_time_incr, os.path.join(env.test_dir, "restore_rename_incr"), restore_roots, expected_incr)


def test_pitr_rebuild_catalog_after_loss(setup_environment, env):
    """
    Integration test:
    - Create FULL and DIFF backups
    - Delete the catalog DB
    - Rebuild DB from remaining archives
    - Verify PITR restore works using rebuilt catalog
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    # Clean out any default test data from fixture setup
    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    data_file = os.path.join(env.data_dir, "pitr_rebuild.txt")
    restore_path = data_file.lstrip("/")

    # Version 1 + FULL
    with open(data_file, "w") as f:
        f.write("Version 1 content")
    time.sleep(2)
    run_backup_script("--full-backup", env)
    time.sleep(2)
    restore_time_v1 = datetime.now()
    time.sleep(2)

    # Version 2 + DIFF
    with open(data_file, "w") as f:
        f.write("Version 2 content")
    time.sleep(2)
    run_backup_script("--differential-backup", env)
    time.sleep(2)

    # Delete the catalog DB to simulate loss
    db_path = os.path.join(env.backup_dir, "example.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    # Rebuild catalog DB and re-add archives
    result_create = runner.run([
        "manager", "--create-db", "--config-file", env.config_file, "--log-stdout"
    ])
    assert result_create.returncode == 0, f"Failed to create DB: {result_create.stderr}"

    result_add = runner.run([
        "manager", "--add-dir", env.backup_dir, "--backup-def", "example",
        "--config-file", env.config_file, "--log-stdout"
    ])
    assert result_add.returncode == 0, f"Failed to add archives: {result_add.stderr}"

    # PITR restore using rebuilt catalog
    restore_dir = os.path.join(env.test_dir, "restore_rebuild_catalog")
    os.makedirs(restore_dir, exist_ok=True)
    cmd = [
        "manager",
        "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", restore_path,
        "--when", restore_time_v1.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_dir,
        "--log-stdout",
    ]
    result_restore = runner.run(cmd, timeout=180)
    assert result_restore.returncode == 0, f"PITR restore failed: {result_restore.stderr}"

    restored_file = os.path.join(restore_dir, data_file.lstrip("/"))
    with open(restored_file, "r") as f:
        assert f.read() == "Version 1 content"
