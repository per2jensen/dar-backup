#!/usr/bin/env python3

import glob
import os
import random
import shutil
import sys
import time
from typing import Optional
from configparser import ConfigParser
from datetime import datetime, timedelta
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

PITR_STEP_SECONDS = 2


# Add src to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner
from dar_backup.config_settings import ConfigSettings
from tests.testdata_verification import run_backup_script




def _disable_par2(env) -> None:
    config = ConfigParser()
    config.read(env.config_file)
    if "PAR2" not in config:
        config["PAR2"] = {}
    config["PAR2"]["ENABLED"] = "False"
    with open(env.config_file, "w") as config_file:
        config.write(config_file)


def _apply_fast_pitr_config(env) -> None:
    config = ConfigParser()
    config.read(env.config_file)
    if "PAR2" not in config:
        config["PAR2"] = {}
    config["PAR2"]["ENABLED"] = "False"
    if "MISC" not in config:
        config["MISC"] = {}
    config["MISC"]["COMMAND_TIMEOUT_SECS"] = "300"
    with open(env.config_file, "w") as config_file:
        config.write(config_file)








class TestClock:
    __test__ = False
    def __init__(self, start: Optional[datetime] = None):
        self._current = start or datetime.now()

    def _advance(self, seconds: int = 1) -> datetime:
        if seconds < 0:
            raise ValueError("seconds must be non-negative")
        now = datetime.now()
        if self._current < now:
            self._current = now
        self._current += timedelta(seconds=seconds)
        # Avoid returning timestamps in the future; wait until real time catches up.
        while True:
            now = datetime.now()
            if now >= self._current:
                break
            sleep_for = (self._current - now).total_seconds()
            time.sleep(min(0.1, max(0.01, sleep_for)))
        return self._current

    def tick(self, seconds: int = 1) -> datetime:
        return self._advance(seconds)

    def touch(self, path: str, seconds: int = 1) -> datetime:
        ts = self._advance(seconds).timestamp()
        os.utime(path, (ts, ts))
        return datetime.fromtimestamp(ts)

    def touch_many(self, paths, seconds: int = 1) -> datetime:
        ts = self._advance(seconds).timestamp()
        for path in paths:
            if os.path.exists(path):
                os.utime(path, (ts, ts))
        return datetime.fromtimestamp(ts)


@pytest.fixture(autouse=True)
def _pitr_integration_config(setup_environment, env):
    _apply_fast_pitr_config(env)
    yield

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

    Archives are created manually with time-suffixed names (`_HHMMSS_NN`):
    between-snapshot selection (steps 5/6/9) needs sub-day archive dates,
    and the real pipeline's date-only names make same-session FULL/DIFF/INCR
    indistinguishable (the documented same-day limitation in
    doc/pitr-archive-date-vs-file-mtime.md).
    """

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    data_file = os.path.join(env.data_dir, "pitr_test_file.txt")
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    def _make_archive(archive_type: str, seq: str, base_archive: Optional[str] = None) -> str:
        """Create a time-suffixed archive of env.data_dir and add it to the catalog."""
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        archive_base = os.path.join(env.backup_dir, f"example_{archive_type}_{ts}_{seq}")
        cmd = [
            "dar", "-c", archive_base, "-N", "-B", env.dar_rc,
            "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        result = runner.run(cmd, timeout=300)
        assert result.returncode == 0, f"dar {archive_type} failed: {result.stderr}"
        result = runner.run([
            "manager", "--add-specific-archive", archive_base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert result.returncode == 0, f"manager add {archive_type} failed: {result.stderr}"
        return archive_base

    # --- Step 1: Version 1 ---
    env.logger.info("Creating Version 1 of file")
    with open(data_file, "w") as f:
        f.write("Version 1 content")

    # Ensure a deterministic mtime for the initial version
    clock.touch(data_file, seconds=PITR_STEP_SECONDS)

    # --- Step 2: Full Backup ---
    env.logger.info("Running FULL backup")
    full_base = _make_archive("FULL", "01")

    # Capture timestamp *after* full backup but *before* modification
    # This will be our target time for restoring Version 1
    # We add a small buffer to ensure we are "after" the backup creation
    restore_time_v1 = clock.tick(PITR_STEP_SECONDS)
    env.logger.info(f"Target Restore Time for V1: {restore_time_v1}")

    # --- Step 3: Version 2 ---
    env.logger.info("Creating Version 2 of file (modification)")
    with open(data_file, "w") as f:
        f.write("Version 2 content")

    clock.touch(data_file, seconds=PITR_STEP_SECONDS)

    # --- Step 4: Differential Backup ---
    env.logger.info("Running DIFFERENTIAL backup")
    diff_base = _make_archive("DIFF", "02", base_archive=full_base)

    restore_time_v2 = clock.tick(PITR_STEP_SECONDS)
    env.logger.info(f"Target Restore Time for V2: {restore_time_v2}")
    
    # --- Step 5: Restore V1 ---
    restore_dir_v1 = os.path.join(env.test_dir, "restore_v1")
    os.makedirs(restore_dir_v1, exist_ok=True)
    
    # Relative path for restore (as stored in backup)
    # dar stores absolute paths relative to root, but -R rebases them.
    # If we backed up env.data_dir (e.g., <temp>/.../data),
    # the file in backup is <temp>/.../data/pitr_test_file.txt
    # We must pass the full path to --restore-path
    
    restore_path = data_file.lstrip("/")
    
    # Format time for the CLI
    time_str_v1 = restore_time_v1.strftime("%Y-%m-%d %H:%M:%S")
    
    # Debug: List archive contents to verify path storage
    env.logger.info(f"Listing contents of {full_base}")
    runner.run(["dar", "-l", full_base, "-Q"])

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

    clock.touch(data_file, seconds=PITR_STEP_SECONDS)

    # --- Step 8: Incremental Backup ---
    env.logger.info("Running INCREMENTAL backup")
    _make_archive("INCR", "03", base_archive=diff_base)

    restore_time_v3 = clock.tick(PITR_STEP_SECONDS)
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
    clock = TestClock()

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
    restore_time_v1 = clock.tick(PITR_STEP_SECONDS)

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
    restore_time_v2 = clock.tick(PITR_STEP_SECONDS)

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

    modified_paths = [os.path.join(env.data_dir, rel) for rel in (deep_files[:15] + new_files[:15])]
    clock.touch_many(modified_paths, seconds=PITR_STEP_SECONDS)

    # --- Step 6: INCR backup ---
    env.logger.info("Running INCREMENTAL backup for tree structure test")
    run_backup_script("--incremental-backup", env)
    restore_time_v3 = clock.tick(PITR_STEP_SECONDS)

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
    clock = TestClock()
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
        archive_time = clock.tick(PITR_STEP_SECONDS)
        timestamp = archive_time.strftime("%Y-%m-%d_%H%M%S")
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
        return archive_base, archive_time

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
        if modified:
            modified_paths = [os.path.join(env.data_dir, rel) for rel in all_files[:10]]
            clock.touch_many(modified_paths, seconds=PITR_STEP_SECONDS)

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
    full_archive, full_time = create_archive("FULL", 1)
    latest_full = full_archive
    archives.append(("FULL", full_archive))
    expected_states.append(expected.copy())
    restore_times.append(full_time)

    apply_mutations(1)

    # DIFF
    diff1, diff_time = create_archive("DIFF", 2, base_archive=latest_full)
    latest_diff = diff1
    archives.append(("DIFF", diff1))
    expected_states.append(expected.copy())
    restore_times.append(diff_time)

    apply_mutations(2)

    # INCR
    incr1, incr_time = create_archive("INCR", 3, base_archive=latest_diff)
    archives.append(("INCR", incr1))
    expected_states.append(expected.copy())
    restore_times.append(incr_time)

    apply_mutations(3)

    # INCR
    incr2, incr_time2 = create_archive("INCR", 4, base_archive=latest_diff)
    archives.append(("INCR", incr2))
    expected_states.append(expected.copy())
    restore_times.append(incr_time2)

    apply_mutations(4)

    # DIFF
    diff2, diff_time2 = create_archive("DIFF", 5, base_archive=latest_full)
    latest_diff = diff2
    archives.append(("DIFF", diff2))
    expected_states.append(expected.copy())
    restore_times.append(diff_time2)

    apply_mutations(5)

    # INCR
    incr3, incr_time3 = create_archive("INCR", 6, base_archive=latest_diff)
    archives.append(("INCR", incr3))
    expected_states.append(expected.copy())
    restore_times.append(incr_time3)

    apply_mutations(6)

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
    clock = TestClock()
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
        archive_time = clock.tick(PITR_STEP_SECONDS)
        timestamp = archive_time.strftime("%Y-%m-%d_%H%M%S")
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
        return archive_base, archive_time

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

    dir_paths = [os.path.join(env.data_dir, top) for top in top_dirs]
    clock.touch_many(dir_paths, seconds=PITR_STEP_SECONDS)

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

    modified_paths = [os.path.join(env.data_dir, rel) for rel in all_files[:5]]
    clock.touch_many(modified_paths, seconds=PITR_STEP_SECONDS)

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

    Archives use time-suffixed names (`_HHMMSS_NN`): the between-snapshot
    restore to V1 needs sub-day archive dates — same-session FULL and DIFF
    with date-only names are indistinguishable to PITR (documented same-day
    limitation).
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    config_settings = ConfigSettings(env.config_file)
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    # Clean out any default test data from fixture setup
    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    data_file = os.path.join(env.data_dir, "pitr_rebuild.txt")
    restore_path = data_file.lstrip("/")

    def _make_archive(archive_type: str, seq: str, base_archive: Optional[str] = None) -> str:
        """Create a time-suffixed archive of env.data_dir and add it to the catalog."""
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        archive_base = os.path.join(env.backup_dir, f"example_{archive_type}_{ts}_{seq}")
        cmd = [
            "dar", "-c", archive_base, "-N", "-B", env.dar_rc,
            "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        result = runner.run(cmd, timeout=300)
        assert result.returncode == 0, f"dar {archive_type} failed: {result.stderr}"
        result = runner.run([
            "manager", "--add-specific-archive", archive_base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert result.returncode == 0, f"manager add {archive_type} failed: {result.stderr}"
        return archive_base

    # Version 1 + FULL
    with open(data_file, "w") as f:
        f.write("Version 1 content")
    clock.touch(data_file, seconds=PITR_STEP_SECONDS)
    full_base = _make_archive("FULL", "01")
    restore_time_v1 = clock.tick(PITR_STEP_SECONDS)

    # Version 2 + DIFF
    with open(data_file, "w") as f:
        f.write("Version 2 content")
    clock.touch(data_file, seconds=PITR_STEP_SECONDS)
    _make_archive("DIFF", "02", base_archive=full_base)

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
    if os.path.exists(restore_dir):
        shutil.rmtree(restore_dir)
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
    result_restore = runner.run(cmd, timeout=config_settings.command_timeout_secs)
    assert result_restore.returncode == 0, f"PITR restore failed: {result_restore.stderr}"

    restored_file = os.path.join(restore_dir, data_file.lstrip("/"))
    with open(restored_file, "r") as f:
        assert f.read() == "Version 1 content"


def test_pitr_full_diff_incr_add_delete_mutate(setup_environment, env):
    """
    Prove dar_manager -r -w correctly handles FULL + DIFF + 3 INCRs
    with file additions, deletions, and mutations at each stage.

    Uses dar directly (with timestamp-based archive names) to avoid
    same-day naming collisions from dar-backup's date-only naming.

    Timeline:
        T0: Create 5 files (f1..f5) -> FULL backup
        T1: Mutate f1, delete f2, add f6 -> DIFF backup (ref: FULL)
        T2: Mutate f3, delete f4, add f7 -> INCR_1 backup (ref: DIFF)
        T3: Mutate f5, add f8 -> INCR_2 backup (ref: DIFF)
        T4: Delete f6, mutate f7, add f9 -> INCR_3 backup (ref: DIFF)

    Then restore at each timestamp and verify exact file contents.
    This proves dar_manager handles the full INCR chain correctly.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    # Clean default test data
    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    seq = [0]

    def create_archive(backup_type: str, base_archive: str = None) -> str:
        """Create a dar archive and register it in the catalog database."""
        seq[0] += 1
        archive_time = clock.tick(PITR_STEP_SECONDS)
        timestamp = archive_time.strftime("%Y-%m-%d_%H%M%S")
        archive_base = os.path.join(
            env.backup_dir, f"example_{backup_type}_{timestamp}_{seq[0]:02d}"
        )
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
        return archive_base

    # Helper: write file and touch with clock
    def write_file(name: str, content: str) -> str:
        """Write a file and return its path."""
        fpath = os.path.join(env.data_dir, name)
        with open(fpath, "w") as f:
            f.write(content)
        clock.touch(fpath, seconds=PITR_STEP_SECONDS)
        return fpath

    def delete_file(name: str) -> None:
        """Delete a file from the data directory."""
        fpath = os.path.join(env.data_dir, name)
        os.remove(fpath)

    def snapshot_files() -> dict:
        """Capture current file state as {name: content}."""
        result = {}
        for name in sorted(os.listdir(env.data_dir)):
            fpath = os.path.join(env.data_dir, name)
            if os.path.isfile(fpath):
                with open(fpath, "r") as f:
                    result[name] = f.read()
        return result

    def restore_and_verify(restore_time: datetime, label: str, expected: dict) -> None:
        """Restore at the given time and verify file contents match expected."""
        restore_dir = os.path.join(env.test_dir, f"restore_{label}")
        os.makedirs(restore_dir, exist_ok=True)

        restore_path = env.data_dir.lstrip("/")
        cmd = [
            "manager",
            "--config-file", env.config_file,
            "--backup-def", "example",
            "--restore-path", restore_path,
            "--when", restore_time.strftime("%Y-%m-%d %H:%M:%S"),
            "--target", restore_dir,
            "--log-stdout",
        ]
        result = runner.run(cmd, timeout=300)
        assert result.returncode == 0, f"Restore '{label}' failed (rc={result.returncode}): {result.stderr}"

        restored_data_dir = os.path.join(restore_dir, env.data_dir.lstrip("/"))
        actual = {}
        if os.path.isdir(restored_data_dir):
            for name in sorted(os.listdir(restored_data_dir)):
                fpath = os.path.join(restored_data_dir, name)
                if os.path.isfile(fpath):
                    with open(fpath, "r") as f:
                        actual[name] = f.read()

        assert actual == expected, (
            f"Restore '{label}' mismatch.\n"
            f"  Expected files: {sorted(expected.keys())}\n"
            f"  Actual files:   {sorted(actual.keys())}\n"
            f"  Missing: {set(expected) - set(actual)}\n"
            f"  Extra:   {set(actual) - set(expected)}\n"
            f"  Content diffs: {[(k, expected.get(k), actual.get(k)) for k in expected if expected.get(k) != actual.get(k)]}"
        )
        env.logger.info(f"Restore '{label}' verified: {len(actual)} files match expected state.")

    # ========== T0: Initial state -> FULL ==========
    write_file("f1.txt", "f1 original")
    write_file("f2.txt", "f2 original")
    write_file("f3.txt", "f3 original")
    write_file("f4.txt", "f4 original")
    write_file("f5.txt", "f5 original")

    env.logger.info("Running FULL backup")
    full_archive = create_archive("FULL")
    t0 = clock.tick(PITR_STEP_SECONDS)
    expected_t0 = snapshot_files()
    assert len(expected_t0) == 5

    # ========== T1: Mutate f1, delete f2, add f6 -> DIFF ==========
    write_file("f1.txt", "f1 mutated at T1")
    delete_file("f2.txt")
    write_file("f6.txt", "f6 added at T1")

    env.logger.info("Running DIFF backup (ref: FULL)")
    diff_archive = create_archive("DIFF", base_archive=full_archive)
    t1 = clock.tick(PITR_STEP_SECONDS)
    expected_t1 = snapshot_files()
    assert "f2.txt" not in expected_t1
    assert expected_t1["f1.txt"] == "f1 mutated at T1"
    assert expected_t1["f6.txt"] == "f6 added at T1"

    # ========== T2: Mutate f3, delete f4, add f7 -> INCR_1 ==========
    write_file("f3.txt", "f3 mutated at T2")
    delete_file("f4.txt")
    write_file("f7.txt", "f7 added at T2")

    env.logger.info("Running INCR_1 backup (ref: DIFF)")
    incr1_archive = create_archive("INCR", base_archive=diff_archive)
    t2 = clock.tick(PITR_STEP_SECONDS)
    expected_t2 = snapshot_files()
    assert "f4.txt" not in expected_t2
    assert expected_t2["f3.txt"] == "f3 mutated at T2"

    # ========== T3: Mutate f5, add f8 -> INCR_2 ==========
    write_file("f5.txt", "f5 mutated at T3")
    write_file("f8.txt", "f8 added at T3")

    env.logger.info("Running INCR_2 backup (ref: DIFF)")
    incr2_archive = create_archive("INCR", base_archive=diff_archive)
    t3 = clock.tick(PITR_STEP_SECONDS)
    expected_t3 = snapshot_files()
    assert expected_t3["f5.txt"] == "f5 mutated at T3"

    # ========== T4: Delete f6, mutate f7, add f9 -> INCR_3 ==========
    delete_file("f6.txt")
    write_file("f7.txt", "f7 mutated at T4")
    write_file("f9.txt", "f9 added at T4")

    env.logger.info("Running INCR_3 backup (ref: DIFF)")
    create_archive("INCR", base_archive=diff_archive)
    t4 = clock.tick(PITR_STEP_SECONDS)
    expected_t4 = snapshot_files()
    assert "f6.txt" not in expected_t4
    assert expected_t4["f7.txt"] == "f7 mutated at T4"

    # ========== Verify restores at each time point ==========
    restore_and_verify(t0, "T0_after_FULL", expected_t0)
    restore_and_verify(t1, "T1_after_DIFF", expected_t1)
    restore_and_verify(t2, "T2_after_INCR1", expected_t2)
    restore_and_verify(t3, "T3_after_INCR2", expected_t3)
    restore_and_verify(t4, "T4_after_INCR3", expected_t4)

    env.logger.info("All 5 PITR restore points verified successfully.")


def test_pitr_multislice_archive(setup_environment, env):
    """
    Verify that PITR correctly restores files from archives that span multiple
    slices (.1.dar, .2.dar, .3.dar, ...).

    Strategy:
    - Write a backup definition with a small slice size (4 kB) and no
      compression so raw file bytes fill multiple slices.
    - Write 3 binary files of 4 kB each → total 12 kB → guaranteed 3+ slices
      per archive.
    - Take FULL backup; assert .2.dar exists.
    - Modify all files; take DIFF backup; assert .2.dar exists for DIFF too.
    - PITR restore to T0 (FULL date): verify original binary content.
    - PITR restore to T1 (DIFF date): verify modified binary content.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()

    # Clear default fixture data so only our controlled files are in the backup.
    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    # Write a custom backup definition: small slice size + no compression.
    # Slice size goes in the backup definition, as is the convention in dar-backup.
    SLICE_BYTES = 4096  # 4 kB per slice
    data_dir_for_dar = env.data_dir.lstrip("/")
    sliced_def_path = os.path.join(env.backup_d_dir, "example_sliced")
    with open(sliced_def_path, "w") as f:
        f.write(
            f"-R /\n"
            f"-s {SLICE_BYTES}\n"
            f"-n\n"                    # no compression → raw bytes fill slices
            f"-am\n"
            f"--cache-directory-tagging\n"
            f"-g {data_dir_for_dar}\n"
        )

    # Non-compressible binary data: a linear byte pattern based on a seed.
    # Since -n disables compression, each file occupies its full size in the archive.
    FILE_SIZE = SLICE_BYTES  # one slice worth per file → 3 files → 3+ slices

    def write_binary_file(name: str, seed: int) -> str:
        """Write a deterministic binary file and return its path."""
        fpath = os.path.join(env.data_dir, name)
        data = bytes([(seed + i) % 256 for i in range(FILE_SIZE)])
        with open(fpath, "wb") as f:
            f.write(data)
        clock.touch(fpath, seconds=PITR_STEP_SECONDS)
        return fpath

    seq = [0]

    def create_archive(backup_type: str, base_archive: str = None) -> str:
        """Create a dar archive using the sliced backup definition."""
        seq[0] += 1
        archive_time = clock.tick(PITR_STEP_SECONDS)
        timestamp = archive_time.strftime("%Y-%m-%d_%H%M%S")
        # Prefix "example_" so manager --add-specific-archive registers in example.db.
        archive_base = os.path.join(
            env.backup_dir, f"example_{backup_type}_{timestamp}_{seq[0]:02d}"
        )
        cmd = [
            "dar", "-c", archive_base,
            "-N",
            "-B", env.dar_rc,
            "-B", sliced_def_path,
            "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        result = runner.run(cmd, timeout=300)
        assert result.returncode == 0, f"dar {backup_type} failed: {result.stderr}"
        add_result = runner.run([
            "manager", "--add-specific-archive", archive_base,
            "--config-file", env.config_file,
            "--log-stdout",
        ], timeout=300)
        assert add_result.returncode == 0, f"manager add-specific-archive failed: {add_result.stderr}"
        return archive_base

    # --- T0: initial files → FULL backup ---
    write_binary_file("slice_a.bin", seed=0xAA)
    write_binary_file("slice_b.bin", seed=0xBB)
    write_binary_file("slice_c.bin", seed=0xCC)

    full_archive = create_archive("FULL")
    t0 = clock.tick(PITR_STEP_SECONDS)

    # Must have at least two slices.
    assert os.path.exists(f"{full_archive}.1.dar"), f"FULL .1.dar missing: {full_archive}"
    slice2_full = f"{full_archive}.2.dar"
    assert os.path.exists(slice2_full), (
        f"FULL .2.dar missing — slice size may be too large or data too small: {full_archive}"
    )
    env.logger.info("FULL multi-slice archive confirmed: at least 2 slices present")

    # Prove that restored content lives in slice 2+, not just in .1.dar:
    # Hide .2.dar, attempt restore, then verify that at least one file is
    # absent or has wrong content in the probe directory.  dar -x with -Q
    # returns 0 even when slices are missing (graceful partial restore), so
    # we cannot rely on the return code — we check the actual content.
    slice2_hidden = slice2_full + ".hidden"
    os.rename(slice2_full, slice2_hidden)
    try:
        probe_dir = os.path.join(env.test_dir, "restore_ms_probe")
        os.makedirs(probe_dir, exist_ok=True)
        runner.run([
            "manager",
            "--config-file", env.config_file,
            "--backup-def", "example",
            "--restore-path", data_dir_for_dar,
            "--when", t0.strftime("%Y-%m-%d %H:%M:%S"),
            "--target", probe_dir,
            "--log-stdout",
        ], timeout=300)
        # Check whether the probe restore is incomplete (file absent or wrong bytes).
        probe_data_dir = os.path.join(probe_dir, data_dir_for_dar)
        probe_incomplete = False
        for name, seed in [("slice_a.bin", 0xAA), ("slice_b.bin", 0xBB), ("slice_c.bin", 0xCC)]:
            expected = bytes([(seed + i) % 256 for i in range(FILE_SIZE)])
            fpath = os.path.join(probe_data_dir, name)
            if not os.path.exists(fpath):
                probe_incomplete = True
                env.logger.info(
                    "Probe (without .2.dar): '%s' absent — content lives in later slices", name
                )
                break
            with open(fpath, "rb") as f:
                if f.read() != expected:
                    probe_incomplete = True
                    env.logger.info(
                        "Probe (without .2.dar): '%s' has wrong content — spans multiple slices", name
                    )
                    break
        assert probe_incomplete, (
            "Probe restore with .2.dar absent returned correct content for all files — "
            "content may not actually span multiple slices; try a smaller slice size"
        )
    finally:
        os.rename(slice2_hidden, slice2_full)  # always restore the slice

    # --- T1: modify all files → DIFF backup ---
    write_binary_file("slice_a.bin", seed=0x11)
    write_binary_file("slice_b.bin", seed=0x22)
    write_binary_file("slice_c.bin", seed=0x33)

    diff_archive = create_archive("DIFF", base_archive=full_archive)
    t1 = clock.tick(PITR_STEP_SECONDS)

    assert os.path.exists(f"{diff_archive}.1.dar"), f"DIFF .1.dar missing: {diff_archive}"
    slice2_diff = f"{diff_archive}.2.dar"
    assert os.path.exists(slice2_diff), (
        f"DIFF .2.dar missing — slice size may be too large or data too small: {diff_archive}"
    )
    env.logger.info("DIFF multi-slice archive confirmed: at least 2 slices present")

    # Same proof for the DIFF archive.
    slice2_diff_hidden = slice2_diff + ".hidden"
    os.rename(slice2_diff, slice2_diff_hidden)
    try:
        probe_dir_diff = os.path.join(env.test_dir, "restore_ms_probe_diff")
        os.makedirs(probe_dir_diff, exist_ok=True)
        runner.run([
            "manager",
            "--config-file", env.config_file,
            "--backup-def", "example",
            "--restore-path", data_dir_for_dar,
            "--when", t1.strftime("%Y-%m-%d %H:%M:%S"),
            "--target", probe_dir_diff,
            "--log-stdout",
        ], timeout=300)
        probe_data_dir_diff = os.path.join(probe_dir_diff, data_dir_for_dar)
        probe_diff_incomplete = False
        for name, seed in [("slice_a.bin", 0x11), ("slice_b.bin", 0x22), ("slice_c.bin", 0x33)]:
            expected = bytes([(seed + i) % 256 for i in range(FILE_SIZE)])
            fpath = os.path.join(probe_data_dir_diff, name)
            if not os.path.exists(fpath):
                probe_diff_incomplete = True
                env.logger.info(
                    "Probe DIFF (without .2.dar): '%s' absent — content in later slices", name
                )
                break
            with open(fpath, "rb") as f:
                if f.read() != expected:
                    probe_diff_incomplete = True
                    env.logger.info(
                        "Probe DIFF (without .2.dar): '%s' wrong content — spans slices", name
                    )
                    break
        assert probe_diff_incomplete, (
            "Probe DIFF restore with .2.dar absent returned correct content — "
            "DIFF content may not span multiple slices; try a smaller slice size"
        )
    finally:
        os.rename(slice2_diff_hidden, slice2_diff)

    # --- PITR restore at T0 → expect FULL (original) content ---
    restore_t0 = os.path.join(env.test_dir, "restore_ms_t0")
    os.makedirs(restore_t0, exist_ok=True)
    result = runner.run([
        "manager",
        "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", data_dir_for_dar,
        "--when", t0.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_t0,
        "--log-stdout",
    ], timeout=300)
    assert result.returncode == 0, f"PITR T0 failed: {result.stderr}"

    restored_t0 = os.path.join(restore_t0, data_dir_for_dar)
    for name, seed in [("slice_a.bin", 0xAA), ("slice_b.bin", 0xBB), ("slice_c.bin", 0xCC)]:
        expected = bytes([(seed + i) % 256 for i in range(FILE_SIZE)])
        fpath = os.path.join(restored_t0, name)
        assert os.path.exists(fpath), f"Restored {name} missing at T0"
        with open(fpath, "rb") as f:
            assert f.read() == expected, f"{name}: wrong content at T0 (FULL)"
    env.logger.info("T0 restore verified: original content from multi-slice FULL archive")

    # --- PITR restore at T1 → expect DIFF (modified) content ---
    restore_t1 = os.path.join(env.test_dir, "restore_ms_t1")
    os.makedirs(restore_t1, exist_ok=True)
    result = runner.run([
        "manager",
        "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", data_dir_for_dar,
        "--when", t1.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_t1,
        "--log-stdout",
    ], timeout=300)
    assert result.returncode == 0, f"PITR T1 failed: {result.stderr}"

    restored_t1 = os.path.join(restore_t1, data_dir_for_dar)
    for name, seed in [("slice_a.bin", 0x11), ("slice_b.bin", 0x22), ("slice_c.bin", 0x33)]:
        expected = bytes([(seed + i) % 256 for i in range(FILE_SIZE)])
        fpath = os.path.join(restored_t1, name)
        assert os.path.exists(fpath), f"Restored {name} missing at T1"
        with open(fpath, "rb") as f:
            assert f.read() == expected, f"{name}: wrong content at T1 (DIFF)"
    env.logger.info("T1 restore verified: modified content from multi-slice DIFF archive")

    env.logger.info("Multi-slice PITR test passed.")


def test_pitr_symlinks_and_hardlinks(setup_environment, env):
    """
    Verify PITR correctly preserves symbolic links and hard links across a
    FULL → DIFF archive chain.

    Setup at FULL time:
    - target_file.txt:    regular file with "original content"
    - link_to_target.lnk: relative symlink → target_file.txt
    - dangling.lnk:       symlink → does_not_exist.txt  (always dangling)
    - original.txt:       regular file; hardlink.txt hard-linked to it

    Between FULL and DIFF:
    - target_file.txt content changed
    - link_to_target.lnk retargeted to new_target.txt
    - new_target.txt added

    PITR assertions at T0 (FULL date):
    - link_to_target.lnk is a symlink pointing to "target_file.txt"
    - target_file.txt has "original content"
    - dangling.lnk is a symlink pointing to "does_not_exist.txt"
    - original.txt and hardlink.txt share the same inode (hard link preserved)

    PITR assertions at T1 (DIFF date):
    - link_to_target.lnk is a symlink pointing to "new_target.txt"
    - target_file.txt has "modified content"
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()

    # Clear default fixture data.
    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        elif os.path.exists(path) or os.path.islink(path):
            os.remove(path)

    # --- Create FULL state ---
    target_file  = os.path.join(env.data_dir, "target_file.txt")
    link_to_target = os.path.join(env.data_dir, "link_to_target.lnk")
    dangling_link  = os.path.join(env.data_dir, "dangling.lnk")
    original_file  = os.path.join(env.data_dir, "original.txt")
    hardlink_file  = os.path.join(env.data_dir, "hardlink.txt")

    with open(target_file, "w") as f:
        f.write("original content")
    clock.touch(target_file, seconds=PITR_STEP_SECONDS)

    with open(original_file, "w") as f:
        f.write("hardlink content")
    clock.touch(original_file, seconds=PITR_STEP_SECONDS)

    os.link(original_file, hardlink_file)            # hard link
    os.symlink("target_file.txt", link_to_target)    # relative symlink (in-tree)
    os.symlink("does_not_exist.txt", dangling_link)  # dangling symlink

    # Use direct dar calls rather than run_backup_script to avoid the post-backup
    # verification step.  Verification randomly picks files to restore; unchanged
    # files (original.txt, hardlink.txt) are not in the DIFF archive and would
    # cause a false "restored file missing" failure unrelated to PITR correctness.
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    seq = [0]

    def create_archive(backup_type: str, base_archive: str = None) -> str:
        """Create a dar archive and register it in the catalog database."""
        seq[0] += 1
        archive_time = clock.tick(PITR_STEP_SECONDS)
        timestamp = archive_time.strftime("%Y-%m-%d_%H%M%S")
        archive_base = os.path.join(
            env.backup_dir, f"example_{backup_type}_{timestamp}_{seq[0]:02d}"
        )
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
        assert result.returncode == 0, f"dar {backup_type} failed: {result.stderr}"
        add_result = runner.run([
            "manager", "--add-specific-archive", archive_base,
            "--config-file", env.config_file,
            "--log-stdout",
        ], timeout=300)
        assert add_result.returncode == 0, f"manager add failed: {add_result.stderr}"
        return archive_base

    full_archive = create_archive("FULL")
    t0 = clock.tick(PITR_STEP_SECONDS)

    # --- Modify for DIFF ---
    with open(target_file, "w") as f:
        f.write("modified content")
    clock.touch(target_file, seconds=PITR_STEP_SECONDS)

    new_target = os.path.join(env.data_dir, "new_target.txt")
    with open(new_target, "w") as f:
        f.write("new target content")
    clock.touch(new_target, seconds=PITR_STEP_SECONDS)

    # Retarget symlink: remove old link, create new one pointing elsewhere.
    os.remove(link_to_target)
    os.symlink("new_target.txt", link_to_target)

    create_archive("DIFF", base_archive=full_archive)
    t1 = clock.tick(PITR_STEP_SECONDS)

    data_dir_rel = env.data_dir.lstrip("/")

    # --- PITR restore at T0 (FULL state) ---
    restore_t0 = os.path.join(env.test_dir, "restore_links_t0")
    os.makedirs(restore_t0, exist_ok=True)
    result = runner.run([
        "manager",
        "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", data_dir_rel,
        "--when", t0.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_t0,
        "--log-stdout",
    ], timeout=300)
    assert result.returncode == 0, f"PITR T0 failed: {result.stderr}"

    restored_t0 = os.path.join(restore_t0, data_dir_rel)

    # Symlink points to original target.
    r_link = os.path.join(restored_t0, "link_to_target.lnk")
    assert os.path.islink(r_link), "link_to_target.lnk should be a symlink at T0"
    assert os.readlink(r_link) == "target_file.txt", (
        f"Symlink target mismatch at T0: expected 'target_file.txt', got '{os.readlink(r_link)}'"
    )

    # target_file.txt has original content.
    r_target = os.path.join(restored_t0, "target_file.txt")
    with open(r_target) as f:
        assert f.read() == "original content", "target_file.txt wrong content at T0"

    # Dangling symlink is preserved as-is.
    r_dangling = os.path.join(restored_t0, "dangling.lnk")
    assert os.path.islink(r_dangling), "dangling.lnk should be a symlink at T0"
    assert os.readlink(r_dangling) == "does_not_exist.txt", (
        f"Dangling symlink target mismatch at T0: got '{os.readlink(r_dangling)}'"
    )

    # Hard link pair shares the same inode.
    r_original  = os.path.join(restored_t0, "original.txt")
    r_hardlink  = os.path.join(restored_t0, "hardlink.txt")
    assert os.path.exists(r_original), "original.txt missing at T0"
    assert os.path.exists(r_hardlink), "hardlink.txt missing at T0"
    inode_original = os.stat(r_original).st_ino
    inode_hardlink = os.stat(r_hardlink).st_ino
    assert inode_original == inode_hardlink, (
        f"Hard link not preserved at T0: original inode={inode_original}, "
        f"hardlink inode={inode_hardlink}"
    )
    env.logger.info("T0: symlink, dangling symlink, and hard link assertions passed")

    # --- PITR restore at T1 (DIFF state) ---
    restore_t1 = os.path.join(env.test_dir, "restore_links_t1")
    os.makedirs(restore_t1, exist_ok=True)
    result = runner.run([
        "manager",
        "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", data_dir_rel,
        "--when", t1.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_t1,
        "--log-stdout",
    ], timeout=300)
    assert result.returncode == 0, f"PITR T1 failed: {result.stderr}"

    restored_t1 = os.path.join(restore_t1, data_dir_rel)

    # Symlink was retargeted to new_target.txt in the DIFF.
    r_link_t1 = os.path.join(restored_t1, "link_to_target.lnk")
    assert os.path.islink(r_link_t1), "link_to_target.lnk should be a symlink at T1"
    assert os.readlink(r_link_t1) == "new_target.txt", (
        f"Symlink not retargeted at T1: expected 'new_target.txt', "
        f"got '{os.readlink(r_link_t1)}'"
    )

    # target_file.txt has modified content.
    r_target_t1 = os.path.join(restored_t1, "target_file.txt")
    with open(r_target_t1) as f:
        assert f.read() == "modified content", "target_file.txt wrong content at T1"

    env.logger.info("T1: retargeted symlink and modified file content assertions passed")
    env.logger.info("Symlink and hard link PITR test passed.")


# Special-character filenames present in the standard conftest fixture data
# plus additional cases added by this test.  Defined at module level so the
# expected values are visible alongside the assertions.
_CONFTEST_SPECIAL_FILES = {
    "file with spaces.txt":               "This is file with spaces.",
    "file_with_danish_chars_æøå.txt":     "This is file with danish chars æøå.",
    "file_with_DANISH_CHARS_ÆØÅ.txt":    "This is file with DANISH CHARS ÆØÅ.",
    "file_with_colon.txt":                "This is file with colon .",
    "file_with_hash.txt":                 "This is file with hash #.",
    "file_with_currency.txt":             "This is file with currency ¤.",
}

_EXTRA_SPECIAL_FILES = {
    "file (with) parens.txt":   "parentheses content v1",
    # "file&ampersand.txt" is intentionally excluded: dar-backup's sanitize_cmd()
    # rejects '&' as an unsafe shell character.  Since subprocess is used (no shell),
    # '&' in filenames is safe at the OS level, but the sanitizer blocks it.
    # This is a known limitation to address separately.
    "file+plus.txt":            "plus content v1",
    "urgent!.txt":              "exclamation content v1",
    "file[brackets].txt":       "brackets content v1",
}


def test_pitr_special_char_filenames(setup_environment, env):
    """
    Verify PITR correctly handles files whose names contain characters that
    are significant in shells or filesystems: spaces, Unicode letters (æ ø å
    Æ Ø Å), hash (#), currency (¤), parentheses, plus, exclamation mark, and
    square brackets.

    Note: '&' in filenames is intentionally excluded — dar-backup's sanitize_cmd()
    rejects it as an unsafe character even though subprocess is used (no shell).
    That is a separate known limitation.

    The conftest fixture already creates several special-char files; this test
    adds more, then:
    1. Takes a FULL backup (T0).
    2. Overwrites all special-char files with "modified: <name>" content.
    3. Takes a DIFF backup (T1).
    4. PITR restore to T0 → expects original content for every file.
    5. PITR restore to T1 → expects modified content for every file.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()

    # Create the extra special-char files (conftest files already exist).
    for name, content in _EXTRA_SPECIAL_FILES.items():
        fpath = os.path.join(env.data_dir, name)
        with open(fpath, "w") as f:
            f.write(content)
        clock.touch(fpath, seconds=PITR_STEP_SECONDS)

    # Touch the conftest-created files so they have a deterministic mtime
    # that the clock has already advanced past.
    for name in _CONFTEST_SPECIAL_FILES:
        fpath = os.path.join(env.data_dir, name)
        if os.path.exists(fpath):
            clock.touch(fpath, seconds=PITR_STEP_SECONDS)

    # Build the union of all special-char files we will test.
    all_special: dict = {**_CONFTEST_SPECIAL_FILES, **_EXTRA_SPECIAL_FILES}

    # Record original content from disk (source of truth for T0 assertions).
    original_content: dict = {}
    for name in all_special:
        fpath = os.path.join(env.data_dir, name)
        if os.path.exists(fpath):
            with open(fpath, encoding="utf-8") as f:
                original_content[name] = f.read()

    # Use direct dar calls to avoid the post-backup verification step, which
    # can pick files not present in the DIFF archive and raise a false failure.
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    seq = [0]

    def create_archive(backup_type: str, base_archive: str = None) -> str:
        """Create a dar archive and register it in the catalog database."""
        seq[0] += 1
        archive_time = clock.tick(PITR_STEP_SECONDS)
        timestamp = archive_time.strftime("%Y-%m-%d_%H%M%S")
        archive_base = os.path.join(
            env.backup_dir, f"example_{backup_type}_{timestamp}_{seq[0]:02d}"
        )
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
        assert result.returncode == 0, f"dar {backup_type} failed: {result.stderr}"
        add_result = runner.run([
            "manager", "--add-specific-archive", archive_base,
            "--config-file", env.config_file,
            "--log-stdout",
        ], timeout=300)
        assert add_result.returncode == 0, f"manager add failed: {add_result.stderr}"
        return archive_base

    # --- FULL backup → T0 ---
    full_archive = create_archive("FULL")
    t0 = clock.tick(PITR_STEP_SECONDS)

    # Overwrite every special-char file with a modified value.
    for name in original_content:
        fpath = os.path.join(env.data_dir, name)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(f"modified: {name}")
        clock.touch(fpath, seconds=PITR_STEP_SECONDS)

    # --- DIFF backup → T1 ---
    create_archive("DIFF", base_archive=full_archive)
    t1 = clock.tick(PITR_STEP_SECONDS)

    data_dir_rel = env.data_dir.lstrip("/")

    # --- PITR restore at T0 → original content ---
    restore_t0 = os.path.join(env.test_dir, "restore_specials_t0")
    os.makedirs(restore_t0, exist_ok=True)
    result = runner.run([
        "manager",
        "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", data_dir_rel,
        "--when", t0.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_t0,
        "--log-stdout",
    ], timeout=300)
    assert result.returncode == 0, f"PITR T0 failed: {result.stderr}"

    restored_t0 = os.path.join(restore_t0, data_dir_rel)
    failures = []
    for name, expected in original_content.items():
        fpath = os.path.join(restored_t0, name)
        if not os.path.exists(fpath):
            failures.append(f"MISSING at T0: '{name}'")
            continue
        with open(fpath, encoding="utf-8") as f:
            actual = f.read()
        if actual != expected:
            failures.append(
                f"CONTENT MISMATCH at T0 for '{name}': "
                f"expected {expected!r}, got {actual!r}"
            )
    assert not failures, "Special-char PITR failures at T0:\n" + "\n".join(failures)
    env.logger.info("T0 restore verified: %d special-char files have original content", len(original_content))

    # --- PITR restore at T1 → modified content ---
    restore_t1 = os.path.join(env.test_dir, "restore_specials_t1")
    os.makedirs(restore_t1, exist_ok=True)
    result = runner.run([
        "manager",
        "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", data_dir_rel,
        "--when", t1.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_t1,
        "--log-stdout",
    ], timeout=300)
    assert result.returncode == 0, f"PITR T1 failed: {result.stderr}"

    restored_t1 = os.path.join(restore_t1, data_dir_rel)
    failures = []
    for name in original_content:
        expected = f"modified: {name}"
        fpath = os.path.join(restored_t1, name)
        if not os.path.exists(fpath):
            failures.append(f"MISSING at T1: '{name}'")
            continue
        with open(fpath, encoding="utf-8") as f:
            actual = f.read()
        if actual != expected:
            failures.append(
                f"CONTENT MISMATCH at T1 for '{name}': "
                f"expected {expected!r}, got {actual!r}"
            )
    assert not failures, "Special-char PITR failures at T1:\n" + "\n".join(failures)
    env.logger.info("T1 restore verified: %d special-char files have modified content", len(original_content))

    env.logger.info("Special character filename PITR test passed.")


def test_pitr_multiple_full_archives_boundary(setup_environment, env):
    """
    Verify PITR selects the correct archive chain when two FULL archives exist
    and --when timestamps straddle the FULL rotation boundary.

    Chain: FULL_1 -> DIFF_1 -> INCR_1 -> FULL_2 -> DIFF_2

    Four restores cover every selection region:
    - after DIFF_1 : FULL_1 + DIFF_1 (must not bleed into INCR_1 or FULL_2)
    - after INCR_1 : FULL_1 + DIFF_1 + INCR_1
    - after FULL_2 : FULL_2 only (new FULL resets the chain)
    - after DIFF_2 : FULL_2 + DIFF_2
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    seq = [0]

    def create_archive(backup_type, base_archive=None):
        seq[0] += 1
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        base = os.path.join(env.backup_dir, f"example_{backup_type}_{ts}_{seq[0]:02d}")
        cmd = ["dar", "-c", base, "-N", "-B", env.dar_rc, "-B", backup_def_path,
               "-Q", "compress-exclusion", "verbose"]
        if base_archive:
            cmd.extend(["-A", base_archive])
        r = runner.run(cmd, timeout=300)
        assert r.returncode == 0, f"dar {backup_type} failed: {r.stderr}"
        r2 = runner.run([
            "manager", "--add-specific-archive", base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert r2.returncode == 0, f"manager add failed: {r2.stderr}"
        return base

    def write_file(name, content):
        fpath = os.path.join(env.data_dir, name)
        with open(fpath, "w") as f:
            f.write(content)
        clock.touch(fpath, seconds=PITR_STEP_SECONDS)

    def restore_and_verify(when_dt, label, expected):
        restore_dir = os.path.join(env.test_dir, f"restore_{label}")
        os.makedirs(restore_dir, exist_ok=True)
        r = runner.run([
            "manager", "--config-file", env.config_file,
            "--backup-def", "example",
            "--restore-path", env.data_dir.lstrip("/"),
            "--when", when_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "--target", restore_dir, "--log-stdout",
        ], timeout=300)
        assert r.returncode == 0, f"PITR {label} failed: {r.stderr}"
        base = os.path.join(restore_dir, env.data_dir.lstrip("/"))
        actual = {}
        if os.path.isdir(base):
            for name in sorted(os.listdir(base)):
                fpath = os.path.join(base, name)
                if os.path.isfile(fpath):
                    with open(fpath) as f:
                        actual[name] = f.read()
        assert actual == expected, (
            f"PITR {label} mismatch.\nExpected: {expected}\nActual:   {actual}"
        )
        env.logger.info("PITR %s verified: %d files correct.", label, len(actual))

    # --- FULL_1: tracked=state-1, stable=stable ---
    write_file("tracked.txt", "state-1")
    write_file("stable.txt", "stable-content")
    full1 = create_archive("FULL")

    # --- DIFF_1: tracked -> state-2 ---
    write_file("tracked.txt", "state-2")
    diff1 = create_archive("DIFF", base_archive=full1)
    t_diff1 = clock.tick(PITR_STEP_SECONDS)

    # --- INCR_1: tracked -> state-3, new file ---
    write_file("tracked.txt", "state-3")
    write_file("incr1_only.txt", "incr1-content")
    _ = create_archive("INCR", base_archive=diff1)
    t_incr1 = clock.tick(PITR_STEP_SECONDS)

    # --- FULL_2: fresh full over current disk state ---
    write_file("tracked.txt", "state-4")
    write_file("full2_only.txt", "full2-content")
    full2 = create_archive("FULL")
    t_full2 = clock.tick(PITR_STEP_SECONDS)

    # --- DIFF_2: tracked -> state-5 ---
    write_file("tracked.txt", "state-5")
    create_archive("DIFF", base_archive=full2)
    t_diff2 = clock.tick(PITR_STEP_SECONDS)

    restore_and_verify(t_diff1, "diff1", {
        "tracked.txt": "state-2",
        "stable.txt": "stable-content",
        # incr1_only and full2_only not yet created at this point
    })
    restore_and_verify(t_incr1, "incr1", {
        "tracked.txt": "state-3",
        "stable.txt": "stable-content",
        "incr1_only.txt": "incr1-content",
        # full2_only not yet created
    })
    restore_and_verify(t_full2, "full2", {
        # FULL_2 captured everything on disk: tracked=4, stable, incr1_only, full2_only
        "tracked.txt": "state-4",
        "stable.txt": "stable-content",
        "incr1_only.txt": "incr1-content",
        "full2_only.txt": "full2-content",
    })
    restore_and_verify(t_diff2, "diff2", {
        "tracked.txt": "state-5",
        "stable.txt": "stable-content",
        "incr1_only.txt": "incr1-content",
        "full2_only.txt": "full2-content",
    })


def test_pitr_detect_directory_via_catalog_fallback(setup_environment, env):
    """
    Verify _detect_directory() falls back to dar -l catalog inspection when the
    path no longer exists on the live filesystem.

    This is the disaster-recovery path: a directory is backed up, then deleted
    from disk entirely. PITR must detect it as a directory by inspecting the
    archive catalog (not os.path.isdir) and restore the full subtree.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    # Create a subdirectory with a nested file tree inside data_dir.
    mydir = os.path.join(env.data_dir, "mydir")
    subdir = os.path.join(mydir, "sub")
    os.makedirs(subdir, exist_ok=True)
    hello_path = os.path.join(mydir, "hello.txt")
    world_path = os.path.join(subdir, "world.txt")
    with open(hello_path, "w") as f:
        f.write("hello")
    clock.touch(hello_path, seconds=PITR_STEP_SECONDS)
    with open(world_path, "w") as f:
        f.write("world")
    clock.touch(world_path, seconds=PITR_STEP_SECONDS)

    # FULL backup capturing mydir and its contents.
    archive_time = clock.tick(PITR_STEP_SECONDS)
    ts = archive_time.strftime("%Y-%m-%d_%H%M%S")
    archive_base = os.path.join(env.backup_dir, f"example_FULL_{ts}_01")
    r = runner.run([
        "dar", "-c", archive_base, "-N", "-B", env.dar_rc,
        "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
    ], timeout=300)
    assert r.returncode == 0, f"dar FULL failed: {r.stderr}"
    r2 = runner.run([
        "manager", "--add-specific-archive", archive_base,
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r2.returncode == 0, f"manager add failed: {r2.stderr}"
    t_full = clock.tick(PITR_STEP_SECONDS)

    # Remove mydir from the live filesystem — simulates accidental deletion or
    # restoring on a different machine where the path does not exist.
    shutil.rmtree(mydir)
    assert not os.path.exists(mydir), "mydir must be absent before PITR to exercise the fallback"

    # PITR: restore the deleted directory. _detect_directory() will find that
    # os.path.isdir() returns False and fall back to dar -l on the FULL archive.
    restore_dir = os.path.join(env.test_dir, "restore_catalog_fallback")
    os.makedirs(restore_dir, exist_ok=True)
    restore_path = mydir.lstrip("/")
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", restore_path,
        "--when", t_full.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_dir, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"PITR catalog-fallback restore failed: {r.stderr}"

    restored_mydir = os.path.join(restore_dir, restore_path)
    assert os.path.isdir(restored_mydir), f"mydir not restored: {restored_mydir}"

    hello_restored = os.path.join(restored_mydir, "hello.txt")
    assert os.path.exists(hello_restored), "hello.txt missing after catalog-fallback restore"
    with open(hello_restored) as f:
        assert f.read() == "hello", "hello.txt content wrong after catalog-fallback restore"

    world_restored = os.path.join(restored_mydir, "sub", "world.txt")
    assert os.path.exists(world_restored), "sub/world.txt missing after catalog-fallback restore"
    with open(world_restored) as f:
        assert f.read() == "world", "sub/world.txt content wrong after catalog-fallback restore"

    env.logger.info("_detect_directory catalog fallback verified: mydir and subtree restored correctly.")


def test_pitr_catalog_fallback_restores_0700_directory(setup_environment, env):
    """
    Verify the dar -l catalog fallback detects a mode-700 directory as a directory.

    Regression test: the permission regex previously required a word boundary
    after the permission string, which silently failed for modes ending in '-'
    ('drwx------', 'drwxr-x---', ...).  A deleted private directory (the classic
    example is ~/.ssh) was then misclassified as a file and restored from a
    single archive instead of the full chain — or not at all.

    Same disaster-recovery scenario as test_pitr_detect_directory_via_catalog_fallback,
    with restrictive permissions: 700 on the directory, 750 on its subdirectory.

    A DIFF archive is included so the FULL→DIFF chain merge is observable: with
    the old regex the misclassified path would be restored from a single archive
    at best, so one of the two files (FULL-only or DIFF-only) would be missing —
    this test cannot pass accidentally on the buggy code.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    # Private directory tree: 700 top-level, 750 subdirectory.
    privdir = os.path.join(env.data_dir, "privdir")
    subdir = os.path.join(privdir, "sub")
    os.makedirs(subdir, exist_ok=True)
    key_path = os.path.join(privdir, "id_test")
    nested_path = os.path.join(subdir, "nested.txt")
    with open(key_path, "w") as f:
        f.write("secret key material")
    clock.touch(key_path, seconds=PITR_STEP_SECONDS)
    with open(nested_path, "w") as f:
        f.write("nested secret")
    clock.touch(nested_path, seconds=PITR_STEP_SECONDS)
    os.chmod(subdir, 0o750)
    os.chmod(privdir, 0o700)

    # FULL backup capturing privdir and its contents.
    archive_time = clock.tick(PITR_STEP_SECONDS)
    ts = archive_time.strftime("%Y-%m-%d_%H%M%S")
    archive_base = os.path.join(env.backup_dir, f"example_FULL_{ts}_01")
    r = runner.run([
        "dar", "-c", archive_base, "-N", "-B", env.dar_rc,
        "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
    ], timeout=300)
    assert r.returncode == 0, f"dar FULL failed: {r.stderr}"
    r2 = runner.run([
        "manager", "--add-specific-archive", archive_base,
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r2.returncode == 0, f"manager add failed: {r2.stderr}"

    # Add a second file inside the 700 directory and capture it in a DIFF, so a
    # correct restore requires merging the FULL→DIFF chain.
    diff_file_path = os.path.join(privdir, "added_for_diff.txt")
    with open(diff_file_path, "w") as f:
        f.write("added for diff")
    clock.touch(diff_file_path, seconds=PITR_STEP_SECONDS)
    diff_time = clock.tick(PITR_STEP_SECONDS)
    diff_ts = diff_time.strftime("%Y-%m-%d_%H%M%S")
    diff_base = os.path.join(env.backup_dir, f"example_DIFF_{diff_ts}_02")
    r = runner.run([
        "dar", "-c", diff_base, "-N", "-B", env.dar_rc,
        "-B", backup_def_path, "-A", archive_base,
        "-Q", "compress-exclusion", "verbose",
    ], timeout=300)
    assert r.returncode == 0, f"dar DIFF failed: {r.stderr}"
    r2 = runner.run([
        "manager", "--add-specific-archive", diff_base,
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r2.returncode == 0, f"manager add DIFF failed: {r2.stderr}"
    t_after_diff = clock.tick(PITR_STEP_SECONDS)

    # Delete the private directory — the fallback must detect it via dar -l.
    shutil.rmtree(privdir)
    assert not os.path.exists(privdir), "privdir must be absent before PITR to exercise the fallback"

    restore_dir = os.path.join(env.test_dir, "restore_0700_fallback")
    os.makedirs(restore_dir, exist_ok=True)
    restore_path = privdir.lstrip("/")
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", restore_path,
        "--when", t_after_diff.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_dir, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"PITR 0700-directory fallback restore failed: {r.stderr}"

    restored_privdir = os.path.join(restore_dir, restore_path)
    assert os.path.isdir(restored_privdir), (
        f"privdir not restored as a directory: {restored_privdir} — "
        f"a mode-700 directory was misclassified by the permission regex"
    )
    assert (os.stat(restored_privdir).st_mode & 0o777) == 0o700, (
        "restored privdir must keep its 700 permissions"
    )

    key_restored = os.path.join(restored_privdir, "id_test")
    assert os.path.isfile(key_restored), "id_test missing after 0700 fallback restore"
    with open(key_restored) as f:
        assert f.read() == "secret key material", "id_test content wrong after restore"

    restored_subdir = os.path.join(restored_privdir, "sub")
    assert os.path.isdir(restored_subdir), "750 subdirectory missing after restore"
    assert (os.stat(restored_subdir).st_mode & 0o777) == 0o750, (
        "restored subdirectory must keep its 750 permissions"
    )
    nested_restored = os.path.join(restored_subdir, "nested.txt")
    assert os.path.isfile(nested_restored), "sub/nested.txt missing after restore"
    with open(nested_restored) as f:
        assert f.read() == "nested secret", "sub/nested.txt content wrong after restore"

    # The DIFF-only file proves the FULL→DIFF chain was applied (a single-archive
    # restore of either archive alone cannot produce both files).
    diff_restored = os.path.join(restored_privdir, "added_for_diff.txt")
    assert os.path.isfile(diff_restored), (
        "added_for_diff.txt missing — FULL→DIFF chain was not applied to the 700 directory"
    )
    with open(diff_restored) as f:
        assert f.read() == "added for diff", "added_for_diff.txt content wrong after restore"

    env.logger.info("0700-directory catalog fallback verified: private tree restored via chain with permissions intact.")


def test_pitr_file_selection_follows_archive_date_contract(setup_environment, env):
    """
    Pin the PITR contract for single-file restores: selection is by ARCHIVE
    creation date, never by recorded file mtime (doc/pitr-archive-date-vs-file-mtime.md).

    Uses time-suffixed archive names for second-level archive dates. Three scenarios,
    all with --when between the file edit/rename and the DIFF that captured it:

    1. Edit trap: report.txt edited BEFORE --when, DIFF taken AFTER --when.
       mtime-based selection would return the edited v2 from the future DIFF;
       the contract requires v1 from the FULL.
    2. Rename trap: original.txt renamed (mtime unchanged) after FULL; the new
       name exists only in the future DIFF. mtime-based selection would restore
       it; the contract requires "no version found" (exit 1).
    3. Positive: --when after the DIFF restores the edited v2.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    report_path = os.path.join(env.data_dir, "report.txt")
    original_path = os.path.join(env.data_dir, "original.txt")
    renamed_path = os.path.join(env.data_dir, "renamed.txt")
    with open(report_path, "w") as f:
        f.write("v1 content")
    clock.touch(report_path, seconds=PITR_STEP_SECONDS)
    with open(original_path, "w") as f:
        f.write("rename me")
    clock.touch(original_path, seconds=PITR_STEP_SECONDS)

    # FULL captures report.txt v1 and original.txt.
    full_time = clock.tick(PITR_STEP_SECONDS)
    full_ts = full_time.strftime("%Y-%m-%d_%H%M%S")
    full_base = os.path.join(env.backup_dir, f"example_FULL_{full_ts}_01")
    r = runner.run([
        "dar", "-c", full_base, "-N", "-B", env.dar_rc,
        "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
    ], timeout=300)
    assert r.returncode == 0, f"dar FULL failed: {r.stderr}"
    r = runner.run([
        "manager", "--add-specific-archive", full_base,
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"manager add FULL failed: {r.stderr}"

    # Edit report.txt (v2, mtime BEFORE t_between) and rename original.txt
    # (mtime unchanged, still before the FULL's date).
    clock.tick(PITR_STEP_SECONDS)
    with open(report_path, "w") as f:
        f.write("v2 content")
    clock.touch(report_path, seconds=PITR_STEP_SECONDS)
    os.rename(original_path, renamed_path)

    # --when target: after the edit/rename, before the DIFF exists.
    t_between = clock.tick(PITR_STEP_SECONDS)

    # DIFF captures v2 and the rename.
    diff_time = clock.tick(PITR_STEP_SECONDS)
    diff_ts = diff_time.strftime("%Y-%m-%d_%H%M%S")
    diff_base = os.path.join(env.backup_dir, f"example_DIFF_{diff_ts}_02")
    r = runner.run([
        "dar", "-c", diff_base, "-N", "-B", env.dar_rc,
        "-B", backup_def_path, "-A", full_base,
        "-Q", "compress-exclusion", "verbose",
    ], timeout=300)
    assert r.returncode == 0, f"dar DIFF failed: {r.stderr}"
    r = runner.run([
        "manager", "--add-specific-archive", diff_base,
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"manager add DIFF failed: {r.stderr}"
    t_after_diff = clock.tick(PITR_STEP_SECONDS)

    report_rel = report_path.lstrip("/")
    renamed_rel = renamed_path.lstrip("/")

    # Scenario 1 — edit trap: --when between edit and DIFF must yield v1 (FULL).
    target_v1 = os.path.join(env.test_dir, "restore_contract_v1")
    os.makedirs(target_v1, exist_ok=True)
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", report_rel,
        "--when", t_between.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", target_v1, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"contract restore (v1) failed: {r.stderr}"
    restored_report = os.path.join(target_v1, report_rel)
    assert os.path.isfile(restored_report), "report.txt missing from contract restore"
    with open(restored_report) as f:
        content = f.read()
    assert content == "v1 content", (
        f"--when predates the DIFF: the edited v2 (old mtime, future archive) must be "
        f"excluded; expected 'v1 content', got {content!r}"
    )

    # Scenario 2 — rename trap: the new name did not exist at t_between.
    target_rename = os.path.join(env.test_dir, "restore_contract_rename")
    os.makedirs(target_rename, exist_ok=True)
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", renamed_rel,
        "--when", t_between.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", target_rename, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 1, (
        "renamed.txt exists only in the future DIFF: PITR must fail (exit 1), "
        f"not resurrect it via its old mtime; got rc={r.returncode}"
    )
    assert not os.path.exists(os.path.join(target_rename, renamed_rel)), (
        "renamed.txt must NOT be restored for a --when before the rename was captured"
    )

    # Scenario 3 — positive: --when after the DIFF yields the edited v2.
    target_v2 = os.path.join(env.test_dir, "restore_contract_v2")
    os.makedirs(target_v2, exist_ok=True)
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", report_rel,
        "--when", t_after_diff.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", target_v2, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"contract restore (v2) failed: {r.stderr}"
    with open(os.path.join(target_v2, report_rel)) as f:
        content = f.read()
    assert content == "v2 content", (
        f"--when after the DIFF must select it; expected 'v2 content', got {content!r}"
    )

    env.logger.info("PITR file archive-date contract verified: edit trap, rename trap, and post-DIFF selection.")


def test_pitr_dir_deleted_before_newer_full_restores_old_chain(setup_environment, env):
    """
    Regression test: _detect_directory's catalog fallback must inspect the
    chain selected for --when, not the newest FULL in the catalog.

    Timeline: FULL#1 captures olddir/a.txt; DIFF#1 adds olddir/b.txt; olddir
    is deleted; FULL#2 runs WITHOUT olddir. Restoring olddir at a --when
    between DIFF#1 and the deletion must apply the FULL#1+DIFF#1 chain and
    produce BOTH files.

    Pre-fix, the fallback inspected only the newest FULL (#2), where olddir
    does not exist → misclassified as a file → restored from the single
    newest archive that saved it (DIFF#1) → a.txt silently missing, exit 0.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    olddir = os.path.join(env.data_dir, "olddir")
    os.makedirs(olddir, exist_ok=True)
    a_path = os.path.join(olddir, "a.txt")
    with open(a_path, "w") as f:
        f.write("from full")
    clock.touch(a_path, seconds=PITR_STEP_SECONDS)

    def _make_archive(archive_type: str, seq: str, base_archive: Optional[str] = None) -> str:
        """Create a time-suffixed archive of env.data_dir and add it to the catalog."""
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        archive_base = os.path.join(env.backup_dir, f"example_{archive_type}_{ts}_{seq}")
        cmd = [
            "dar", "-c", archive_base, "-N", "-B", env.dar_rc,
            "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        result = runner.run(cmd, timeout=300)
        assert result.returncode == 0, f"dar {archive_type} failed: {result.stderr}"
        result = runner.run([
            "manager", "--add-specific-archive", archive_base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert result.returncode == 0, f"manager add {archive_type} failed: {result.stderr}"
        return archive_base

    full1_base = _make_archive("FULL", "01")

    b_path = os.path.join(olddir, "b.txt")
    with open(b_path, "w") as f:
        f.write("from diff")
    clock.touch(b_path, seconds=PITR_STEP_SECONDS)
    _make_archive("DIFF", "02", base_archive=full1_base)

    # --when target: after the DIFF, before the deletion and the newer FULL.
    t_mid = clock.tick(PITR_STEP_SECONDS)

    # Delete olddir; the newer FULL never contains it.
    shutil.rmtree(olddir)
    _make_archive("FULL", "03")

    restore_dir = os.path.join(env.test_dir, "restore_old_chain")
    os.makedirs(restore_dir, exist_ok=True)
    restore_path = olddir.lstrip("/")
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", restore_path,
        "--when", t_mid.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_dir, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"old-chain directory restore failed: {r.stderr}"

    restored_olddir = os.path.join(restore_dir, restore_path)
    assert os.path.isdir(restored_olddir), (
        "olddir not restored as a directory — misclassified because the "
        "fallback inspected the newest FULL instead of the --when chain"
    )
    a_restored = os.path.join(restored_olddir, "a.txt")
    assert os.path.isfile(a_restored), (
        "a.txt (FULL#1-only) missing — restored from a single archive instead "
        "of the FULL#1+DIFF#1 chain"
    )
    with open(a_restored) as f:
        assert f.read() == "from full"
    b_restored = os.path.join(restored_olddir, "b.txt")
    assert os.path.isfile(b_restored), "b.txt (DIFF#1) missing from chain restore"
    with open(b_restored) as f:
        assert f.read() == "from diff"

    env.logger.info("when-aware directory detection verified: old chain restored despite newer FULL.")


def test_pitr_after_archive_path_relocation(setup_environment, env):
    """
    Verify PITR works after archive slices are physically moved to a new
    directory and the catalog is updated via manager --relocate-archive-path.

    This is the standard storage-migration workflow: archives are moved,
    the catalog is updated, and PITR must still find and restore the data.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    seq = [0]

    def create_archive(backup_type, base_archive=None):
        seq[0] += 1
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        base = os.path.join(env.backup_dir, f"example_{backup_type}_{ts}_{seq[0]:02d}")
        cmd = ["dar", "-c", base, "-N", "-B", env.dar_rc, "-B", backup_def_path,
               "-Q", "compress-exclusion", "verbose"]
        if base_archive:
            cmd.extend(["-A", base_archive])
        r = runner.run(cmd, timeout=300)
        assert r.returncode == 0, f"dar {backup_type} failed: {r.stderr}"
        r2 = runner.run([
            "manager", "--add-specific-archive", base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert r2.returncode == 0, f"manager add failed: {r2.stderr}"
        return base

    # FULL with one tracked file.
    fpath = os.path.join(env.data_dir, "relocate_me.txt")
    with open(fpath, "w") as f:
        f.write("original-content")
    clock.touch(fpath, seconds=PITR_STEP_SECONDS)
    full_archive = create_archive("FULL")
    t_full = clock.tick(PITR_STEP_SECONDS)

    # DIFF: modify the file so the catalog holds two versions.
    with open(fpath, "w") as f:
        f.write("modified-content")
    clock.touch(fpath, seconds=PITR_STEP_SECONDS)
    create_archive("DIFF", base_archive=full_archive)

    # Move all .dar slices to a new directory, leaving the .db in place.
    new_backup_dir = os.path.join(env.test_dir, "backups_new")
    os.makedirs(new_backup_dir, exist_ok=True)
    for fname in os.listdir(env.backup_dir):
        if fname.endswith(".dar"):
            shutil.move(
                os.path.join(env.backup_dir, fname),
                os.path.join(new_backup_dir, fname),
            )

    # Update the catalog so it points at the new location.
    r = runner.run([
        "manager",
        "--relocate-archive-path", env.backup_dir, new_backup_dir,
        "--backup-def", "example",
        "--config-file", env.config_file,
        "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"--relocate-archive-path failed: {r.stderr}"

    # PITR at FULL time must restore original-content via the new path.
    restore_dir = os.path.join(env.test_dir, "restore_relocated")
    os.makedirs(restore_dir, exist_ok=True)
    restore_path = fpath.lstrip("/")
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", restore_path,
        "--when", t_full.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_dir, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"PITR after relocation failed: {r.stderr}"

    restored_file = os.path.join(restore_dir, restore_path)
    assert os.path.exists(restored_file), f"Restored file missing: {restored_file}"
    with open(restored_file) as f:
        assert f.read() == "original-content", "Wrong content after relocation + PITR"

    env.logger.info("Archive path relocation + PITR verified successfully.")


def test_pitr_report_and_pitr_report_first(setup_environment, env):
    """
    Verify --pitr-report and --pitr-report-first with real archives:

    1. --pitr-report returns 0 when the archive chain is intact.
    2. --pitr-report returns non-zero when the FULL slice is missing.
    3. --pitr-report-first with an intact chain proceeds to restore correctly.
    4. --pitr-report-first aborts without restoring when the chain is broken.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    seq = [0]

    def create_archive(backup_type, base_archive=None):
        seq[0] += 1
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        base = os.path.join(env.backup_dir, f"example_{backup_type}_{ts}_{seq[0]:02d}")
        cmd = ["dar", "-c", base, "-N", "-B", env.dar_rc, "-B", backup_def_path,
               "-Q", "compress-exclusion", "verbose"]
        if base_archive:
            cmd.extend(["-A", base_archive])
        r = runner.run(cmd, timeout=300)
        assert r.returncode == 0, f"dar {backup_type} failed: {r.stderr}"
        r2 = runner.run([
            "manager", "--add-specific-archive", base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert r2.returncode == 0, f"manager add failed: {r2.stderr}"
        return base

    fpath = os.path.join(env.data_dir, "report_test.txt")
    with open(fpath, "w") as f:
        f.write("v1")
    clock.touch(fpath, seconds=PITR_STEP_SECONDS)
    full_archive = create_archive("FULL")

    with open(fpath, "w") as f:
        f.write("v2")
    clock.touch(fpath, seconds=PITR_STEP_SECONDS)
    create_archive("DIFF", base_archive=full_archive)
    t_diff = clock.tick(PITR_STEP_SECONDS)

    restore_path = env.data_dir.lstrip("/")
    when_str = t_diff.strftime("%Y-%m-%d %H:%M:%S")
    full_slice = f"{full_archive}.1.dar"
    assert os.path.exists(full_slice), f"FULL slice not found: {full_slice}"
    full_slice_hidden = full_slice + ".hidden"

    # --- Part 1: intact chain → rc 0 ---
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--pitr-report",
        "--restore-path", restore_path,
        "--when", when_str,
        "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"--pitr-report with intact chain failed: {r.stderr}"
    env.logger.info("--pitr-report intact chain: rc=0 ✓")

    # --- Part 2: missing FULL slice → rc != 0 ---
    os.rename(full_slice, full_slice_hidden)
    try:
        r = runner.run([
            "manager", "--config-file", env.config_file,
            "--backup-def", "example",
            "--pitr-report",
            "--restore-path", restore_path,
            "--when", when_str,
            "--log-stdout",
        ], timeout=300)
        assert r.returncode != 0, "--pitr-report should fail when FULL slice is missing"
        env.logger.info("--pitr-report missing slice: rc=%d (non-zero) ✓", r.returncode)
    finally:
        os.rename(full_slice_hidden, full_slice)

    # --- Part 3: --pitr-report-first with intact chain → restores content ---
    restore_dir_ok = os.path.join(env.test_dir, "restore_report_first_ok")
    os.makedirs(restore_dir_ok, exist_ok=True)
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--pitr-report-first",
        "--restore-path", restore_path,
        "--when", when_str,
        "--target", restore_dir_ok,
        "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"--pitr-report-first with intact chain failed: {r.stderr}"
    restored_file = os.path.join(restore_dir_ok, restore_path, "report_test.txt")
    assert os.path.exists(restored_file), "Restored file missing after --pitr-report-first"
    with open(restored_file) as f:
        assert f.read() == "v2", "Wrong content after --pitr-report-first restore"
    env.logger.info("--pitr-report-first intact chain: rc=0, content verified ✓")

    # --- Part 4: --pitr-report-first with missing slice → aborts, no restore ---
    os.rename(full_slice, full_slice_hidden)
    try:
        restore_dir_fail = os.path.join(env.test_dir, "restore_report_first_fail")
        os.makedirs(restore_dir_fail, exist_ok=True)
        r = runner.run([
            "manager", "--config-file", env.config_file,
            "--backup-def", "example",
            "--pitr-report-first",
            "--restore-path", restore_path,
            "--when", when_str,
            "--target", restore_dir_fail,
            "--log-stdout",
        ], timeout=300)
        assert r.returncode != 0, "--pitr-report-first should abort when FULL slice is missing"
        # The nested restore path must not exist — no restore was attempted.
        restored_data_dir = os.path.join(restore_dir_fail, restore_path)
        assert not os.path.exists(restored_data_dir), (
            "--pitr-report-first restored files despite a broken chain"
        )
        env.logger.info("--pitr-report-first broken chain: rc=%d, no restore ✓", r.returncode)
    finally:
        os.rename(full_slice_hidden, full_slice)


def test_pitr_when_before_any_archive(setup_environment, env):
    """
    Verify PITR returns a non-zero exit code when --when is earlier than every
    archive in the catalog.

    _select_archive_chain returns an empty list when no FULL archive exists at
    or before the requested timestamp, and _restore_with_dar propagates rc=1.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    for name in os.listdir(env.data_dir):
        path = os.path.join(env.data_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)

    fpath = os.path.join(env.data_dir, "file.txt")
    with open(fpath, "w") as f:
        f.write("content")

    # Record a timestamp that will be strictly before the archive is created.
    before_archive = clock.tick(PITR_STEP_SECONDS)

    # Create the FULL archive after recording before_archive.
    clock.touch(fpath, seconds=PITR_STEP_SECONDS)
    ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
    archive_base = os.path.join(env.backup_dir, f"example_FULL_{ts}_01")
    r = runner.run([
        "dar", "-c", archive_base, "-N", "-B", env.dar_rc,
        "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
    ], timeout=300)
    assert r.returncode == 0, f"dar FULL failed: {r.stderr}"
    r2 = runner.run([
        "manager", "--add-specific-archive", archive_base,
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r2.returncode == 0, f"manager add failed: {r2.stderr}"

    # PITR with --when before any archive: _select_archive_chain returns [] → rc 1.
    restore_dir = os.path.join(env.test_dir, "restore_before_any")
    os.makedirs(restore_dir, exist_ok=True)
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", env.data_dir.lstrip("/"),
        "--when", before_archive.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_dir, "--log-stdout",
    ], timeout=300)
    assert r.returncode != 0, (
        f"PITR should fail when --when precedes every archive, got rc={r.returncode}"
    )
    env.logger.info(
        "PITR with --when before any archive returned rc=%d (non-zero) ✓", r.returncode
    )


def test_pitr_multipath_dir_and_file(setup_environment, env):
    """
    Verify that a single --restore-path call with both a directory and a file
    path exercises the for-path loop in _restore_with_dar(), taking the directory
    branch for one path and the file-version branch for the other.

    Archive layout:
        FULL: subdir/fileA.txt = "fileA-v1", top_file.txt = "top-v1"
        DIFF: subdir/fileA.txt = "fileA-v2"  (top_file unchanged)

    Restore --when = just before DIFF (→ FULL only for both paths).
    Expected: subdir/fileA.txt = "fileA-v1", top_file.txt = "top-v1".
    """
    _apply_fast_pitr_config(env)
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    # Clear default test data so archives only contain our controlled files.
    for name in os.listdir(env.data_dir):
        p = os.path.join(env.data_dir, name)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.remove(p)

    subdir = os.path.join(env.data_dir, "subdir")
    os.makedirs(subdir, exist_ok=True)
    file_a = os.path.join(subdir, "fileA.txt")
    top_file = os.path.join(env.data_dir, "top_file.txt")

    with open(file_a, "w") as f:
        f.write("fileA-v1")
    with open(top_file, "w") as f:
        f.write("top-v1")

    seq = [0]

    def create_archive(backup_type, base_archive=None):
        seq[0] += 1
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        base = os.path.join(env.backup_dir, f"example_{backup_type}_{ts}_{seq[0]:02d}")
        cmd = [
            "dar", "-c", base, "-N", "-B", env.dar_rc,
            "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        r = runner.run(cmd, timeout=300)
        assert r.returncode == 0, f"dar {backup_type} failed: {r.stderr}"
        r2 = runner.run([
            "manager", "--add-specific-archive", base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert r2.returncode == 0, f"manager add failed: {r2.stderr}"
        return base

    full1 = create_archive("FULL")
    t_after_full = clock.tick(PITR_STEP_SECONDS)  # timestamp to use as --when

    # DIFF: update file_a (top_file unchanged)
    with open(file_a, "w") as f:
        f.write("fileA-v2")
    clock.touch(file_a, seconds=PITR_STEP_SECONDS)
    _ = create_archive("DIFF", base_archive=full1)

    restore_dir = os.path.join(env.test_dir, "restore_multipath")
    os.makedirs(restore_dir, exist_ok=True)

    subdir_rp = subdir.lstrip("/")
    top_file_rp = top_file.lstrip("/")

    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", subdir_rp, top_file_rp,
        "--when", t_after_full.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_dir, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"PITR multi-path failed: {r.stderr}"

    restored_a = os.path.join(restore_dir, subdir_rp, "fileA.txt")
    restored_top = os.path.join(restore_dir, top_file_rp)

    with open(restored_a) as f:
        assert f.read() == "fileA-v1", "subdir/fileA.txt should be v1 from FULL"
    with open(restored_top) as f:
        assert f.read() == "top-v1", "top_file.txt should be top-v1 from FULL"

    env.logger.info("Multi-path PITR (dir + file) ✓")


def test_pitr_file_single_version_full_only(setup_environment, env):
    """
    Verify PITR restores a file that exists only in the FULL archive when
    dar_manager -f returns a single candidate.

    stable.txt is written once into FULL and never modified — the DIFF archive
    treats it as unchanged and does not contain a new copy.  Requesting PITR at
    DIFF-time for stable.txt must restore the FULL version.
    """
    _apply_fast_pitr_config(env)
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    for name in os.listdir(env.data_dir):
        p = os.path.join(env.data_dir, name)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.remove(p)

    stable = os.path.join(env.data_dir, "stable.txt")
    changed = os.path.join(env.data_dir, "changed.txt")
    with open(stable, "w") as f:
        f.write("stable-content")
    with open(changed, "w") as f:
        f.write("changed-v1")

    seq = [0]

    def create_archive(backup_type, base_archive=None):
        seq[0] += 1
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        base = os.path.join(env.backup_dir, f"example_{backup_type}_{ts}_{seq[0]:02d}")
        cmd = [
            "dar", "-c", base, "-N", "-B", env.dar_rc,
            "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        r = runner.run(cmd, timeout=300)
        assert r.returncode == 0, f"dar {backup_type} failed: {r.stderr}"
        r2 = runner.run([
            "manager", "--add-specific-archive", base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert r2.returncode == 0, f"manager add failed: {r2.stderr}"
        return base

    full1 = create_archive("FULL")

    # Modify changed.txt; stable.txt stays identical → DIFF won't store a new copy.
    with open(changed, "w") as f:
        f.write("changed-v2")
    clock.touch(changed, seconds=PITR_STEP_SECONDS)
    _ = create_archive("DIFF", base_archive=full1)
    t_after_diff = clock.tick(PITR_STEP_SECONDS)

    restore_dir = os.path.join(env.test_dir, "restore_single_ver")
    os.makedirs(restore_dir, exist_ok=True)

    stable_rp = stable.lstrip("/")

    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", stable_rp,
        "--when", t_after_diff.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_dir, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"PITR single-version file failed: {r.stderr}"

    restored = os.path.join(restore_dir, stable_rp)
    with open(restored) as f:
        content = f.read()
    assert content == "stable-content", (
        f"Expected 'stable-content', got '{content}'"
    )
    env.logger.info("Single-version file PITR (FULL-only candidate) ✓")


def test_pitr_two_backup_definitions_catalog_isolation(setup_environment, env):
    """
    Verify that two independent backup definitions ('home' and 'proj') each have
    their own catalog database and that PITR for one definition does not bleed
    into the other.

    Each definition gets a FULL archive with a unique file.  PITR for 'home'
    must restore only the home file; PITR for 'proj' must restore only the proj
    file.
    """
    _apply_fast_pitr_config(env)
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()

    # ------------------------------------------------------------------
    # Create two data trees and their backup definitions
    # ------------------------------------------------------------------
    home_data = os.path.join(env.test_dir, "home_data")
    proj_data = os.path.join(env.test_dir, "proj_data")
    os.makedirs(home_data, exist_ok=True)
    os.makedirs(proj_data, exist_ok=True)

    home_file = os.path.join(home_data, "home_secret.txt")
    proj_file = os.path.join(proj_data, "proj_readme.txt")
    with open(home_file, "w") as f:
        f.write("home-only-content")
    with open(proj_file, "w") as f:
        f.write("proj-only-content")

    def make_def(name: str, data_dir: str) -> str:
        """Write a backup definition file and return its path."""
        content = (
            f"-R /\n"
            f"-s 10G\n"
            f"-z6\n"
            f"-am\n"
            f"--cache-directory-tagging\n"
            f"-g {data_dir}\n"
        ).replace("-g /tmp/", "-g tmp/")
        def_path = os.path.join(env.backup_d_dir, name)
        with open(def_path, "w") as f:
            f.write(content)
        return def_path

    home_def = make_def("home", home_data)
    proj_def = make_def("proj", proj_data)

    # Create separate catalog DBs for each definition
    for backup_def in ("home", "proj"):
        r = runner.run([
            "manager", "--create-db", "--backup-def", backup_def,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert r.returncode == 0, f"--create-db --backup-def {backup_def} failed: {r.stderr}"

    seq = [0]

    def create_archive(backup_type: str, backup_def_name: str, def_path: str, base_archive=None) -> str:
        seq[0] += 1
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        base = os.path.join(env.backup_dir, f"{backup_def_name}_{backup_type}_{ts}_{seq[0]:02d}")
        cmd = [
            "dar", "-c", base, "-N", "-B", env.dar_rc,
            "-B", def_path, "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        r = runner.run(cmd, timeout=300)
        assert r.returncode == 0, f"dar {backup_type} ({backup_def_name}) failed: {r.stderr}"
        r2 = runner.run([
            "manager", "--add-specific-archive", base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert r2.returncode == 0, f"manager add ({backup_def_name}) failed: {r2.stderr}"
        return base

    _ = create_archive("FULL", "home", home_def)
    t_home_full = clock.tick(PITR_STEP_SECONDS)
    _ = create_archive("FULL", "proj", proj_def)
    t_proj_full = clock.tick(PITR_STEP_SECONDS)

    # ------------------------------------------------------------------
    # PITR for 'home' — must restore home_file, must NOT restore proj_file
    # ------------------------------------------------------------------
    restore_home = os.path.join(env.test_dir, "restore_home")
    os.makedirs(restore_home, exist_ok=True)
    home_rp = home_file.lstrip("/")

    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "home",
        "--restore-path", home_rp,
        "--when", t_home_full.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_home, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"PITR home failed: {r.stderr}"

    restored_home_file = os.path.join(restore_home, home_rp)
    assert os.path.exists(restored_home_file), "home_secret.txt should be restored"
    with open(restored_home_file) as f:
        assert f.read() == "home-only-content"

    proj_in_home_restore = os.path.join(restore_home, proj_file.lstrip("/"))
    assert not os.path.exists(proj_in_home_restore), (
        "proj file must NOT appear in the home restore"
    )

    # ------------------------------------------------------------------
    # PITR for 'proj' — must restore proj_file, must NOT restore home_file
    # ------------------------------------------------------------------
    restore_proj = os.path.join(env.test_dir, "restore_proj")
    os.makedirs(restore_proj, exist_ok=True)
    proj_rp = proj_file.lstrip("/")

    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "proj",
        "--restore-path", proj_rp,
        "--when", t_proj_full.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_proj, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"PITR proj failed: {r.stderr}"

    restored_proj_file = os.path.join(restore_proj, proj_rp)
    assert os.path.exists(restored_proj_file), "proj_readme.txt should be restored"
    with open(restored_proj_file) as f:
        assert f.read() == "proj-only-content"

    home_in_proj_restore = os.path.join(restore_proj, home_file.lstrip("/"))
    assert not os.path.exists(home_in_proj_restore), (
        "home file must NOT appear in the proj restore"
    )

    env.logger.info("Two-definition catalog isolation ✓")


def test_pitr_file_failfast_missing_diff_slice(setup_environment, env):
    """
    Verify that when the best-match archive slice for a file is the DIFF archive
    but its .dar slice is missing, PITR returns non-zero and does NOT silently
    fall back to restoring the FULL version.

    The fail-fast break at lines 1217-1221 of manager.py must prevent the older
    FULL version from leaking through as a silent success.
    """
    _apply_fast_pitr_config(env)
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    for name in os.listdir(env.data_dir):
        p = os.path.join(env.data_dir, name)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.remove(p)

    target_file = os.path.join(env.data_dir, "target.txt")
    with open(target_file, "w") as f:
        f.write("target-v1")

    seq = [0]

    def create_archive(backup_type, base_archive=None):
        seq[0] += 1
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        base = os.path.join(env.backup_dir, f"example_{backup_type}_{ts}_{seq[0]:02d}")
        cmd = [
            "dar", "-c", base, "-N", "-B", env.dar_rc,
            "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        r = runner.run(cmd, timeout=300)
        assert r.returncode == 0, f"dar {backup_type} failed: {r.stderr}"
        r2 = runner.run([
            "manager", "--add-specific-archive", base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert r2.returncode == 0, f"manager add failed: {r2.stderr}"
        return base

    full1 = create_archive("FULL")
    # Modify target_file so DIFF contains a new version.
    with open(target_file, "w") as f:
        f.write("target-v2")
    clock.touch(target_file, seconds=PITR_STEP_SECONDS)
    diff1 = create_archive("DIFF", base_archive=full1)
    t_after_diff = clock.tick(PITR_STEP_SECONDS)

    # Find the first .dar slice of the DIFF archive and hide it.
    diff_slice = diff1 + ".1.dar"
    assert os.path.exists(diff_slice), f"Expected DIFF slice at {diff_slice}"
    diff_slice_hidden = diff_slice + ".hidden"
    os.rename(diff_slice, diff_slice_hidden)

    restore_dir = os.path.join(env.test_dir, "restore_failfast")
    os.makedirs(restore_dir, exist_ok=True)
    target_rp = target_file.lstrip("/")

    try:
        r = runner.run([
            "manager", "--config-file", env.config_file,
            "--backup-def", "example",
            "--restore-path", target_rp,
            "--when", t_after_diff.strftime("%Y-%m-%d %H:%M:%S"),
            "--target", restore_dir, "--log-stdout",
        ], timeout=300)
        assert r.returncode != 0, (
            f"PITR should fail when DIFF slice is missing, got rc={r.returncode}"
        )

        # The file must NOT be restored (no silent FULL fallback).
        restored = os.path.join(restore_dir, target_rp)
        assert not os.path.exists(restored), (
            "target.txt must NOT be restored from FULL after DIFF slice failure"
        )
        env.logger.info("Fail-fast on missing DIFF slice ✓ (rc=%d)", r.returncode)
    finally:
        os.rename(diff_slice_hidden, diff_slice)


def test_pitr_timezone_aware_when(setup_environment, env):
    """
    Verify that a timezone-aware --when string (UTC offset) is correctly handled
    by _normalize_when_dt() when selecting the archive chain.

    Two archives are created:
        FULL:  target.txt = "v1"
        DIFF:  target.txt = "v2"

    Two PITR calls use UTC-formatted --when strings:
        1. Between FULL and DIFF → expect "v1"
        2. After DIFF            → expect "v2"
    """
    _apply_fast_pitr_config(env)
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()
    backup_def_path = os.path.join(env.backup_d_dir, "example")

    from datetime import timezone

    def local_to_utc_str(dt: datetime) -> str:
        """Convert a naive local datetime to a UTC offset string that _normalize_when_dt() understands."""
        local_tz = datetime.now(timezone.utc).astimezone().tzinfo
        aware_local = dt.replace(tzinfo=local_tz)
        utc_dt = aware_local.astimezone(timezone.utc)
        return utc_dt.strftime("%Y-%m-%d %H:%M:%S+00:00")

    for name in os.listdir(env.data_dir):
        p = os.path.join(env.data_dir, name)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.remove(p)

    target_file = os.path.join(env.data_dir, "target.txt")
    with open(target_file, "w") as f:
        f.write("v1")

    seq = [0]

    def create_archive(backup_type, base_archive=None):
        seq[0] += 1
        ts = clock.tick(PITR_STEP_SECONDS).strftime("%Y-%m-%d_%H%M%S")
        base = os.path.join(env.backup_dir, f"example_{backup_type}_{ts}_{seq[0]:02d}")
        cmd = [
            "dar", "-c", base, "-N", "-B", env.dar_rc,
            "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
        ]
        if base_archive:
            cmd.extend(["-A", base_archive])
        r = runner.run(cmd, timeout=300)
        assert r.returncode == 0, f"dar {backup_type} failed: {r.stderr}"
        r2 = runner.run([
            "manager", "--add-specific-archive", base,
            "--config-file", env.config_file, "--log-stdout",
        ], timeout=300)
        assert r2.returncode == 0, f"manager add failed: {r2.stderr}"
        return base

    full1 = create_archive("FULL")
    t_between = clock.tick(PITR_STEP_SECONDS)  # after FULL, before DIFF

    with open(target_file, "w") as f:
        f.write("v2")
    clock.touch(target_file, seconds=PITR_STEP_SECONDS)
    _ = create_archive("DIFF", base_archive=full1)
    t_after_diff = clock.tick(PITR_STEP_SECONDS)

    target_rp = target_file.lstrip("/")

    # --- Restore 1: --when between FULL and DIFF (UTC string) → expect v1 ---
    restore_v1 = os.path.join(env.test_dir, "restore_tz_v1")
    os.makedirs(restore_v1, exist_ok=True)
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", target_rp,
        "--when", local_to_utc_str(t_between),
        "--target", restore_v1, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"PITR tz v1 failed: {r.stderr}"

    restored_v1 = os.path.join(restore_v1, target_rp)
    with open(restored_v1) as f:
        content = f.read()
    assert content == "v1", f"Expected 'v1' from FULL, got '{content}'"
    env.logger.info("Timezone-aware PITR → v1 (between FULL/DIFF) ✓")

    # --- Restore 2: --when after DIFF (UTC string) → expect v2 ---
    restore_v2 = os.path.join(env.test_dir, "restore_tz_v2")
    os.makedirs(restore_v2, exist_ok=True)
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "example",
        "--restore-path", target_rp,
        "--when", local_to_utc_str(t_after_diff),
        "--target", restore_v2, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"PITR tz v2 failed: {r.stderr}"

    restored_v2 = os.path.join(restore_v2, target_rp)
    with open(restored_v2) as f:
        content = f.read()
    assert content == "v2", f"Expected 'v2' from DIFF, got '{content}'"
    env.logger.info("Timezone-aware PITR → v2 (after DIFF) ✓")


def test_pitr_restore_path_with_non_root_backup_definition(setup_environment, env):
    """
    Regression test for v2/BUG.txt: manager.py's _is_directory_path() hardcoded
    os.sep, assuming a backup definition's -R was always "/". With a real -R
    other than "/", the fast filesystem check looks in the wrong place (real
    "/" instead of the actual -R root) and misdetects a genuine directory as
    "not a directory".

    "newdir" here is created entirely in the DIFF and extended in the INCR, so
    the FULL archive never contains it. (Historically the archive-catalog
    fallback inspected only the most recent FULL and could not mask the
    mis-detection; it now inspects the --when-selected chain, but the fast
    filesystem check exercised here remains the first line of detection.) dar_manager's own -f lookup *does* track directory paths and reports
    whichever archive most recently touched "newdir" (the INCR) as its latest
    version, so pre-fix, PITR silently restores *only* that single archive
    instead of the correct additive DIFF+INCR chain. Since a differential/
    incremental archive never carries forward unchanged files, a single-
    archive (INCR-only) restore of "newdir" would be missing the stable file
    and the hardlink pair entirely -- exactly the "restored files matched
    stale content and one hard-linked file went missing entirely" symptom
    reported in v2/BUG.txt. A correct additive chain restore (DIFF, then INCR
    on top) produces the full, current set.

    Also exercises a -R root containing a space and non-ASCII (UTF-8)
    characters -- a real path shape that must not break -R parsing or the
    restore itself.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    clock = TestClock()

    # A source root that is NOT "/", and contains a space + UTF-8 characters.
    alt_root = os.path.join(env.data_dir, "backup source café ünïcödé 日本語")
    os.makedirs(alt_root, exist_ok=True)

    backup_def_path = os.path.join(env.backup_d_dir, "altroot")
    with open(backup_def_path, "w", encoding="utf-8") as f:
        # Quoted: dar's own -B reference-file parser splits an unquoted -R
        # value on whitespace (confirmed empirically) -- a path containing a
        # space *must* be quoted, exactly like get_backup_definition_root()
        # expects to unquote.
        f.write(f'-R "{alt_root}"\n-s 10G\n-z6\n-am\n--cache-directory-tagging\n')

    # The shared setup_environment fixture only creates a catalog db for the
    # "example" definition (present at fixture setup time, before this
    # definition file existed) -- create one for "altroot" now.
    r0 = runner.run([
        "manager", "--create-db", "-d", "altroot",
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r0.returncode == 0, f"manager --create-db (altroot) failed: {r0.stderr}"

    # --- FULL: a stable file elsewhere in alt_root. "newdir" does NOT exist
    # yet -- the FULL archive must never contain it, so the archive-catalog
    # fallback (which only inspects the most recent FULL) cannot mask a
    # mis-detection later.
    other_file = os.path.join(alt_root, "other.txt")
    with open(other_file, "w") as f:
        f.write("unrelated content")
    clock.touch(other_file, seconds=PITR_STEP_SECONDS)

    full_time = clock.tick(PITR_STEP_SECONDS)
    full_ts = full_time.strftime("%Y-%m-%d_%H%M%S")
    full_base = os.path.join(env.backup_dir, f"altroot_FULL_{full_ts}")
    r = runner.run([
        "dar", "-c", full_base, "-N", "-B", env.dar_rc,
        "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
    ], timeout=300)
    assert r.returncode == 0, f"dar FULL failed: {r.stderr}"
    r2 = runner.run([
        "manager", "--add-specific-archive", full_base,
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r2.returncode == 0, f"manager add (FULL) failed: {r2.stderr}"

    # --- DIFF: "newdir" is created here for the first time, with a stable
    # file, a to-be-modified file, and a hardlinked file pair.
    newdir = os.path.join(alt_root, "newdir")
    os.makedirs(newdir, exist_ok=True)
    stable_path = os.path.join(newdir, "stable.txt")
    with open(stable_path, "w") as f:
        f.write("stable content")
    clock.touch(stable_path, seconds=PITR_STEP_SECONDS)
    changing_path = os.path.join(newdir, "changing.txt")
    with open(changing_path, "w") as f:
        f.write("v1")
    clock.touch(changing_path, seconds=PITR_STEP_SECONDS)
    link1 = os.path.join(newdir, "link1.txt")
    link2 = os.path.join(newdir, "link2.txt")
    with open(link1, "w") as f:
        f.write("linked content")
    clock.touch(link1, seconds=PITR_STEP_SECONDS)
    os.link(link1, link2)

    diff_time = clock.tick(PITR_STEP_SECONDS)
    diff_ts = diff_time.strftime("%Y-%m-%d_%H%M%S")
    diff_base = os.path.join(env.backup_dir, f"altroot_DIFF_{diff_ts}")
    r = runner.run([
        "dar", "-c", diff_base, "-N", "-B", env.dar_rc,
        "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
        "-A", full_base,
    ], timeout=300)
    assert r.returncode == 0, f"dar DIFF failed: {r.stderr}"
    r2 = runner.run([
        "manager", "--add-specific-archive", diff_base,
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r2.returncode == 0, f"manager add (DIFF) failed: {r2.stderr}"

    # --- INCR: only "changing.txt" is modified. stable.txt and the hardlink
    # pair are untouched, so an incremental archive does not carry them --
    # only the additive DIFF+INCR chain has the complete, current "newdir".
    with open(changing_path, "w") as f:
        f.write("v2")
    clock.touch(changing_path, seconds=PITR_STEP_SECONDS)

    incr_time = clock.tick(PITR_STEP_SECONDS)
    incr_ts = incr_time.strftime("%Y-%m-%d_%H%M%S")
    incr_base = os.path.join(env.backup_dir, f"altroot_INCR_{incr_ts}")
    r = runner.run([
        "dar", "-c", incr_base, "-N", "-B", env.dar_rc,
        "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
        "-A", diff_base,
    ], timeout=300)
    assert r.returncode == 0, f"dar INCR failed: {r.stderr}"
    r2 = runner.run([
        "manager", "--add-specific-archive", incr_base,
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r2.returncode == 0, f"manager add (INCR) failed: {r2.stderr}"

    restore_time = clock.tick(PITR_STEP_SECONDS)

    # --- PITR restore of the directory, as of after the INCR. ---
    restore_dir = os.path.join(env.test_dir, "restore_altroot")
    os.makedirs(restore_dir, exist_ok=True)
    r = runner.run([
        "manager", "--config-file", env.config_file,
        "--backup-def", "altroot",
        "--restore-path", "newdir",
        "--when", restore_time.strftime("%Y-%m-%d %H:%M:%S"),
        "--target", restore_dir, "--log-stdout",
    ], timeout=300)
    assert r.returncode == 0, f"PITR restore of 'newdir' failed: {r.stderr}"

    restored_dir = os.path.join(restore_dir, "newdir")
    assert os.path.isdir(restored_dir), (
        f"'newdir' was not restored as a directory -- PITR likely fell back to "
        f"a single-archive restore attempt instead of the additive chain (the "
        f"exact bug reported in v2/BUG.txt). restore_dir contents: {os.listdir(restore_dir)}"
    )

    restored_changing = os.path.join(restored_dir, "changing.txt")
    assert os.path.exists(restored_changing), "changing.txt missing after restore"
    with open(restored_changing) as f:
        assert f.read() == "v2", "changing.txt must show the INCR's latest content"

    restored_stable = os.path.join(restored_dir, "stable.txt")
    assert os.path.exists(restored_stable), (
        "stable.txt missing after restore -- a single-archive (INCR-only) "
        "restore would be missing this, since the INCR never carries forward "
        "unchanged files. Proves the additive DIFF+INCR chain was used."
    )
    with open(restored_stable) as f:
        assert f.read() == "stable content"

    restored_link1 = os.path.join(restored_dir, "link1.txt")
    restored_link2 = os.path.join(restored_dir, "link2.txt")
    assert os.path.exists(restored_link1), "link1.txt missing after restore"
    assert os.path.exists(restored_link2), (
        "link2.txt (hardlink) missing after restore -- matches the "
        "'hard-linked file went missing entirely' symptom from v2/BUG.txt"
    )
    assert os.stat(restored_link1).st_ino == os.stat(restored_link2).st_ino, (
        "link1.txt and link2.txt must share the same inode after restore -- "
        "the hardlink relationship was not preserved"
    )

    env.logger.info(
        "PITR restore-path with non-root (-R) backup definition, including "
        "spaces/UTF-8, verified correct: additive chain restore used, "
        "directory + hardlink preserved, no stale/missing content."
    )
