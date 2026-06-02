# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests: par2 repair followed by a real file-content restore.

Finding #5 — The existing bitrot tests (test_5_bitrot_recovery,
test_25_bitrot_recovery) verify that dar -t passes after par2 repair.
They do NOT extract files and compare them byte-for-byte against the originals.
dar -t only checks archive integrity checksums; a corrupt-then-repaired archive
could still produce wrong file content on extraction.

These tests go the full distance:

  1. Create a backup with known content.
  2. Inject controlled bitrot into the .dar slice.
  3. Confirm dar -t detects corruption.
  4. Repair with par2.
  5. Extract the archive to a fresh directory.
  6. Compare every extracted file byte-for-byte against the originals.

Marks: integration, slow
"""

import filecmp
import os
import random
import sys
from datetime import datetime
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dar_backup.command_runner import CommandRunner, CommandResult
from tests.envdata import EnvData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEST_FILES = {
    "restore_alpha.txt": "Alpha file content — line 1\nAlpha file content — line 2\n",
    "restore_beta.txt":  "Beta file — some data here\n" * 20,
    "restore_gamma.bin": None,  # binary; created separately
}
_GAMMA_SIZE = 64 * 1024   # 64 kB of random bytes
_BACKUP_DEF = "repair-restore-test"


def _create_test_data(env: EnvData) -> None:
    """Populate data_dir with files whose exact content we can verify later."""
    for name, content in _TEST_FILES.items():
        path = os.path.join(env.data_dir, name)
        if content is None:
            rng = random.Random(42)
            Path(path).write_bytes(bytes(rng.getrandbits(8) for _ in range(_GAMMA_SIZE)))
        else:
            Path(path).write_text(content, encoding="utf-8")


def _write_backup_def_and_catalog(env: EnvData) -> None:
    """Write backup definition and initialise the catalog DB."""
    def_path = os.path.join(env.backup_d_dir, _BACKUP_DEF)
    Path(def_path).write_text(
        "-R /\n-s 10G\n-z6\n-am\n--cache-directory-tagging\n"
        f"-g {env.data_dir.lstrip('/')}\n"
    )
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        ["manager", "--create-db", "--config-file", env.config_file, "--log-stdout"],
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"manager --create-db failed: {result.stderr}")


def _run_full_backup(env: EnvData, runner: CommandRunner) -> None:
    result: CommandResult = runner.run(
        [
            "dar-backup", "--full-backup",
            "-d", _BACKUP_DEF,
            "--log-stdout", "--log-level", "debug",
            "--config-file", env.config_file,
        ],
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"dar-backup failed (rc={result.returncode}): {result.stderr}")


def _archive_slice_path(env: EnvData) -> str:
    """Return the path to the single .1.dar slice created by _run_full_backup."""
    date = datetime.now().strftime("%Y-%m-%d")
    path = os.path.join(env.backup_dir, f"{_BACKUP_DEF}_FULL_{date}.1.dar")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Archive slice not found: {path}")
    return path


def _archive_base(env: EnvData) -> str:
    """Return the archive base path (without .1.dar)."""
    date = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(env.backup_dir, f"{_BACKUP_DEF}_FULL_{date}")


def _inject_bitrot(slice_path: str, corrupt_percent: float) -> None:
    """Overwrite corrupt_percent % of the archive slice with random bytes."""
    size = os.path.getsize(slice_path)
    rng = random.Random(99)
    corrupt_bytes = max(1, int(size * corrupt_percent / 100))
    payload = bytes(rng.getrandbits(8) for _ in range(corrupt_bytes))
    position = rng.randint(0, max(0, size - corrupt_bytes))
    with open(slice_path, "r+b") as fh:
        fh.seek(position)
        fh.write(payload)


def _find_par2_file(env: EnvData) -> str:
    """Return the .par2 index file for the FULL archive."""
    date = datetime.now().strftime("%Y-%m-%d")
    name = f"{_BACKUP_DEF}_FULL_{date}.par2"
    candidates = [
        os.path.join(env.backup_dir, name),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    # Also look in any PAR2_DIR if configured
    all_par2 = [
        os.path.join(env.backup_dir, f)
        for f in os.listdir(env.backup_dir)
        if f.startswith(f"{_BACKUP_DEF}_FULL_") and f.endswith(".par2")
        and ".vol" not in f
    ]
    if all_par2:
        return all_par2[0]
    raise FileNotFoundError("No .par2 index file found for the FULL archive")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_par2_repair_then_extract_matches_source(
    setup_environment, env: EnvData
) -> None:
    """
    Full cycle: backup → inject bitrot → detect corruption → repair → extract
    → byte-for-byte compare every file against its source.

    This is the test that was missing: the existing bitrot tests stop after
    dar -t passes; this one confirms the extracted bytes are actually correct.
    """
    _create_test_data(env)
    _write_backup_def_and_catalog(env)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    _run_full_backup(env, runner)

    slice_path = _archive_slice_path(env)
    archive_base = _archive_base(env)
    par2_file = _find_par2_file(env)

    env.logger.info("Archive slice: %s (%d bytes)", slice_path, os.path.getsize(slice_path))
    env.logger.info("PAR2 index: %s", par2_file)

    # --- Step 1: inject corruption (3% — well within 5% default redundancy)
    _inject_bitrot(slice_path, corrupt_percent=3.0)
    env.logger.info("Injected ~3%% bitrot into %s", slice_path)

    # --- Step 2: dar -t must detect corruption
    check_before = runner.run(["dar", "-t", archive_base, "-N", "-Q"])
    assert check_before.returncode != 0, (
        "dar -t did not detect corruption after bitrot injection"
    )
    env.logger.info("dar -t correctly detected corruption (rc=%d)", check_before.returncode)

    # --- Step 3: par2 repair
    repair = runner.run(
        ["par2", "repair", "-B", env.backup_dir, "-q", par2_file],
        timeout=120,
    )
    assert repair.returncode == 0, (
        f"par2 repair failed (rc={repair.returncode}):\n{repair.stderr}"
    )
    env.logger.info("par2 repaired the archive")

    # --- Step 4: dar -t must pass after repair
    check_after = runner.run(["dar", "-t", archive_base, "-N", "-Q"])
    assert check_after.returncode == 0, (
        f"dar -t still fails after par2 repair (rc={check_after.returncode}):\n"
        f"{check_after.stderr}"
    )
    env.logger.info("dar -t passes after repair")

    # --- Step 5: extract to a fresh directory
    extract_dir = os.path.join(env.test_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    extract = runner.run(
        ["dar", "-x", archive_base, "-R", extract_dir, "-Q", "-N",
         "-B", env.dar_rc, "restore-options"],
        timeout=120,
    )
    assert extract.returncode == 0, (
        f"dar -x (extract) failed after par2 repair (rc={extract.returncode}):\n"
        f"{extract.stderr}"
    )
    env.logger.info("Extraction after repair succeeded")

    # --- Step 6: byte-for-byte comparison
    for name in _TEST_FILES:
        source = os.path.join(env.data_dir, name)
        # dar preserves absolute path under extract_dir
        restored = os.path.join(extract_dir, env.data_dir.lstrip("/"), name)

        assert os.path.exists(restored), (
            f"Extracted file missing: {restored}"
        )
        assert filecmp.cmp(source, restored, shallow=False), (
            f"File content differs after repair+extract: {name}\n"
            f"  source:   {source}\n"
            f"  restored: {restored}"
        )
        env.logger.info("OK byte-for-byte match: %s", name)


def test_par2_repair_does_not_produce_truncated_files(
    setup_environment, env: EnvData
) -> None:
    """
    After par2 repair + extraction, every file must have the same size as
    its source.  A repair that pads with zeros would pass dar -t but produce
    wrong-sized files.
    """
    _create_test_data(env)
    _write_backup_def_and_catalog(env)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    _run_full_backup(env, runner)

    slice_path = _archive_slice_path(env)
    archive_base = _archive_base(env)
    par2_file = _find_par2_file(env)

    _inject_bitrot(slice_path, corrupt_percent=2.5)

    runner.run(["par2", "repair", "-B", env.backup_dir, "-q", par2_file], timeout=120)

    extract_dir = os.path.join(env.test_dir, "size_check_extract")
    os.makedirs(extract_dir, exist_ok=True)
    runner.run(
        ["dar", "-x", archive_base, "-R", extract_dir, "-Q", "-N",
         "-B", env.dar_rc, "restore-options"],
        timeout=120,
    )

    for name in _TEST_FILES:
        source = os.path.join(env.data_dir, name)
        restored = os.path.join(extract_dir, env.data_dir.lstrip("/"), name)

        assert os.path.exists(restored), f"Extracted file missing: {restored}"

        source_size = os.path.getsize(source)
        restored_size = os.path.getsize(restored)
        assert source_size == restored_size, (
            f"Size mismatch for {name}: source={source_size} restored={restored_size}"
        )
        env.logger.info("OK size match for %s (%d bytes)", name, source_size)
