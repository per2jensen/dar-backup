"""
Integration tests for detecting bitrot and repairing it in dar archives.

Each test creates real dar archives, injects binary corruption into a slice,
confirms dar detects the corruption, then uses par2 to repair it and confirms
dar passes again.
"""

import os
import random
import sys

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from datetime import datetime

from dar_backup.command_runner import CommandResult, CommandRunner
from dar_backup.config_settings import ConfigSettings
from tests.envdata import EnvData


def create_random_data_file(env: EnvData, name: str, size: int) -> None:
    """
    Create a binary file filled with random data.

    Args:
        env: EnvData fixture providing the test directory.
        name: Label used in the filename (e.g. "100kB").
        size: File size in bytes.
    """
    filename = f"random-{name}.dat"
    filepath = os.path.join(env.data_dir, filename)
    with open(filepath, "wb") as fh:
        fh.write(os.urandom(size))
    env.logger.info("Created %s (%d bytes)", filepath, size)


def generate_datafiles(env: EnvData, file_sizes: dict[str, int]) -> None:
    """
    Generate a set of random binary data files for backup testing.

    Args:
        env: EnvData fixture providing the test directory.
        file_sizes: Mapping of label → size-in-bytes.

    Raises:
        Exception: Re-raises any error from file creation after logging it.
    """
    try:
        for name, size in file_sizes.items():
            create_random_data_file(env, name, size)
    except Exception:
        env.logger.exception("Data file generation failed")
        raise


def simulate_bitrot(env: EnvData, bitrot_percent: int) -> None:
    """
    Inject deterministic corruption into the FULL archive slice.

    Overwrites `bitrot_percent * 0.98 %` of the slice with random bytes at a
    deterministic position.  The 0.98 factor keeps the corrupted region
    slightly below `bitrot_percent` so the test stays within par2's recovery
    capacity even accounting for block-alignment overhead.

    Args:
        env: EnvData fixture providing the test directory.
        bitrot_percent: Percentage of the archive to corrupt (0–100).

    Raises:
        FileNotFoundError: If the archive slice does not exist.
    """
    date = datetime.now().strftime("%Y-%m-%d")
    archive_path = os.path.join(env.backup_dir, f"example_FULL_{date}.1.dar")

    if not os.path.exists(archive_path):
        raise FileNotFoundError(f"Archive slice not found: {archive_path}")

    archive_size = os.path.getsize(archive_path)
    env.logger.info("Archive size before bitrot injection: %d bytes", archive_size)

    rng = random.Random(0)  # deterministic seed for reproducibility
    corrupt_bytes = int(archive_size * (bitrot_percent / 100) * 0.98)
    random_data = bytearray(rng.getrandbits(8) for _ in range(corrupt_bytes))
    position = rng.randint(0, int(archive_size * 0.7))

    with open(archive_path, "r+b") as fh:
        fh.seek(position)
        fh.write(random_data)

    env.logger.info(
        "Injected %d%% bitrot (%d bytes at offset %d) into %s",
        bitrot_percent, corrupt_bytes, position, archive_path,
    )


def modify_par2_redundancy(env: EnvData, redundancy: int) -> None:
    """
    Patch ERROR_CORRECTION_PERCENT in the test config file.

    Args:
        env: EnvData fixture providing the config file path.
        redundancy: New redundancy level in percent.
    """
    with open(env.config_file) as fh:
        lines = fh.readlines()
    with open(env.config_file, "w") as fh:
        for line in lines:
            if line.startswith("ERROR_CORRECTION_PERCENT"):
                fh.write(f"ERROR_CORRECTION_PERCENT = {redundancy}\n")
            else:
                fh.write(line)
    env.logger.info("Set ERROR_CORRECTION_PERCENT = %d", redundancy)


def check_bitrot_recovery(env: EnvData, runner: CommandRunner) -> None:
    """
    Verify the three-step bitrot recovery cycle on the current FULL archive.

    Steps:
      1. `dar -t` must fail and report a corruption keyword in stderr,
         confirming the injected bitrot is detected.
      2. `par2 repair` must exit 0.
      3. `dar -t` must exit 0 after repair.

    Args:
        env: EnvData fixture providing directory paths and logger.
        runner: Configured CommandRunner to use for all subprocess calls.

    Raises:
        AssertionError: If any of the three steps produces unexpected results.
    """
    date = datetime.now().strftime("%Y-%m-%d")
    basename_path = os.path.join(env.backup_dir, f"example_FULL_{date}")
    par2_path = os.path.join(env.backup_dir, f"example_FULL_{date}.par2")

    # Step 1 — dar must detect corruption
    result: CommandResult = runner.run(["dar", "-t", basename_path, "-N", "-Q"])
    env.logger.info("dar -t (corrupt) stdout:\n%s", result.stdout)
    env.logger.info("dar -t (corrupt) stderr:\n%s", result.stderr)

    assert result.returncode != 0, "dar returned success on a corrupted archive"
    assert any(
        kw in result.stderr.lower()
        for kw in ("crc", "error", "corrupt", "checksum")
    ), f"Expected a corruption keyword in dar stderr:\n{result.stderr}"
    env.logger.info("dar correctly detected archive corruption.")

    # Step 2 — par2 repair
    result = runner.run(["par2", "repair", "-B", env.backup_dir, "-q", par2_path])
    env.logger.info("par2 repair stdout:\n%s", result.stdout)
    env.logger.info("par2 repair stderr:\n%s", result.stderr)
    assert result.returncode == 0, f"par2 failed to repair the archive (rc={result.returncode})"
    env.logger.info("par2 repaired the archive successfully.")

    # Step 3 — dar must now pass
    result = runner.run(["dar", "-t", basename_path, "-N", "-Q"])
    env.logger.info("dar -t (repaired) stdout:\n%s", result.stdout)
    env.logger.info("dar -t (repaired) stderr:\n%s", result.stderr)
    assert result.returncode == 0, (
        f"dar -t failed after par2 repair (rc={result.returncode}):\n{result.stderr}"
    )
    env.logger.info("Archive verified successfully after par2 repair.")


def run_bitrot_recovery(env: EnvData, redundancy_percentage: int) -> None:
    """
    End-to-end bitrot-recovery scenario for a given par2 redundancy level.

    Corruption is injected at half the redundancy level, keeping the corrupted
    region well within par2's recovery capacity regardless of block-alignment
    overhead.

    Args:
        env: EnvData fixture providing directory paths, config, and loggers.
        redundancy_percentage: par2 ERROR_CORRECTION_PERCENT to configure.
    """
    config_settings = ConfigSettings(env.config_file)
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=config_settings.command_timeout_secs,
    )

    file_sizes: dict[str, int] = {
        "100kB": 100 * 1024,
        "1MB": 1024 * 1024,
        "10MB": 10 * 1024 * 1024,
    }
    generate_datafiles(env, file_sizes)
    modify_par2_redundancy(env, redundancy_percentage)

    command = [
        "dar-backup", "--full-backup", "-d", "example",
        "--config-file", env.config_file,
        "--log-level", "debug", "--log-stdout",
    ]
    process: CommandResult = runner.run(command)
    env.logger.info("dar-backup stdout:\n%s", process.stdout)
    env.logger.info("dar-backup stderr:\n%s", process.stderr)
    if process.returncode != 0:
        raise RuntimeError(
            f"dar-backup --full-backup failed (rc={process.returncode})"
        )

    # Corrupt at half the redundancy level — safely within par2's recovery capacity
    bitrot_percent = max(1, redundancy_percentage // 2)
    simulate_bitrot(env, bitrot_percent)
    check_bitrot_recovery(env, runner)


def test_5_bitrot_recovery(setup_environment, env: EnvData) -> None:
    """
    Verify bitrot detection and par2 recovery at 5% redundancy / ~2% corruption.
    """
    run_bitrot_recovery(env, redundancy_percentage=5)


def test_25_bitrot_recovery(setup_environment, env: EnvData) -> None:
    """
    Verify bitrot detection and par2 recovery at 25% redundancy / ~12% corruption.
    """
    run_bitrot_recovery(env, redundancy_percentage=25)
