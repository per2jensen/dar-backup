import os
import sys
from configparser import ConfigParser
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner
from tests.envdata import EnvData


def _write_random_file(path: str, size: int) -> None:
    with open(path, "wb") as f:
        f.write(os.urandom(size))


def _configure_par2_dir(env: EnvData, par2_dir: str) -> None:
    config = ConfigParser()
    config.read(env.config_file)
    config["PAR2"]["PAR2_DIR"] = par2_dir
    config["PAR2"]["PAR2_MODE"] = "per-archive"
    config["PAR2"]["PAR2_RATIO_FULL"] = "5"
    with open(env.config_file, "w") as f:
        config.write(f)


def test_par2_dir_manifest_and_repair(setup_environment, env: EnvData):
    os.makedirs(env.data_dir, exist_ok=True)
    _write_random_file(os.path.join(env.data_dir, "a.bin"), 2048)
    _write_random_file(os.path.join(env.data_dir, "b.bin"), 4096)

    par2_dir = os.path.join(env.test_dir, "par2")
    os.makedirs(par2_dir, exist_ok=True)
    _configure_par2_dir(env, par2_dir)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = [
        "dar-backup",
        "-F",
        "-d",
        "example",
        "--config-file",
        env.config_file,
        "--log-level",
        "debug",
        "--log-stdout",
    ]
    result = runner.run(command)
    if result.returncode != 0:
        raise RuntimeError(f"dar-backup failed: {result.stderr}")

    date = datetime.now().strftime("%Y-%m-%d")
    archive_base = f"example_FULL_{date}"
    par2_path = os.path.join(par2_dir, f"{archive_base}.par2")
    manifest_path = f"{par2_path}.manifest.ini"
    assert os.path.exists(par2_path), f"Expected par2 set at: {par2_path}"
    assert os.path.exists(manifest_path), f"Expected manifest at: {manifest_path}"

    backup_par2_matches = [f for f in os.listdir(env.backup_dir) if f.startswith(archive_base) and f.endswith(".par2")]
    assert not backup_par2_matches, f"Found par2 files in archive dir: {backup_par2_matches}"

    slice_path = os.path.join(env.backup_dir, f"{archive_base}.1.dar")
    with open(slice_path, "r+b") as f:
        original = f.read(1)
        f.seek(0)
        if not original:
            raise RuntimeError("Failed to read data from slice for corruption test")
        flipped = bytes([original[0] ^ 0xFF])
        f.write(flipped)

    verify_command = ["par2", "verify", "-B", env.backup_dir, par2_path]
    verify_result = runner.run(verify_command)
    assert verify_result.returncode != 0, "Expected par2 verify to fail after corruption"

    repair_command = ["par2", "repair", "-B", env.backup_dir, par2_path]
    repair_result = runner.run(repair_command)
    assert repair_result.returncode == 0, f"par2 repair failed: {repair_result.stderr}"

    verify_result = runner.run(verify_command)
    assert verify_result.returncode == 0, "Expected par2 verify to succeed after repair"
