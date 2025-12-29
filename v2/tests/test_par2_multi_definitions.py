"""
Integration test for PAR2 per-backup overrides across multiple backup definitions.

This test:
- Creates three backup definitions with different PAR2 directories and ratios.
- Runs dar-backup to generate archives and PAR2 sets.
- Corrupts a slice, confirms dar -t fails.
- Confirms par2 verify fails, then repairs and re-validates with dar -t.
"""

import os
import glob
from configparser import ConfigParser
from datetime import datetime

from dar_backup.command_runner import CommandRunner
from tests.envdata import EnvData


def _write_random_file(path: str, size: int) -> None:
    with open(path, "wb") as f:
        f.write(os.urandom(size))


def _dar_safe_path(path: str) -> str:
    return path.lstrip("/")


def _write_backup_definition(def_path: str, data_dir: str) -> None:
    content = "\n".join(
        [
            "-R /",
            "-s 10M",
            "-z6",
            "-am",
            "--cache-directory-tagging",
            f"-g {_dar_safe_path(data_dir)}",
        ]
    )
    with open(def_path, "w") as f:
        f.write(content + "\n")


def _configure_par2_overrides(env: EnvData, overrides: dict) -> None:
    config = ConfigParser()
    config.read(env.config_file)
    for section, values in overrides.items():
        if section not in config:
            config[section] = {}
        for key, value in values.items():
            config[section][key] = str(value)
    with open(env.config_file, "w") as f:
        config.write(f)


def _find_archive_base(backup_dir: str, definition: str, date: str) -> str:
    pattern = os.path.join(backup_dir, f"{definition}_FULL_{date}.1.dar")
    matches = glob.glob(pattern)
    if not matches:
        raise RuntimeError(f"No archive found for pattern: {pattern}")
    return os.path.basename(matches[0]).rsplit(".1.dar", 1)[0]


def _flip_first_byte(path: str) -> None:
    with open(path, "r+b") as f:
        original = f.read(1)
        f.seek(0)
        if not original:
            raise RuntimeError(f"Failed to read data from {path}")
        f.write(bytes([original[0] ^ 0xFF]))


def test_par2_multi_definition_repair_flow(setup_environment, env: EnvData):
    date = datetime.now().strftime("%Y-%m-%d")
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    definitions = {
        "media-files": {
            "data_dir": os.path.join(env.test_dir, "data_media"),
            "par2_dir": os.path.join(env.test_dir, "par2_media"),
            "ratio_full": 11,
        },
        "docs": {
            "data_dir": os.path.join(env.test_dir, "data_docs"),
            "par2_dir": os.path.join(env.test_dir, "par2_docs"),
            "ratio_full": 7,
        },
        "pics": {
            "data_dir": os.path.join(env.test_dir, "data_pics"),
            "par2_dir": os.path.join(env.test_dir, "par2_pics"),
            "ratio_full": 5,
        },
    }

    overrides = {}
    for name, cfg in definitions.items():
        os.makedirs(cfg["data_dir"], exist_ok=True)
        os.makedirs(cfg["par2_dir"], exist_ok=True)
        _write_random_file(os.path.join(cfg["data_dir"], "a.bin"), 2048)
        _write_random_file(os.path.join(cfg["data_dir"], "b.bin"), 4096)
        _write_backup_definition(os.path.join(env.backup_d_dir, name), cfg["data_dir"])
        overrides[name] = {
            "PAR2_DIR": cfg["par2_dir"],
            "PAR2_MODE": "per-archive",
            "PAR2_RATIO_FULL": cfg["ratio_full"],
        }

    _configure_par2_overrides(env, overrides)

    create_db = [
        "manager",
        "--create-db",
        "--config-file",
        env.config_file,
        "--log-level",
        "debug",
        "--log-stdout",
    ]
    db_result = runner.run(create_db)
    if db_result.returncode != 0:
        raise RuntimeError(f"manager --create-db failed: {db_result.stderr}")

    for name in definitions:
        command = [
            "dar-backup",
            "-F",
            "-d",
            name,
            "--config-file",
            env.config_file,
            "--log-level",
            "debug",
            "--log-stdout",
        ]
        result = runner.run(command)
        if result.returncode != 0:
            raise RuntimeError(f"dar-backup failed for {name}: {result.stderr}")

    for name, cfg in definitions.items():
        archive_base = _find_archive_base(env.backup_dir, name, date)
        slice_path = os.path.join(env.backup_dir, f"{archive_base}.1.dar")
        par2_path = os.path.join(cfg["par2_dir"], f"{archive_base}.par2")

        _flip_first_byte(slice_path)

        dar_test = runner.run(["dar", "-t", os.path.join(env.backup_dir, archive_base)])
        assert dar_test.returncode != 0, f"dar -t should fail for {archive_base}"

        verify = runner.run(["par2", "verify", "-B", env.backup_dir, par2_path])
        assert verify.returncode != 0, f"par2 verify should fail for {archive_base}"

        repair = runner.run(["par2", "repair", "-B", env.backup_dir, par2_path])
        assert repair.returncode == 0, f"par2 repair failed for {archive_base}: {repair.stderr}"

        dar_test = runner.run(["dar", "-t", os.path.join(env.backup_dir, archive_base)])
        assert dar_test.returncode == 0, f"dar -t should succeed after repair for {archive_base}"
