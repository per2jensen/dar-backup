import os
import pytest


from types import SimpleNamespace
from unittest.mock import patch
import logging

from pathlib import Path

from dar_backup.util import (
    expand_path,
    _default_completer_logfile,
    _setup_completer_logger,
    backup_definition_completer,
    list_archive_completer,
    archive_content_completer
)





def test_expand_path(monkeypatch):
    monkeypatch.setenv("TEST_VAR", "expanded")
    path = "~/$TEST_VAR/some/path"
    expanded = expand_path(path)
    expected = os.path.join(os.path.expanduser("~"), "expanded/some/path")
    assert expanded == expected


def test_default_completer_logfile_includes_uid():
    if not hasattr(os, "getuid"):
        pytest.skip("os.getuid not available on this platform")
    logfile = _default_completer_logfile()
    assert str(os.getuid()) in os.path.basename(logfile)
    assert logfile.startswith("/tmp/")


def test_setup_completer_logger_failure_does_not_raise(monkeypatch):
    logger = logging.getLogger("completer")
    original_handlers = list(logger.handlers)
    logger.handlers = []

    def fail_handler(*_args, **_kwargs):
        raise OSError("boom")

    monkeypatch.setattr("dar_backup.util.logging.FileHandler", fail_handler)
    try:
        test_logger = _setup_completer_logger(logfile="/root/deny.log")
        test_logger.debug("completer logger fallback works")
        assert test_logger is logger
        assert any(isinstance(h, logging.NullHandler) for h in test_logger.handlers)
    finally:
        logger.handlers = original_handlers


def test_backup_definition_completer(setup_environment, tmp_path, env):
    backup_d_dir = env.backup_d_dir
    (Path(backup_d_dir) / "configA").write_text("placeholder")
    (Path(backup_d_dir) / "not_this_one").write_text("placeholder")

    class Args:
        config_file = env.config_file

    results = backup_definition_completer("c", Args())
    env.logger.debug(f"backup_definition_completer() -> {results}")
    assert "configA" in results
    assert "not_this_one" not in results


def test_list_archive_completer_with_definition(tmp_path, setup_environment, env):
    backup_dir = Path(env.backup_dir)
    backup_def = "pCloudDrive"
    expected_files = [
        f"{backup_def}_FULL_2024-01-01.1.dar",
        f"{backup_def}_INCR_2024-01-02.1.dar",
        f"{backup_def}_DIFF_2024-01-03.1.dar"
    ]
    for f in expected_files:
        (backup_dir / f).write_text("fake dar data")

    class Args:
        config_file = env.config_file
        backup_definition = backup_def

    results = list_archive_completer("", Args())
    env.logger.debug(f"list_archive_completer() -> {results}")
    assert set(results) == set(f.replace(".1.dar", "") for f in expected_files)
    

def test_list_archive_completer_all_archives(tmp_path,setup_environment, env):
    backup_dir = Path(env.backup_dir)
    expected_files = [
        "miscBackup_FULL_2024-01-01.1.dar",
        "otherBackup_DIFF_2024-01-02.1.dar",
        "archive_INCR_2024-01-03.1.dar"
    ]
    for f in expected_files:
        (backup_dir / f).write_text("fake dar data")

    class Args:
        config_file = env.config_file
        backup_definition = None

    results = list_archive_completer("", Args())
    env.logger.debug(f"list_archive_completer() -> {results}")
    assert set(results) == set(f.replace(".1.dar", "") for f in expected_files)



def test_archive_content_completer_with_mocked_db(setup_environment, env):
    from types import SimpleNamespace
    from unittest.mock import patch

    # Use existing backup definition created by setup_environment
    backup_def = "example"

    test_path = Path(env.test_dir)

    args = SimpleNamespace(
        config_file=env.config_file,
        backup_def=backup_def,
        manager_db_dir=str(test_path / "backups"),
        backup_dir=str(test_path / "backups")
    )


    # Simulated output from `dar_manager --list`
    mock_dar_output = "\n".join([
        "\t1\t/home/pj/mnt/dar\texample_FULL_2024-01-01",
        "\t2\t/home/pj/mnt/dar\texample_DIFF_2024-01-02",
        "\t3\t/home/pj/mnt/dar\texample_INCR_2024-01-03"
    ])

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = SimpleNamespace(
            stdout=mock_dar_output,
            stderr="",
            returncode=0
        )

        result = archive_content_completer("example", args)

    expected = [
        "example_FULL_2024-01-01",
        "example_DIFF_2024-01-02",
        "example_INCR_2024-01-03"
    ]
    
    assert sorted(result) == sorted(expected)
    

def test_archive_content_completer_global_prefix_match(tmp_path):

    # -- 1. Create dummy config file with required sections
    dummy_config = tmp_path / "dummy.conf"
    dummy_config.write_text(f"""\
[MISC]
LOGFILE_LOCATION = /tmp/test.log
MAX_SIZE_VERIFICATION_MB = 100
MIN_SIZE_VERIFICATION_MB = 1
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 5

[DIRECTORIES]
BACKUP_DIR = {tmp_path}
TEST_RESTORE_DIR = /tmp/restore
BACKUP.D_DIR = /tmp/backup.d

[AGE]
DIFF_AGE = 3
INCR_AGE = 1

[PAR2]
ERROR_CORRECTION_PERCENT = 10
ENABLED = false
""")

    # -- 2. Create dummy databases
    db_path1 = tmp_path / "pCloudDrive.db"
    db_path2 = tmp_path / "testBackup.db"
    db_path1.touch()
    db_path2.touch()

    class Args:
        config_file = str(dummy_config)
        backup_def = None

    def fake_run(cmd, **kwargs):
        if any("pCloudDrive.db" in part for part in cmd):
            return SimpleNamespace(
                stdout="\n".join([
                    "\t1\t/tmp/pCloudDrive\tpCloudDrive_FULL_2024-01-01",
                    "\t2\t/tmp/pCloudDrive\tpCloudDrive_DIFF_2024-01-02",
                    "\t3\t/tmp/pCloudDrive\tpCloudDrive_INCR_2024-01-03"
                ]),
                returncode=0
            )
        elif any("testBackup.db" in part for part in cmd):
            return SimpleNamespace(
                stdout="\n".join([
                    "\t4\t/tmp/testBackup\ttestBackup_FULL_2024-01-04",
                    "\t5\t/tmp/testBackup\ttestBackup_INCR_2024-01-05"
                ]),
                returncode=0
            )
        return SimpleNamespace(stdout="", returncode=1)

    with patch("subprocess.run", side_effect=fake_run):
        result = archive_content_completer("p", Args())

    assert "pCloudDrive_FULL_2024-01-01" in result
    assert "pCloudDrive_DIFF_2024-01-02" in result
    assert "pCloudDrive_INCR_2024-01-03" in result
    assert all("testBackup" not in r for r in result)



def test_archive_content_completer_sorting(tmp_path):
    from types import SimpleNamespace
    from unittest.mock import patch

    # Write valid dummy config
    dummy_config = tmp_path / "dummy.conf"
    dummy_config.write_text(f"""\
[MISC]
LOGFILE_LOCATION = /tmp/test.log
MAX_SIZE_VERIFICATION_MB = 100
MIN_SIZE_VERIFICATION_MB = 1
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 5

[DIRECTORIES]
BACKUP_DIR = {tmp_path}
TEST_RESTORE_DIR = /tmp/restore
BACKUP.D_DIR = /tmp/backup.d

[AGE]
DIFF_AGE = 3
INCR_AGE = 1

[PAR2]
ERROR_CORRECTION_PERCENT = 10
ENABLED = false
""")

    db1 = tmp_path / "alpha.db"
    db2 = tmp_path / "beta.db"
    db1.touch()
    db2.touch()

    class Args:
        config_file = str(dummy_config)
        backup_def = None

    fake_output = "\n".join([
        "\t1\t/tmp/alpha\talpha_FULL_2024-01-01",
        "\t2\t/tmp/alpha\talpha_INCR_2024-01-03",
        "\t3\t/tmp/beta\tbeta_FULL_2024-01-01",
        "\t4\t/tmp/beta\tbeta_INCR_2024-01-02",
    ])

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = SimpleNamespace(stdout=fake_output, returncode=0)
        result = archive_content_completer("", Args())

    expected_order = [
        "alpha_FULL_2024-01-01",
        "alpha_INCR_2024-01-03",
        "beta_FULL_2024-01-01",
        "beta_INCR_2024-01-02"
    ]

    assert result == expected_order

import unittest.mock
from dar_backup.util import add_specific_archive_completer

def test_add_specific_archive_completer_full_coverage(setup_environment, env):
    # Setup
    backup_def = "example"
    backup_dir = env.backup_dir
    archive_prefix = f"{backup_def}_FULL_2025-01-01"
    archive_filename = f"{archive_prefix}.1.dar"
    archive_path = os.path.join(backup_dir, archive_filename)
    open(archive_path, "w").close()

    # Confirm file exists and matches pattern
    assert os.path.exists(archive_path)


    from types import SimpleNamespace
    from pathlib import Path

    test_backups_dir = str(Path(env.test_dir) / "backups")

    args = SimpleNamespace(
        config_file=env.config_file,
        backup_def=backup_def,
        manager_db_dir=test_backups_dir,
        backup_dir=test_backups_dir,
)
    # Test: archive should appear since it's not in the DB yet
    result = add_specific_archive_completer(prefix=archive_prefix[:3], parsed_args=args)
    assert archive_prefix in result

    # Simulate it being listed in the DB by mocking subprocess output
    subprocess_output = f"0\tINFO\t{archive_prefix}\n"
    def fake_run(*_, **__):
        class R:
            stdout = subprocess_output
            returncode = 0
        return R()
    
    subprocess_path = "dar_backup.util.subprocess.run"
    with unittest.mock.patch(subprocess_path, side_effect=fake_run):
        result = add_specific_archive_completer(prefix=archive_prefix[:3], parsed_args=args)
        assert result == ['[no new archives]']

    # Clean up
    if os.path.exists(archive_path):
        os.remove(archive_path)
