import os
import pytest
import configparser
import re


from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from pathlib import Path

from dar_backup.util import (
    expand_path,
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
    from dar_backup.util import archive_content_completer
    from types import SimpleNamespace
    from unittest.mock import patch

    # Use existing backup definition created by setup_environment
    backup_def = "example"

    args = SimpleNamespace(
        config_file=env.config_file,
        backup_def=backup_def
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

        results = archive_content_completer("example", args)

    expected = [
        "example_FULL_2024-01-01",
        "example_DIFF_2024-01-02",
        "example_INCR_2024-01-03"
    ]
    
    assert results == expected
