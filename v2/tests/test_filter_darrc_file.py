import os
import logging

from dar_backup.dar_backup import filter_darrc_file
from tests.envdata import EnvData
import pytest

pytestmark = pytest.mark.unit








def test_filter_darrc_file_removes_verbose_flags(monkeypatch, tmp_path):
    logger = logging.getLogger("test_logger")
    command_logger = logging.getLogger("command_logger")
    env = EnvData("FilterDarrcVerboseTest", logger, command_logger, base_dir=tmp_path)

    # Create test .darrc content with verbose flags and valid entries
    verbose_lines = [
        "-vt", "-vs", "-vd", "-vf", "-va",  # should be removed
        "+ /important/data", "- /tmp", "-v", "--", "+ /extra"
    ]

    os.makedirs(env.test_dir, exist_ok=True)
    test_darrc_path = os.path.join(env.test_dir, ".darrc")
    with open(test_darrc_path, "w") as f:
        f.write("\n".join(verbose_lines))

    # Redirect HOME to a temporary location
    fake_home = os.path.join(env.test_dir, "fake_home")
    os.makedirs(fake_home, exist_ok=True)
    monkeypatch.setenv("HOME", fake_home)

    # Call the function and get the filtered file path
    filtered_path = filter_darrc_file(test_darrc_path)

    # Verify the file was created
    assert os.path.exists(filtered_path)

    env.logger.info(f"Filtered darrc: {filtered_path}")

    with open(filtered_path, "r") as f:
        filtered_lines = f.read().splitlines()

    # These flags should have been removed
    for removed in ["-vt", "-vs", "-vd", "-vf", "-va"]:
        assert removed not in filtered_lines

    # These should remain
    for kept in ["+ /important/data", "- /tmp", "-v", "--", "+ /extra"]:
        assert kept in filtered_lines
