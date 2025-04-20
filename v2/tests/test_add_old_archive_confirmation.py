import pytest
from unittest.mock import patch
from inputimeout import TimeoutOccurred
import dar_backup.manager as manager

def test_confirm_add_old_archive_yes(setup_environment, env):
    manager.logger = env.logger
    with patch("dar_backup.manager.inputimeout", return_value="yes"):
        assert manager.confirm_add_old_archive("example_FULL_2024-01-01", "2024-01-10")


def test_confirm_add_old_archive_no(setup_environment, env):
    manager.logger = env.logger
    with patch("dar_backup.manager.inputimeout", return_value="no"):
        assert not manager.confirm_add_old_archive("example_FULL_2024-01-01", "2024-01-10")


def test_confirm_add_old_archive_timeout(setup_environment, env):
    manager.logger = env.logger
    with patch("dar_backup.manager.inputimeout", side_effect=TimeoutOccurred):
        assert not manager.confirm_add_old_archive("example_FULL_2024-01-01", "2024-01-10")


def test_confirm_add_old_archive_keyboard_interrupt(setup_environment, env):
    manager.logger = env.logger
    with patch("dar_backup.manager.inputimeout", side_effect=KeyboardInterrupt):
        assert not manager.confirm_add_old_archive("example_FULL_2024-01-01", "2024-01-10")
