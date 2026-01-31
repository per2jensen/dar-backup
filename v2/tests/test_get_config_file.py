import os
from types import SimpleNamespace

from dar_backup.util import get_config_file
import pytest

pytestmark = pytest.mark.unit









def _expected_path(raw_path: str) -> str:
    return os.path.abspath(os.path.expanduser(os.path.expandvars(raw_path)))


def test_get_config_file_defaults_to_user_config(monkeypatch):
    monkeypatch.delenv("DAR_BACKUP_CONFIG_FILE", raising=False)
    args = SimpleNamespace()
    assert get_config_file(args) == _expected_path("~/.config/dar-backup/dar-backup.conf")


def test_get_config_file_uses_env_override(monkeypatch, tmp_path):
    env_path = tmp_path / "env.conf"
    monkeypatch.setenv("DAR_BACKUP_CONFIG_FILE", str(env_path))
    args = SimpleNamespace()
    assert get_config_file(args) == _expected_path(str(env_path))


def test_get_config_file_cli_wins_over_env(monkeypatch, tmp_path):
    env_path = tmp_path / "env.conf"
    cli_path = tmp_path / "cli.conf"
    monkeypatch.setenv("DAR_BACKUP_CONFIG_FILE", str(env_path))
    args = SimpleNamespace(config_file=str(cli_path))
    assert get_config_file(args) == _expected_path(str(cli_path))


def test_get_config_file_missing_config_file_attr_uses_default(monkeypatch):
    monkeypatch.delenv("DAR_BACKUP_CONFIG_FILE", raising=False)

    class Args:
        pass

    args = Args()
    assert get_config_file(args) == _expected_path("~/.config/dar-backup/dar-backup.conf")


def test_get_config_file_env_none_uses_default(monkeypatch):
    monkeypatch.delenv("DAR_BACKUP_CONFIG_FILE", raising=False)
    args = SimpleNamespace()
    assert get_config_file(args) == _expected_path("~/.config/dar-backup/dar-backup.conf")


def test_get_config_file_ignores_whitespace_env(monkeypatch):
    monkeypatch.setenv("DAR_BACKUP_CONFIG_FILE", "   ")
    args = SimpleNamespace()
    assert get_config_file(args) == _expected_path("~/.config/dar-backup/dar-backup.conf")


def test_get_config_file_whitespace_cli_uses_env(monkeypatch, tmp_path):
    env_path = tmp_path / "env.conf"
    monkeypatch.setenv("DAR_BACKUP_CONFIG_FILE", str(env_path))
    args = SimpleNamespace(config_file="   ")
    assert get_config_file(args) == _expected_path(str(env_path))
