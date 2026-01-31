
import os
from  dar_backup.config_settings import ConfigSettings
from dar_backup.installer import run_installer
from dar_backup.manager import get_db_dir
from dar_backup.util import expand_path



import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import dar_backup.installer as installer
import pytest

pytestmark = pytest.mark.unit









# --- Helpers -----------------------------------------------------------------

class DummyCfg:
    def __init__(self, backup_dir, test_restore_dir, backup_d_dir):
        self.backup_dir = backup_dir
        self.test_restore_dir = test_restore_dir
        self.backup_d_dir = backup_d_dir
        # required by run_installer()
        self.logfile_location = os.path.join(backup_dir, "dar-backup.log")
        self.logfile_max_bytes = 1024 * 1024
        self.logfile_no_count = 3

def _patch_min_logging_and_runner():
    # prevent real logging/runner init noise
    return patch.multiple(
        installer,
        setup_logging=MagicMock(),
        get_logger=MagicMock(return_value=MagicMock()),
        CommandRunner=MagicMock(return_value=MagicMock()),
    )


# --- run_installer() core flows ----------------------------------------------

def test_run_installer_creates_required_dirs(tmp_path, capsys):
    cfg_file = tmp_path / "dar-backup.conf"
    cfg_file.write_text("dummy", encoding="utf-8")
    backup_dir = tmp_path / "backups"
    test_restore_dir = tmp_path / "restore"
    backup_d_dir = tmp_path / "backup.d"
    manager_db_dir = tmp_path / "dbdir"

    dummy_cfg = DummyCfg(str(backup_dir), str(test_restore_dir), str(backup_d_dir))

    with patch.object(installer, "ConfigSettings", return_value=dummy_cfg), \
         patch.object(installer, "get_db_dir", return_value=str(manager_db_dir)), \
         patch.object(installer, "expand_path", side_effect=lambda p: p), \
         patch.object(installer, "is_safe_path", return_value=True), \
         _patch_min_logging_and_runner():
        installer.run_installer(str(cfg_file), create_db_flag=False)

    # All required dirs are created
    for p in (backup_dir, test_restore_dir, backup_d_dir, manager_db_dir):
        assert p.exists() and p.is_dir()


def test_run_installer_with_create_db_prints_results(tmp_path, capsys):
    cfg_file = tmp_path / "dar-backup.conf"
    cfg_file.write_text("dummy", encoding="utf-8")
    backup_d_dir = tmp_path / "backup.d"
    backup_d_dir.mkdir(parents=True)
    (backup_d_dir / "photos").write_text("", encoding="utf-8")
    (backup_d_dir / "docs").write_text("", encoding="utf-8")
    (backup_d_dir / "nested").mkdir()

    dummy_cfg = DummyCfg(str(tmp_path / "backups"), str(tmp_path / "restore"), str(backup_d_dir))

    def fake_create_db(name, *_a, **_k):
        return 0 if name == "photos" else 1

    with patch.object(installer, "ConfigSettings", return_value=dummy_cfg), \
         patch.object(installer, "get_db_dir", return_value=str(tmp_path / "db")), \
         patch.object(installer, "expand_path", side_effect=lambda p: p), \
         patch.object(installer, "is_safe_path", return_value=True), \
         patch.object(installer, "create_db", side_effect=fake_create_db), \
         _patch_min_logging_and_runner():
        installer.run_installer(str(cfg_file), create_db_flag=True)

    out = capsys.readouterr().out
    assert "Creating catalog for: photos" in out
    assert "✔️  Catalog created" in out
    assert "Creating catalog for: docs" in out
    assert "❌ Failed to create catalog" in out
    assert "nested" not in out


def test_run_installer_blocks_unsafe_path(tmp_path):
    cfg_file = tmp_path / "dar-backup.conf"
    cfg_file.write_text("dummy", encoding="utf-8")
    dummy_cfg = DummyCfg(str(tmp_path / "backups"), str(tmp_path / "restore"), str(tmp_path / "backup.d"))

    with patch.object(installer, "ConfigSettings", return_value=dummy_cfg), \
         patch.object(installer, "get_db_dir", return_value=str(tmp_path / "db")), \
         patch.object(installer, "expand_path", side_effect=lambda p: p), \
         patch.object(installer, "is_safe_path", return_value=False), \
         _patch_min_logging_and_runner():
        with pytest.raises(ValueError, match="Unsafe path detected"):
            installer.run_installer(str(cfg_file), create_db_flag=False)


# --- main() CLI branches -----------------------------------------------------

def test_installer_main_missing_config_prints_and_returns(monkeypatch, tmp_path, capsys):
    # Nonexistent file
    missing = tmp_path / "no.conf"
    monkeypatch.setattr(sys, "argv", ["installer", "--config", str(missing)])

    # Avoid extra side effects of autocompletion checks
    with patch.object(installer, "install_autocompletion"), \
         patch.object(installer, "uninstall_autocompletion"):
        installer.main()

    out = capsys.readouterr().out
    assert "Config file does not exist" in out


def test_installer_main_calls_run_installer(monkeypatch, tmp_path):
    cfg = tmp_path / "dar-backup.conf"
    cfg.write_text("dummy", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["installer", "--config", str(cfg), "--create-db"])

    with patch.object(installer, "run_installer") as run_mock:
        installer.main()

    run_mock.assert_called_once_with(str(cfg), True)


def test_installer_main_install_autocompletion(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["installer", "--install-autocompletion"])
    with patch.object(installer, "install_autocompletion") as install_mock:
        installer.main()
    install_mock.assert_called_once()


def test_installer_main_remove_autocompletion(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["installer", "--remove-autocompletion"])
    with patch.object(installer, "uninstall_autocompletion") as uninstall_mock:
        installer.main()
    uninstall_mock.assert_called_once()


# --- autocompletion install/uninstall ----------------------------------------

def test_install_autocompletion_appends_and_is_idempotent(monkeypatch, tmp_path):
    # Fake home and shell
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    rc = tmp_path / ".bashrc"
    rc.write_text("# initial\n", encoding="utf-8")

    # First install
    installer.install_autocompletion()
    content1 = rc.read_text(encoding="utf-8")
    assert "dar-backup" in content1  # marker block present

    # Second install should not duplicate
    installer.install_autocompletion()
    content2 = rc.read_text(encoding="utf-8")
    assert content2.count("dar-backup") == content1.count("dar-backup")


def test_install_autocompletion_uses_bash_profile(monkeypatch, tmp_path):
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    bash_profile = tmp_path / ".bash_profile"
    bash_profile.write_text("# profile\n", encoding="utf-8")

    installer.install_autocompletion()

    assert "# >>> dar-backup autocompletion >>>" in bash_profile.read_text(encoding="utf-8")
    assert not (tmp_path / ".bashrc").exists()


def test_install_autocompletion_uses_zsh(monkeypatch, tmp_path):
    monkeypatch.setenv("SHELL", "/bin/zsh")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    installer.install_autocompletion()

    zshrc = tmp_path / ".zshrc"
    assert zshrc.exists()
    assert "# >>> dar-backup autocompletion >>>" in zshrc.read_text(encoding="utf-8")


def test_uninstall_autocompletion_removes_block(monkeypatch, tmp_path):
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    rc = tmp_path / ".bashrc"
    rc.write_text("# initial\n", encoding="utf-8")

    # Install then uninstall
    installer.install_autocompletion()
    assert "dar-backup" in rc.read_text(encoding="utf-8")

    installer.uninstall_autocompletion()
    text = rc.read_text(encoding="utf-8")
    assert "dar-backup" not in text


def test_uninstall_autocompletion_no_marker(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    rc = tmp_path / ".bashrc"
    rc.write_text("# nothing to see\n", encoding="utf-8")

    result = installer.uninstall_autocompletion()

    out = capsys.readouterr().out
    assert "No autocompletion block found" in out
    assert "No autocompletion block found" in result
    assert rc.read_text(encoding="utf-8") == "# nothing to see\n"


def test_install_autocompletion_rc_is_dir(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    rc = tmp_path / ".bashrc"
    rc.mkdir()

    installer.install_autocompletion()

    out = capsys.readouterr().out
    assert "RC path is a directory" in out


def test_uninstall_autocompletion_missing_rc(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    installer.uninstall_autocompletion()

    out = capsys.readouterr().out
    assert "RC file not found" in out


def test_uninstall_autocompletion_rc_is_dir(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    rc = tmp_path / ".bashrc"
    rc.mkdir()

    installer.uninstall_autocompletion()

    out = capsys.readouterr().out
    assert "RC path is a directory" in out


def test_uninstall_autocompletion_end_marker_missing(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    rc = tmp_path / ".bashrc"
    rc.write_text("# >>> dar-backup autocompletion >>>\n# no end marker\n", encoding="utf-8")

    result = installer.uninstall_autocompletion()

    out = capsys.readouterr().out
    assert "end marker not found" in out
    assert "end marker not found" in result
    assert "# >>> dar-backup autocompletion >>>" in rc.read_text(encoding="utf-8")







###########################################


@pytest.mark.parametrize("use_manager_db_dir", [False, True])
def test_installer_creates_catalog(setup_environment, env, use_manager_db_dir):
    """
    Integration test: Ensures run_installer creates catalog databases in correct location.
    """
    # Optionally inject MANAGER_DB_DIR
    if use_manager_db_dir:
        custom_catalog_dir = os.path.join(env.test_dir, "catalogs")
        os.makedirs(custom_catalog_dir, exist_ok=True)
        with open(env.config_file, "a") as f:
            f.write(f"\nMANAGER_DB_DIR = {custom_catalog_dir}\n")

    # Create dummy .def file
    backup_def_name = "demo"
    backup_def_path = os.path.join(env.backup_d_dir, backup_def_name)
    with open(backup_def_path, "w") as f:
        f.write("fake contents")

    # Run installer (creates the catalogs)
    run_installer(env.config_file, create_db_flag=True)

    # Load the config settings
    config_settings = ConfigSettings(env.config_file)

    # Determine catalog dir based on config
    catalog_dir = expand_path(get_db_dir(config_settings))
    expected_catalog = os.path.join(catalog_dir, f"{backup_def_name}.db")

    assert os.path.exists(expected_catalog), f"Expected catalog not found: {expected_catalog}"

    # Assert all standard dirs exist
    expected_dirs = [
        env.backup_dir,
        env.backup_d_dir,
        env.restore_dir,
        env.data_dir,
        catalog_dir,
    ]
    for d in expected_dirs:
        assert os.path.isdir(d), f"Expected directory not found: {d}"
