from dar_backup.installer import install_autocompletion, uninstall_autocompletion
import pytest

pytestmark = pytest.mark.unit








@pytest.fixture(autouse=True)
def isolate_home(tmp_path, monkeypatch):
    """
    Redirect HOME and SHELL to a temporary directory and default shell.
    """
    # Create fake home and rc files
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    # Set HOME to fake_home
    monkeypatch.setenv("HOME", str(fake_home))
    # Default to bash shell
    monkeypatch.setenv("SHELL", "/bin/bash")
    return fake_home

def read_rc(home, filename):
    return (home / filename).read_text().splitlines()


def test_install_autocompletion_first_time(isolate_home, monkeypatch):
    home = isolate_home
    # Ensure no existing rc
    rc_file = home / ".bashrc"
    # Install
    install_autocompletion()
    # After install, rc should exist
    assert rc_file.exists()
    lines = read_rc(home, ".bashrc")
    # Marker present
    assert any("# >>> dar-backup autocompletion >>>" in l for l in lines)


def test_install_autocompletion_idempotent(isolate_home, monkeypatch):
    home = isolate_home
    rc_file = home / ".bashrc"
    # First install
    install_autocompletion()
    # Clear logger
    # Second install should not duplicate
    install_autocompletion()
    lines = read_rc(home, ".bashrc")
    # Only one marker
    assert sum(1 for l in lines if "# >>> dar-backup autocompletion >>>" in l) == 1


def test_uninstall_autocompletion_removes_block(isolate_home, monkeypatch):
    home = isolate_home
    rc_file = home / ".bashrc"
    # Prepare rc with block
    install_autocompletion()
    # Now uninstall
    uninstall_autocompletion()
    lines = read_rc(home, ".bashrc")
    # Marker should be absent
    assert not any("# >>> dar-backup autocompletion >>>" in l for l in lines)
