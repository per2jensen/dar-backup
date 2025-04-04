import sys
import pytest
from unittest.mock import patch, MagicMock
from tests.envdata import EnvData
from dar_backup.installer import main
from dar_backup.installer import CONFIG_DIR, DAR_BACKUP_DIR

@pytest.fixture
def mock_envdata():
    logger = MagicMock()
    command_logger = MagicMock()
    return EnvData(test_case_name="InstallerTest", logger=logger, command_logger=command_logger)


@pytest.mark.parametrize("arg", ["--help", "-h"])
def test_installer_help_shows_usage(arg):
    from dar_backup import installer

    test_args = ["installer.py", arg]
    with patch.object(sys, "argv", test_args), patch("sys.stdout"):
        with pytest.raises(SystemExit) as exc:
            installer.main()
        assert exc.value.code == 0




@patch("dar_backup.installer.sys.exit", side_effect=SystemExit(1))
@patch("dar_backup.installer.shutil.copy2")
@patch("dar_backup.installer.os.makedirs")
@patch("dar_backup.installer.os.path.exists", return_value=True)  # simulate existing dirs
@patch("dar_backup.installer.Path.exists", return_value=False)
def test_installer_main_logic(mock_path_exists, mock_os_exists, mock_makedirs, mock_copy2, mock_exit, mock_envdata):
    from dar_backup import installer

    test_args = ["installer.py", "--install"]
    with patch.object(sys, "argv", test_args):
        with pytest.raises(SystemExit) as exc:
            installer.main()
        assert exc.value.code == 1



def test_installer_creates_missing_destination_dir(monkeypatch):
    monkeypatch.setattr("sys.argv", ["installer"])
    monkeypatch.setattr("sys.exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))
    monkeypatch.setattr("os.path.exists", lambda path: False)
    monkeypatch.setattr("pathlib.Path.exists", lambda self: True)
    monkeypatch.setattr("os.makedirs", lambda path, exist_ok=True: None)
    monkeypatch.setattr("shutil.copy2", lambda src, dst: None)

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0



def test_installer_invalid_argument(monkeypatch):
    monkeypatch.setattr("sys.argv", ["installer", "--invalid"])
    monkeypatch.setattr("sys.exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2



def test_installer_copy_failure(monkeypatch):
    monkeypatch.setattr("sys.argv", ["installer", "--install"])
    monkeypatch.setattr("os.path.exists", lambda path: False)  # Make install paths look empty
    monkeypatch.setattr("pathlib.Path.exists", lambda self: True)
    monkeypatch.setattr("os.makedirs", lambda path, exist_ok=True: None)
    monkeypatch.setattr("shutil.copy2", lambda src, dst: (_ for _ in ()).throw(OSError("copy failed")))
    monkeypatch.setattr("sys.exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1

def test_installer_default_config_copy(monkeypatch):
    monkeypatch.setattr("sys.argv", ["installer", "--install"])
    monkeypatch.setattr("os.path.exists", lambda path: False)  # Make install paths look empty
    monkeypatch.setattr("pathlib.Path.exists", lambda self: True)
    monkeypatch.setattr("os.makedirs", lambda path, exist_ok=True: None)

    copied = {}

    def fake_copy2(src, dst):
        copied["src"] = str(src)
        copied["dst"] = str(dst)

    monkeypatch.setattr("shutil.copy2", fake_copy2)
    monkeypatch.setattr("sys.exit", lambda code=0: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit):
        main()

    assert "src" in copied and "dst" in copied

