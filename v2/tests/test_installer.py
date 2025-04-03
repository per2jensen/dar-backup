import sys
import pytest
from unittest.mock import patch, MagicMock
from tests.envdata import EnvData

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


