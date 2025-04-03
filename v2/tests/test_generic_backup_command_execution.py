import pytest
import subprocess
import io
from unittest.mock import patch, MagicMock, Mock
from dar_backup.dar_backup import generic_backup
from dar_backup.config_settings import ConfigSettings
from tests.envdata import EnvData

@pytest.fixture
def mock_envdata():
    logger = MagicMock()
    command_logger = MagicMock()
    return EnvData(test_case_name="GenericBackupTest", logger=logger, command_logger=command_logger)

@pytest.fixture
def mock_config():
    config = MagicMock(spec=ConfigSettings)
    config.backup_root_dir = "/mock/backups"
    config.command_timeout_secs = 60
    config.logfile_location = "/mock/logs/backup.log"
    return config

#@patch("dar_backup.util.get_logger", return_value=MagicMock())
@patch("dar_backup.dar_backup.get_logger", return_value=MagicMock())
@patch("dar_backup.util", return_value=MagicMock())
@patch("dar_backup.util.shutil.which", return_value=True)
@patch("dar_backup.util.subprocess.Popen")
@patch("dar_backup.dar_backup.logger", new_callable=MagicMock)
@patch("dar_backup.dar_backup.os.path.exists")
@patch("dar_backup.dar_backup.runner")
def test_generic_backup_success(
    mock_runner,
    mock_exists,
    mock_logger,
    mock_popen,
    mock_which,
    mock_get_logger,
    mock_envdata,
    mock_config,
):
    # Arrange
    mock_exists.return_value = False

    # Setup mocked runner behavior
    mock_runner.run.side_effect = [
        # First call simulates successful `dar` run
        MagicMock(returncode=0, stdout="stdout", stderr=""),
        # Second call simulates successful catalog update
        MagicMock(returncode=0, stdout="catalog added", stderr="")
    ]

    args = MagicMock()
    args.config_file = "/mock/dar-backup.conf"

    backup_file = "backup_test"
    backup_definition = "/mock/data"
    darrc = "/mock/.darrc"
    backup_type = "FULL"
    command = ["dar", "-c", backup_file, "-R", backup_definition, "-B", darrc]

    # Act
    result = generic_backup(backup_type, command, backup_file, backup_definition, darrc, mock_config, args)

    # Assert
    assert isinstance(result, list)
    assert mock_runner.run.call_count == 2
    mock_logger.info.assert_called()
