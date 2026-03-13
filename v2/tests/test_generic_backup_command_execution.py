from unittest.mock import patch, MagicMock
from dar_backup.dar_backup import generic_backup
from dar_backup.config_settings import ConfigSettings
from tests.envdata import EnvData
import pytest

pytestmark = pytest.mark.component


# ---------------------------------------------------------------------------
# Sample dar inode summary used across dar-stats tests.
# Mirrors the output that `dar` writes to stdout or stderr depending on version.
# ---------------------------------------------------------------------------
_DAR_SUMMARY = """\
 42 inode(s) saved
   including 1 hard link(s) treated
 0 inode(s) changed at the moment of the backup and could not be saved properly
 0 byte(s) have been wasted in the archive to resave changing files
 0 inode(s) with only metadata changed
 10 inode(s) not saved (no inode/file change)
 0 inode(s) failed to be saved (filesystem error)
 2 inode(s) ignored (excluded by filters)
 0 inode(s) recorded as deleted from reference backup
 --------------------------------------------
 Total number of inode(s) considered: 55
 --------------------------------------------
 EA saved for 0 inode(s)
 FSA saved for 0 inode(s)
"""








@pytest.fixture
def mock_envdata(tmp_path):
    logger = MagicMock()
    command_logger = MagicMock()
    return EnvData(test_case_name="GenericBackupTest", logger=logger, command_logger=command_logger, base_dir=tmp_path)

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
    assert isinstance(result.issues, list)
    assert result.dar_exit_code == 0
    assert result.catalog_updated is True
    assert mock_runner.run.call_count == 2
    mock_logger.info.assert_called()


# ---------------------------------------------------------------------------
# dar stats: stdout vs stderr capture
# ---------------------------------------------------------------------------

@patch("dar_backup.dar_backup.get_logger", return_value=MagicMock())
@patch("dar_backup.util.shutil.which", return_value=True)
@patch("dar_backup.util.subprocess.Popen")
@patch("dar_backup.dar_backup.logger", new_callable=MagicMock)
@patch("dar_backup.dar_backup.os.path.exists")
@patch("dar_backup.dar_backup.runner")
def test_generic_backup_dar_stats_captured_from_stderr(
    mock_runner,
    mock_exists,
    mock_logger,
    mock_popen,
    mock_which,
    mock_get_logger,
    mock_envdata,
    mock_config,
):
    """
    When dar writes its inode summary to stderr only (stdout is empty), the
    combined-stream parse must still populate dar_stats correctly.

    This is the critical regression guard for the stdout+stderr fix:
      dar_stats = parse_dar_stats((process.stdout or "") + (process.stderr or ""))
    """
    mock_exists.return_value = False
    mock_runner.run.side_effect = [
        # dar run: summary in stderr, nothing in stdout
        MagicMock(returncode=0, stdout="", stderr=_DAR_SUMMARY),
        # catalog update
        MagicMock(returncode=0, stdout="catalog added", stderr=""),
    ]

    args = MagicMock()
    args.config_file = "/mock/dar-backup.conf"
    command = ["dar", "-c", "backup_test", "-R", "/mock/data", "-B", "/mock/.darrc"]

    result = generic_backup("FULL", command, "backup_test", "/mock/data", "/mock/.darrc", mock_config, args)

    assert result.dar_stats["inodes_saved"] == 42, (
        "inodes_saved must be parsed from stderr when stdout is empty"
    )
    assert result.dar_stats["inodes_not_saved"] == 10
    assert result.dar_stats["inodes_total"] == 55
    assert result.dar_stats["hard_links_treated"] == 1


@patch("dar_backup.dar_backup.get_logger", return_value=MagicMock())
@patch("dar_backup.util.shutil.which", return_value=True)
@patch("dar_backup.util.subprocess.Popen")
@patch("dar_backup.dar_backup.logger", new_callable=MagicMock)
@patch("dar_backup.dar_backup.os.path.exists")
@patch("dar_backup.dar_backup.runner")
def test_generic_backup_dar_stats_captured_from_stdout(
    mock_runner,
    mock_exists,
    mock_logger,
    mock_popen,
    mock_which,
    mock_get_logger,
    mock_envdata,
    mock_config,
):
    """
    When dar writes its inode summary to stdout (the common case), dar_stats
    must be populated correctly.
    """
    mock_exists.return_value = False
    mock_runner.run.side_effect = [
        MagicMock(returncode=0, stdout=_DAR_SUMMARY, stderr=""),
        MagicMock(returncode=0, stdout="catalog added", stderr=""),
    ]

    args = MagicMock()
    args.config_file = "/mock/dar-backup.conf"
    command = ["dar", "-c", "backup_test", "-R", "/mock/data", "-B", "/mock/.darrc"]

    result = generic_backup("FULL", command, "backup_test", "/mock/data", "/mock/.darrc", mock_config, args)

    assert result.dar_stats["inodes_saved"] == 42
    assert result.dar_stats["inodes_total"] == 55


@patch("dar_backup.dar_backup.get_logger", return_value=MagicMock())
@patch("dar_backup.util.shutil.which", return_value=True)
@patch("dar_backup.util.subprocess.Popen")
@patch("dar_backup.dar_backup.logger", new_callable=MagicMock)
@patch("dar_backup.dar_backup.os.path.exists")
@patch("dar_backup.dar_backup.runner")
def test_generic_backup_dar_stats_all_none_when_no_output(
    mock_runner,
    mock_exists,
    mock_logger,
    mock_popen,
    mock_which,
    mock_get_logger,
    mock_envdata,
    mock_config,
):
    """
    When dar produces no output on either stream, all dar_stats values must
    be None — never KeyError, never crash.
    """
    mock_exists.return_value = False
    mock_runner.run.side_effect = [
        MagicMock(returncode=0, stdout="", stderr=""),
        MagicMock(returncode=0, stdout="catalog added", stderr=""),
    ]

    args = MagicMock()
    args.config_file = "/mock/dar-backup.conf"
    command = ["dar", "-c", "backup_test", "-R", "/mock/data", "-B", "/mock/.darrc"]

    result = generic_backup("FULL", command, "backup_test", "/mock/data", "/mock/.darrc", mock_config, args)

    assert result.dar_stats, "dar_stats dict must not be empty even with no output"
    assert all(v is None for v in result.dar_stats.values()), (
        "Every dar_stats value must be None when dar produced no parseable output"
    )
