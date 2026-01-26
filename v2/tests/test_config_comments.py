from dar_backup.config_settings import ConfigSettings

def test_config_inline_comments(tmp_path):
    """
    Verify that inline comments are handled correctly by ConfigSettings.
    """
    config_file = tmp_path / "dar-backup.conf"
    config_content = """
[MISC]
LOGFILE_LOCATION = /tmp/dar-backup.log # This is a comment
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 1
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 86400
TRACE_LOG_MAX_BYTES = 10485760 # 10 MB
TRACE_LOG_BACKUP_COUNT = 1 # 1 file

[DIRECTORIES]
BACKUP_DIR = /tmp/backups
BACKUP.D_DIR = /tmp/backup.d
TEST_RESTORE_DIR = /tmp/restore

[AGE]
DIFF_AGE = 100
INCR_AGE = 40

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True
"""
    config_file.write_text(config_content)

    config = ConfigSettings(str(config_file))

    assert config.logfile_location == "/tmp/dar-backup.log"
    assert config.trace_log_max_bytes == 10485760
    assert config.trace_log_backup_count == 1
