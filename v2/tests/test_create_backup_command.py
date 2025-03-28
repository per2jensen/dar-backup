import pytest
from dar_backup.dar_backup import create_backup_command
from dar_backup.config_settings import ConfigSettings
import os
import sys  
# Ensure the src directory is in the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

@pytest.mark.parametrize("backup_type, expect_reference", [
    ("FULL", False),
    ("DIFF", True),
    ("INCR", True),
])
def test_create_backup_command_minimal_structure(tmp_path, backup_type, expect_reference):
    dummy_config_path = tmp_path / "dar-backup.conf"
    dummy_config_path.write_text("""
[MISC]
LOGFILE_LOCATION = /tmp/fake.log
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 0
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 86400

[DIRECTORIES]
BACKUP_DIR = /tmp/backups/
BACKUP.D_DIR = /tmp/backup.d/
DATA_DIR = /tmp/data/
TEST_RESTORE_DIR = /tmp/restore/

[AGE]
DIFF_AGE = 30
INCR_AGE = 15

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True
""")
    _ = ConfigSettings(config_file=str(dummy_config_path))

    backup_file = "test-archive"
    darrc_path = str(tmp_path / ".darrc")
    backup_definition = str(tmp_path / "backup_def.dar")
    reference_backup = "ref-archive" if expect_reference else None

    command = create_backup_command(
        backup_type,
        backup_file,
        darrc_path,
        backup_definition,
        reference_backup
    )

    assert command[0] == "dar"
    assert "-c" in command
    assert backup_file in command
    assert "-B" in command
    assert darrc_path in command
    assert backup_definition in command

    if expect_reference:
        assert "-A" in command
        assert reference_backup in command
    else:
        assert "-A" not in command
