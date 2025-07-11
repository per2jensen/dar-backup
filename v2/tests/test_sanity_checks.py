# modified: 2021-07-25 to be a pytest test
import glob
import importlib
import os
import pytest
import re
import shutil
import subprocess
import sys
import tempfile
from time import time
from typing import Generator

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner
from dar_backup.dar_backup import find_files_with_paths
from dar_backup.util import setup_logging
from pathlib import Path
from tests.envdata import EnvData
from unittest.mock import patch


runner: CommandRunner = None

@pytest.fixture(autouse=True)
def setup_runner(env: EnvData):
    global runner
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)


@pytest.fixture
def modify_config_file_tilde(env: EnvData) -> Generator[dict, None, None]:
    unix_time = int(time())
    LOGFILE_LOCATION = f"~/.test_{unix_time}_dar-backup.log"
    env.logger.info(f"LOGFILE_LOCATION: {LOGFILE_LOCATION}")
    config_path = os.path.join(env.test_dir, env.config_file)
    env.logger.info(f"config file path: {config_path}")
    with open(config_path, 'r') as f:
        lines = f.readlines()
    with open(config_path, 'w') as f:
        for line in lines:
            if line.startswith('LOGFILE_LOCATION = '):
                f.write(f'LOGFILE_LOCATION = {LOGFILE_LOCATION}\n')
            else:
                f.write(line)
    yield {'LOGFILE_LOCATION': LOGFILE_LOCATION}
    if os.path.exists(os.path.expanduser(LOGFILE_LOCATION)):
        os.remove(os.path.expanduser(LOGFILE_LOCATION))
        env.logger.info(f"Removed: {LOGFILE_LOCATION}")


@pytest.fixture
def modify_config_file_env_vars(env: EnvData) -> Generator[dict, None, None]:
    BACKUP_DIR = tempfile.mkdtemp(dir="/tmp")
    LOG_DIR = tempfile.mkdtemp(dir="/tmp")
    config_path = os.path.join(env.test_dir, env.config_file)
    with open(config_path, 'r') as f:
        lines = f.readlines()
    with open(config_path, 'w') as f:
        for line in lines:
            if line.startswith('BACKUP_DIR = '):
                f.write('BACKUP_DIR = ${BACKUP_DIR}\n')
            elif line.startswith('LOGFILE_LOCATION = '):
                f.write('LOGFILE_LOCATION = ${LOG_DIR}/dar-backup.log\n')
            else:
                f.write(line)
    yield {'BACKUP_DIR': BACKUP_DIR, 'LOG_DIR': LOG_DIR}
    if os.path.exists(BACKUP_DIR):
        shutil.rmtree(BACKUP_DIR)
    if os.path.exists(LOG_DIR):
        shutil.rmtree(LOG_DIR)


def test_env_vars_in_config_file(
    setup_environment,
    env: EnvData,
    modify_config_file_env_vars: dict,
    setup_runner: CommandRunner
):
    os.environ["BACKUP_DIR"] = modify_config_file_env_vars["BACKUP_DIR"]
    os.environ["LOG_DIR"] = modify_config_file_env_vars["LOG_DIR"]

    process = runner.run(["manager", "--create-db", "--config-file", env.config_file])
    assert process.returncode == 0

    process = runner.run([
        "dar-backup", "--full-backup", "--config-file", env.config_file,
        "-d", "example", "--log-level", "debug", "--log-stdout"
    ])
    assert process.returncode == 0

    expected_backup = os.path.join(os.environ["BACKUP_DIR"], f'example_FULL_{env.datestamp}.1.dar')
    expected_log = os.path.join(os.environ["LOG_DIR"], "dar-backup.log")

    assert os.path.exists(expected_backup)
    assert os.path.exists(expected_log)


@pytest.mark.skip(reason="`dar` does not expand env vars in it's config files, test kept for documentation")
def _test_env_vars_in_backup_definition(setup_environment, env: EnvData):
    """
    WILL NOT WORK AS EXPECTED, because the dar-backup command does not
    expand environment variables in the backup definition file.
    The backup definition file is read as a literal string by `dar`.

    dar-backup must preprocess the backup definition file for it to 
    contain environment variables and feed the processed content to `dar`.
    
    Test that environment variables in the backup definition file are correctly expanded by dar-backup.
    """
    # Set environment variables
    os.environ["TEST_ROOT"] = "/"
    os.environ["TEST_DATA_DIR"] = env.data_dir

    # Create the backup definition content
    # Use shell-style environment variable references ($VAR or ${VAR})
    backup_definition = f"""
-R "$TEST_ROOT"
-s 10G
-z6
-am
--cache-directory-tagging
-g "$TEST_DATA_DIR"
""".replace("-g /tmp/", "-g tmp/")  # because dar does not allow first "/"

    # Write the backup definition file
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    with open(backup_def_path, "w") as f:
        f.write(backup_definition)

    # Run the backup using the definition name and -d argument
    process = runner.run([
        "dar-backup",
        "--full-backup",
        "-d", "example",
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout"
    ])

    assert process.returncode == 0, f"Backup command failed:\n{process.stderr}\n{process.stdout}"

    # Validate the expected backup file exists
    expected_backup = os.path.join(env.backup_dir, f"example_FULL_{env.datestamp}.1.dar")

    assert os.path.exists(expected_backup)

    # the test must restore the backup and verify the files in env.data_dir are restored correctly
    # to f"{env.restore_dir}/{env.data_dir}"
    

def test_tilde_in_config_file(
    setup_environment,
    env: EnvData,
    modify_config_file_tilde: dict,
    setup_runner: CommandRunner
):
    env.logger.info(f"LOGFILE_LOCATION: {modify_config_file_tilde['LOGFILE_LOCATION']}")
    logfile = os.path.expanduser(modify_config_file_tilde["LOGFILE_LOCATION"])

    process = runner.run([
        "dar-backup", "--full-backup", "--config-file", env.config_file,
        "-d", "example", "--log-level", "debug", "--log-stdout"
    ])
    assert process.returncode == 0

    assert os.path.exists(logfile)
    assert os.path.getsize(logfile) > 0

    with open(logfile, "r") as f:
        for line in f:
            env.logger.info(line.strip())



def test_clean_log_missing_logfile_location_key(setup_environment, env: EnvData):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    # Manually create a dummy log file (since sample_log_file fixture isn't available here)
    log_file = os.path.join(env.test_dir, "test.log")
    with open(log_file, "w") as f:
        f.write("INFO - <Directory>\nERROR - Something bad happened\n")

    # Now patch the config to remove the logfile location key
    config_path = env.config_file
    with open(config_path, "r") as f:
        lines = f.readlines()

    with open(config_path, "w") as f:
        for line in lines:
            if not line.strip().startswith("LOGFILE_LOCATION"):
                f.write(line)

    command = ["clean-log", "-c", config_path]
    process = runner.run(command)

    assert process.returncode != 0

    error_output = process.stderr + process.stdout
    assert "Missing mandatory configuration key" in error_output




def test_clean_log_invalid_backup_dir_path(setup_environment, env: EnvData, sample_log_file):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    broken_config = os.path.join(env.test_dir, "invalid_backup_dir.conf")

    with open(broken_config, "w") as f:
        f.write("[MISC]\n")
        f.write(f"LOGFILE_LOCATION = {sample_log_file}\n")
        f.write("MAX_SIZE_VERIFICATION_MB = 20\n")
        f.write("MIN_SIZE_VERIFICATION_MB = 0\n")
        f.write("NO_FILES_VERIFICATION = 5\n")
        f.write("COMMAND_TIMEOUT_SECS = 30\n")

        f.write("[DIRECTORIES]\n")

        f.write("BACKUP_DIR = /tmp/fake/path/backup/\n")
        f.write("BACKUP.D_DIR = /tmp/fake/path/backup.d/\n")
        f.write("DATA_DIR = /tmp/fake/path/data/\n")
        f.write("TEST_RESTORE_DIR = /tmp/fake/path/restore/\n")

        
        f.write("[AGE]\n")
        f.write("DIFF_AGE = 30\n")
        f.write("INCR_AGE = 15\n")
        f.write("[PAR2]\n")
        f.write("ERROR_CORRECTION_PERCENT = 5\n")
        f.write("ENABLED = True\n")

    command = ["clean-log", "-f", sample_log_file, "-c", broken_config]
    process = runner.run(command)

    assert process.returncode == 0  # It should still clean the file, BACKUP_DIR is unused in clean-log
    with open(sample_log_file) as f:
        content = f.read()
    assert "Inspecting directory" not in content



def test_clean_log_missing_directories_section(setup_environment, env: EnvData, sample_log_file):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    broken_config = os.path.join(env.test_dir, "missing_directories_section.conf")

    with open(broken_config, "w") as f:
        f.write("[MISC]\nLOGFILE_LOCATION = {}\n".format(sample_log_file))

    command = ["clean-log", "-f", sample_log_file, "-c", broken_config]
    process = runner.run(command)

    assert process.returncode != 0
    error_output = process.stderr + process.stdout
    assert "Missing mandatory configuration key" in error_output or "DIRECTORIES" in error_output



def test_config_parsing_missing_misc_section(setup_environment, env: EnvData):
    """
    Ensure the tool fails gracefully when the [MISC] section is missing from the config file.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    # Write broken config (missing [MISC]) to env.config_file
    broken_config = """\
[DIRECTORIES]
BACKUP_DIR = /tmp/fake/backup
BACKUP.D_DIR = /tmp/fake/backup.d
TEST_RESTORE_DIR = /tmp/fake/restore

[AGE]
DIFF_AGE = 30
INCR_AGE = 15

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True
"""
    with open(env.config_file, "w") as f:
        f.write(broken_config)
    env.logger.debug("Written broken config without [MISC] to %s", env.config_file)

    # Write a dummy log file to clean
    log_file = os.path.join(env.test_dir, "test.log")
    with open(log_file, "w") as f:
        f.write("INFO - Dummy log line\n")

    # Run the tool with the bad config
    command = ["clean-log", "-f", log_file, "-c", env.config_file]
    process = runner.run(command)

    assert process.returncode != 0, "Command should fail due to missing [MISC] section"

    error_output = process.stderr + process.stdout
    assert "Missing mandatory configuration key" in error_output or "[MISC]" in error_output, (
        f"Expected error about missing [MISC] section. Output was:\n{error_output}"
    )



def test_dar_backup_definition_with_underscore(setup_environment, env):
    process = runner.run(['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example_2'])
    assert process.returncode != 0

def test_dar_backup_nonexistent_definition_(setup_environment, env):
    process = runner.run(['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'nonexistent_definition'])
    assert process.returncode == 127

def test_dar_backup_nonexistent_config_file(setup_environment, env):
    process = runner.run(['dar-backup', '--full-backup', '--config-file', 'non-existent-config-file', '-d', 'example'])
    assert process.returncode == 127

def setup_cache_directory(env):
    cache_dir = os.path.join(env.data_dir, "cache-dir")
    os.makedirs(cache_dir, exist_ok=True)
    for i in range(1, 4):
        with open(os.path.join(cache_dir, f"test_file_{i}.txt"), "w") as f:
            f.write(f"This is test file {i}.\n")
    with open(os.path.join(cache_dir, "CACHEDIR.TAG"), "w", encoding='utf-8') as f:
        f.write("Signature: 8a477f597d28d172789f06886806bc55")

def test_skip_cache_directories(setup_environment, env):
    setup_cache_directory(env)
    runner.run(['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example', '--verbose', '--log-stdout'])
    process = runner.run(['dar-backup', '--config-file', env.config_file, '--list-contents', f'example_FULL_{env.datestamp}'])
    assert "cache-dir/CACHEDIR.TAG" not in process.stdout
    assert "cache-dir/test_file_1.txt" not in process.stdout

def test_validate_xml_parser(setup_environment, env):
    xml_doc = """<?xml version="1.0" ?>
<!DOCTYPE Catalog SYSTEM "dar-catalog.dtd">
<Catalog format="1.2">
<Directory name=".local">
<Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwx------" atime="1739280438" mtime="1715508282" ctime="1721767430" />
        <Directory name="share">
        <Attributes data="saved" metadata="absent" user="pj" group="pj" permissions=" drwx------" atime="1738346589" mtime="1739283519" ctime="1739283519" />
                <Directory name="vlc">
                <Attributes data="saved" metadata="absent" user="pj" group="pj" permissions=" drwx------" atime="1738346589" mtime="1739283601" ctime="1739283601" />
                        <File name="ml.xspf" size="297 o" stored="178 o" crc="207a1300" dirty="no" sparse="no" delta_sig="no" patch_base_crc="" patch_result_crc="">
                        <Attributes data="saved" metadata="absent" user="pj" group="pj" permissions=" -rw-rw-r--" atime="1739283601" mtime="1739283601" ctime="1739283601" />
                        </File>
                </Directory>
                <Directory name="gegl-0.4">
                <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwx------" atime="1738346589" mtime="1715621892" ctime="1715621892" />
                        <Directory name="plug-ins">
                        <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwx------" atime="1739128963" mtime="1715621892" ctime="1715621892" />
                        </Directory>
                </Directory>
                <Directory name="vulkan">
                <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxrwxr-x" atime="1738346589" mtime="1715717830" ctime="1715717830" />
                        <Directory name="implicit_layer.d">
                        <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxrwxr-x" atime="1739130249" mtime="1715717830" ctime="1715717830" />
                                <File name="steamoverlay_i386.json" size="457 o" stored="" crc="" dirty="no" sparse="yes" delta_sig="no" patch_base_crc="" patch_result_crc="">
                                <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" -rwxrwxr-x" atime="1739130249" mtime="1736456318" ctime="1736456318" />
                                </File>
                                <File name="steamoverlay_x86_64.json" size="457 o" stored="" crc="" dirty="no" sparse="yes" delta_sig="no" patch_base_crc="" patch_result_crc="">
                                <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" -rwxrwxr-x" atime="1739130249" mtime="1736456318" ctime="1736456318" />
                                </File>
                                <File name="steamfossilize_i386.json" size="632 o" stored="" crc="" dirty="no" sparse="yes" delta_sig="no" patch_base_crc="" patch_result_crc="">
                                <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" -rwxrwxr-x" atime="1739130249" mtime="1736456318" ctime="1736456318" />
                                </File>
                                <File name="steamfossilize_x86_64.json" size="632 o" stored="" crc="" dirty="no" sparse="yes" delta_sig="no" patch_base_crc="" patch_result_crc="">
                                <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" -rwxrwxr-x" atime="1739130249" mtime="1736456318" ctime="1736456318" />
                                </File>
                        </Directory>
                </Directory>
                <Directory name="systemd">
                <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxr-xr-x" atime="1738346589" mtime="1715793442" ctime="1715793442" />
                        <Directory name="timers">
                        <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxr-xr-x" atime="1738346589" mtime="1723114240" ctime="1723114240" />
                                <File name="stamp-dar-diff-backup.timer" size="0" stored="0" crc="00" dirty="no" sparse="no" delta_sig="no" patch_base_crc="" patch_result_crc="">
                                <Attributes data="saved" metadata="absent" user="pj" group="pj" permissions=" -rw-r--r--" atime="1738432997" mtime="1738432997" ctime="1738432997" />
                                </File>
                                <File name="stamp-dar-inc-backup.timer" size="0" stored="0" crc="00" dirty="no" sparse="no" delta_sig="no" patch_base_crc="" patch_result_crc="">
                                <Attributes data="saved" metadata="absent" user="pj" group="pj" permissions=" -rw-r--r--" atime="1739210592" mtime="1739210592" ctime="1739210592" />
                                </File>
                        </Directory>
                </Directory>
                <Directory name="remmina">
                <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxr-x---" atime="1738346589" mtime="1716212561" ctime="1716212561" />
                </Directory>
                <Directory name="lensfun">
                <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxrwxr-x" atime="1739116520" mtime="1719036714" ctime="1719036714" />
                        <Directory name="updates">
                        <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxrwxr-x" atime="1738346589" mtime="1734813717" ctime="1734813717" />
                                <Directory name="version_1">
                                <Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxrwxr-x" atime="1739116520" mtime="1734813718" ctime="1734813718" />
                                        <File name="mil-sony.xml" size="265 kio" stored="" crc="" dirty="no" sparse="yes" delta_sig="no" patch_base_crc="" patch_result_crc="">
                                        <Attributes data="saved" metadata="absent" user="pj" group="pj" permissions=" -rw-r--r--" atime="1739210592" mtime="1739210592" ctime="1739210592" />
                                        </File>
                                </Directory>
                        </Directory>
                </Directory>
        </Directory>
</Directory>
</Catalog>
"""

    paths = find_files_with_paths(xml_doc)
    expected_paths = {
        ".local/share/vlc/ml.xspf": True,
        ".local/share/vulkan/implicit_layer.d/steamoverlay_i386.json": True,
        ".local/share/vulkan/implicit_layer.d/steamoverlay_x86_64.json": True,
        ".local/share/vulkan/implicit_layer.d/steamfossilize_i386.json": True,
        ".local/share/vulkan/implicit_layer.d/steamfossilize_x86_64.json": True,
        ".local/share/systemd/timers/stamp-dar-diff-backup.timer": True,
        ".local/share/systemd/timers/stamp-dar-inc-backup.timer": True,
        ".local/share/lensfun/updates/version_1/mil-sony.xml": True
    }
    for path, size in paths:
        assert path in expected_paths
    assert len(paths) == len(expected_paths)

def test_duplicate_full_backup_fails(setup_environment, env: EnvData):
    first = runner.run(["dar-backup", "--full-backup", "-d", "example", "--config-file", env.config_file, "--log-level", "debug", "--log-stdout"])
    assert first.returncode == 0
    second = runner.run(["dar-backup", "--full-backup", "-d", "example", "--config-file", env.config_file, "--log-level", "debug", "--log-stdout"])
    assert second.returncode != 0
    assert "already exists" in second.stderr or "already exists" in second.stdout



# Map script names to relative paths
SCRIPTS = {
    "dar_backup.py": "src/dar_backup/dar_backup.py",
    "manager.py": "src/dar_backup/manager.py",
    "cleanup.py": "src/dar_backup/cleanup.py",
}

@pytest.mark.parametrize("script_name, script_path", SCRIPTS.items())
def test_script_shows_version(script_name, script_path):
    full_path = os.path.abspath(script_path)

    result = subprocess.run(
        [sys.executable, "-m", f"dar_backup.{script_name.replace('.py', '')}", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
    )

    print(f"\n=== {script_name} ===")
    print(f"Return code: {result.returncode}")
    print(f"STDOUT:\n{result.stdout}")
    print(f"STDERR:\n{result.stderr}")

    output = result.stdout.strip()
    assert f"{script_name} source code is here: https://github.com/per2jensen/dar-backup" in output

    assert "Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file \"LICENSE\" for details." in output
    assert "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE." in output
    assert "See section 15 and section 16 in the supplied \"LICENSE\" file." in output



import io
import sys
import pytest
from dar_backup.util import print_aligned_settings
from tests.envdata import EnvData

@pytest.fixture(autouse=True)
def setup_env(env: EnvData):
    """Auto-use the env fixture to prepare environment."""
    pass

import io
import sys
import pytest
from dar_backup.util import print_aligned_settings
from tests.envdata import EnvData

def test_print_aligned_settings_trimming_and_logging(env: EnvData, caplog):
    """Test that labels and texts are trimmed correctly, printed, and logged, with dangerous highlighting."""

    settings = [
        ("short", "a simple short value"),
        ("this_is_a_very_long_label_that_will_need_trimming_because_it_is_too_big", "short"),
        ("normal_label", "this is a very long text that should be trimmed to not exceed 80 characters in total line length"),
        ("delete_operation", "delete full backup now"),  # <-- Danger keyword test
    ]

    highlight_keywords = ["delete", "danger", "full backup"]

    captured_output = io.StringIO()
    sys.stdout = captured_output

    try:
        with caplog.at_level(env.logger.level):
            print_aligned_settings(settings, log=True, quiet=False, highlight_keywords=highlight_keywords)
    finally:
        sys.stdout = sys.__stdout__

    # Capture printed output (optional verification)
    output_lines = captured_output.getvalue().strip().split("\n")

    # ===== Log Verification (PRIMARY) =====
    log_lines = [record.message for record in caplog.records]

    # First log is header, last log is footer, settings are between
    assert log_lines[0].startswith("=========="), "First log line should be header"
    assert log_lines[-1].startswith("="), "Last log line should be footer"

    # Extract the setting lines only
    setting_log_lines = log_lines[1:-1]

    assert len(setting_log_lines) == len(settings), f"Expected {len(settings)} logged settings, got {len(setting_log_lines)}"

    # Each setting must match the order
    for (label, text), log_line in zip(settings, setting_log_lines):
        clean_label = str(label)
        clean_text = str(text)
        assert clean_label in log_line, f"Label '{clean_label}' missing in log '{log_line}'"
        assert clean_text in log_line, f"Text '{clean_text}' missing in log '{log_line}'"

    # ===== Dangerous Line Check =====
    # Look for the dangerous keyword manually
    dangerous_found = False
    for log_line in setting_log_lines:
        if "delete full backup" in log_line.lower():
            dangerous_found = True
    assert dangerous_found, "Dangerous setting line not found in logs"

    # ===== Printed Output (Secondary Check) =====
    # Cannot assert strict line counts because rich wraps, but can still sanity check
    assert "Startup Settings" in captured_output.getvalue(), "Header not printed"
    assert "delete full backup" in captured_output.getvalue(), "Dangerous text not printed"




# Custom RotatingFileHandler that announces rotation
import logging
from logging.handlers import RotatingFileHandler

class AnnounceRotatingFileHandler(RotatingFileHandler):
    def doRollover(self):
        print(f"[TEST] Rotating log: {self.baseFilename}")
        super().doRollover()

@pytest.mark.usefixtures("env")
def test_logfile_rotation_and_content_integrity(setup_environment, env: 'EnvData'):
    log_dir = Path(env.test_dir)
    log_path = log_dir / "dar-backup.log"
    cmd_log_path = log_dir / "dar-backup-commands.log"
    max_bytes = 50 * 1024  # 50 KB
    backup_count = 5
    total_lines = 3000

    # Patch the handler only inside the test
    with patch("dar_backup.util.RotatingFileHandler", AnnounceRotatingFileHandler):
        logger = setup_logging(
            str(log_path),
            str(cmd_log_path),
            log_level="debug",
            log_to_stdout=False,
            logfile_max_bytes=max_bytes,
            logfile_backup_count=backup_count,
        )

        # Use the global loggers as set by util.py
        from dar_backup.util import logger as main_logger, secondary_logger

        # Write lots of lines to both loggers, uniquely numbered
        msg = "0123456789" * 20  # About 200 bytes per line
        for i in range(total_lines):
            main_logger.debug(f"mainlog {i} - {msg}")
            secondary_logger.debug(f"cmdlog {i} - {msg}")

        # Ensure all log output is flushed
        for handler in main_logger.handlers:
            handler.close()
        for handler in secondary_logger.handlers:
            handler.close()

    # Helper to get log lines in rotation order (oldest first)
    def get_log_lines_in_rotation_order(prefix):
        files = []
        # .5 (oldest) to .1, then base file
        for i in range(backup_count, 0, -1):
            f = log_dir / f"{prefix}.{i}"
            if f.exists():
                files.append(f)
        base = log_dir / prefix
        if base.exists():
            files.append(base)
        lines = []
        for f in files:
            with f.open(encoding="utf-8") as logf:
                lines.extend(logf.readlines())
        return lines

    # Get all lines written across all rotated log files
    main_lines = get_log_lines_in_rotation_order("dar-backup.log")
    cmd_lines = get_log_lines_in_rotation_order("dar-backup-commands.log")

    main_lines = [line.split(" - ", 2)[-1] for line in main_lines]
    cmd_lines  = [line.split(" - ", 2)[-1] for line in cmd_lines]

    # Compose the expected lines
    expected_main_lines = [f"mainlog {i} - {msg}\n" for i in range(total_lines)]
    expected_cmd_lines  = [f"cmdlog {i} - {msg}\n" for i in range(total_lines)]

    # The logs may be truncated at the beginning if too much was written (oldest lines fall off)
    # So we check that the *end* of the expected lines matches the actual lines present
    assert main_lines[-len(main_lines):] == expected_main_lines[-len(main_lines):], "Main log lines corrupted or out of order after rotation"
    assert cmd_lines[-len(cmd_lines):] == expected_cmd_lines[-len(cmd_lines):], "Command log lines corrupted or out of order after rotation"

    # Print for visual confirmation (non-invasive, only for test run)
    print(f"[TEST] Main log files found: {[str(f) for f in log_dir.glob('dar-backup.log*')]}")
    print(f"[TEST] Command log files found: {[str(f) for f in log_dir.glob('dar-backup-commands.log*')]}")

    # Check log file count (current + backups)
    assert len(list(log_dir.glob("dar-backup.log*"))) == backup_count + 1
    assert len(list(log_dir.glob("dar-backup-commands.log*"))) == backup_count + 1

    # Optional: check file sizes do not exceed max_bytes
    for f in log_dir.glob("dar-backup.log*"):
        assert f.stat().st_size <= max_bytes
    for f in log_dir.glob("dar-backup-commands.log*"):
        assert f.stat().st_size <= max_bytes
