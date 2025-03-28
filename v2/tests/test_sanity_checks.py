# modified: 2021-07-25 to be a pytest test
import importlib
import os
import pytest
import re
import shutil
import sys
import tempfile
from time import time
from typing import Generator

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner
from dar_backup.dar_backup import find_files_with_paths
from tests.envdata import EnvData

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

def test_env_vars_in_config_file(setup_environment, env: EnvData, modify_config_file_env_vars: dict):
    os.environ['BACKUP_DIR'] = modify_config_file_env_vars['BACKUP_DIR']
    os.environ['LOG_DIR'] = modify_config_file_env_vars['LOG_DIR']
    process = runner.run(['manager', '--create-db', '--config-file', env.config_file])
    assert process.returncode == 0
    process = runner.run(['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example', '--log-level', 'debug', '--log-stdout'])
    assert process.returncode == 0
    assert os.path.exists(os.path.join(os.environ['BACKUP_DIR'], f'example_FULL_{env.datestamp}.1.dar'))
    assert os.path.exists(os.path.join(os.environ['LOG_DIR'], 'dar-backup.log'))

def test_tilde_in_config_file(setup_environment, env: EnvData, modify_config_file_tilde: dict):
    logfile = os.path.expanduser(modify_config_file_tilde['LOGFILE_LOCATION'])
    process = runner.run(['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example', '--log-level', 'debug', '--log-stdout'])
    assert process.returncode == 0
    assert os.path.exists(logfile)
    assert os.path.getsize(logfile) > 0
    with open(logfile, 'r') as f:
        for line in f:
            env.logger.info(line.strip())

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
