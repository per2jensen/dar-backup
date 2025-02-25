# modified: 2021-07-25 to be a pytest test
import importlib
import os
import re
import sys
import tempfile

from tests.envdata import EnvData
from time import time
from dar_backup.util import run_command
from dar_backup.dar_backup import find_files_with_paths


def modify_config_file_tilde(env: EnvData) -> dict:
    """
    Modify the LOG_DIR in the config file to include "~"

    Args:
        env (EnvData): The environment data object.
    
    Returns:
        dict: { "LOGFILE_LOCATION" : "<path to log file>" }
    
    Raises:
        RuntimeError: If the command fails.
    """

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

    env.logger.info("Patched config file:")
    with open(config_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            env.logger.info(line)

    return { 'LOGFILE_LOCATION': LOGFILE_LOCATION }   




def modify_config_file_env_vars(env: EnvData) -> dict:
    """
    Modify the BACKUP_DIR and LOG_DIR in the config file to include environtment variables

    Args:
        env (EnvData): The environment data object.
    
    Returns:
        dict: with the keys BACKUP_DIR and LOG_DIR
    
    Raises:
        RuntimeError: If the command fails.
    """

    BACKUP_DIR = tempfile.mkdtemp(dir="/tmp")
    env.logger.info(f"BACKUP_DIR: {BACKUP_DIR}")

    LOG_DIR    = tempfile.mkdtemp(dir="/tmp")  
    env.logger.info(f"LOG_DIR: {LOG_DIR}")

    config_path = os.path.join(env.test_dir, env.config_file)
    env.logger.info(f"Resulting config file path: {config_path}")

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

    env.logger.info("Patched config file:")
    with open(config_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            env.logger.info(line)

    return {'BACKUP_DIR': BACKUP_DIR, 'LOG_DIR': LOG_DIR}   



def test_env_vars_in_config_file(setup_environment, env: EnvData):
    """
    Test that environment variables in the config file are correctly expanded.
    """

    # Create temporary config file with environment variables
    env_vars = modify_config_file_env_vars(env)

    # Set environment variables
    os.environ['BACKUP_DIR'] = env_vars['BACKUP_DIR']
    env.logger.info(f"env var $BACKUP_DIR: {os.environ['BACKUP_DIR']}")

    os.environ['LOG_DIR']    = env_vars['LOG_DIR']
    env.logger.info(f"env var $LOG_DIR: {os.environ['LOG_DIR']}")

    try:
        #run manager --create again, since the BACKUP_DIR was changed after the environment was set up
        command = ['manager', '--create-db', '--config-file', env.config_file]
        process = run_command(command)
        assert process.returncode == 0, f'manager command failed with return code {process.returncode}'

        # Run the dar-backup command with the temporary config file
        command = ['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example', '--log-level', 'debug', '--log-stdout']
        process = run_command(command)

        # Check that the command executed successfully
        assert process.returncode == 0, f'dar-backup command failed with return code {process.returncode}'

        # Verify that the backup and log directories were used correctly
        assert os.path.exists(os.path.join(os.environ['BACKUP_DIR'], f'example_FULL_{env.datestamp}.1.dar')), f'Archive f"example_FULL_{env.datestamp}.1.dar" not found in Backup directory'
        assert os.path.exists(os.path.join(os.environ['LOG_DIR'], 'dar-backup.log')), 'Log directory was not used correctly'
    finally:
        # Clean up temporary config file and directories
        if os.environ['BACKUP_DIR'].startswith('/tmp/'):
            command = ['rm', '-rf', f"/tmp/{env_vars['BACKUP_DIR'][5:]}"]

        if os.environ['LOG_DIR'].startswith('/tmp/'):
            command = ['rm', '-rf', f"/tmp/{env_vars['LOG_DIR'][5:]}"]


def test_tilde_in_config_file(setup_environment, env: EnvData):
    """
    Test that "~" in the config file is correctly expanded.
    """

    # Create temporary config file with environment variables
    dict = modify_config_file_tilde(env)

    try:
        # Run the dar-backup command with the temporary config file
        command = ['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example', '--log-level', 'debug', '--log-stdout']
        process = run_command(command)

        # Check that the command executed successfully
        assert process.returncode == 0, f'dar-backup command failed with return code {process.returncode}'

        # Verify that logfile exists
        logfile = os.path.expanduser(dict['LOGFILE_LOCATION'])  
        assert os.path.exists(logfile), f'Logfile: {logfile} not found in home directory'
        assert os.path.getsize(logfile) > 0, f'Logfile: {logfile} is empty'

        env.logger.info(f"Contents of logfile '{logfile}'\n==================")
        with open(logfile, 'r') as f:
            for line in f:
                env.logger.info(line.strip())  # Removes unnecessary newlines
        
    finally:
        # Clean up temporary config file and directories
        if os.path.exists(logfile):
            os.remove(logfile)
            env.logger.info(f"Removed logfile: {logfile}")


def test_dar_backup_definition_with_underscore(setup_environment, env):
    command = ['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example_2']
    process = run_command(command)
    if process.returncode == 0:
        raise Exception(f'dar-backup must fail on a backup definition with an underscore in the name')

def test_dar_backup_nonexistent_definition_(setup_environment, env):
    command = ['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'nonexistent_definition']
    process = run_command(command)
    assert process.returncode == 127, f'dar-backup must fail if backup definition is not found, using -d option'


def test_dar_backup_nonexistent_config_file(setup_environment, env):
    command = ['dar-backup', '--full-backup', '--config-file', 'non-existent-config-file', '-d', 'example']
    process = run_command(command)
    assert process.returncode == 127, f'dar-backup must fail and return code must be 127 if config file is not found'


def test_validate_xml_parser(setup_environment, env):
    """
    Test that the XML parser is working correctly.
    """
    # Create a temporary XML file
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

    expected_paths = {".local/share/vlc/ml.xspf" : True,
        ".local/share/vulkan/implicit_layer.d/steamoverlay_i386.json" : True, 
        ".local/share/vulkan/implicit_layer.d/steamoverlay_x86_64.json" : True,
        ".local/share/vulkan/implicit_layer.d/steamfossilize_i386.json" : True,
        ".local/share/vulkan/implicit_layer.d/steamfossilize_x86_64.json" : True,
        ".local/share/systemd/timers/stamp-dar-diff-backup.timer" : True,
        ".local/share/systemd/timers/stamp-dar-inc-backup.timer" : True,
        ".local/share/lensfun/updates/version_1/mil-sony.xml" : True
    }

    env.logger.info(f"Files in dar XML\n=================")
    for path, size in paths:
        env.logger.info(f"{path} -> {size}")
        assert path in expected_paths, f'Unexpected path: {path}'

    assert len(paths) == len(expected_paths), f'Expected {len(expected_paths)} paths, but found {len(paths)}'   