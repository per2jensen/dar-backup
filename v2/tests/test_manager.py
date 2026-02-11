"""
Test manager.py, that `dar` catalogs are created correctly
"""
import os
import sys
#sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import re
import envdata
import test_bitrot
import tempfile
import subprocess


from datetime import date
from dar_backup.command_runner import CommandRunner
from dar_backup.config_settings import ConfigSettings
from dar_backup.manager import list_catalog_contents

from envdata import EnvData
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List
from unittest.mock import patch, MagicMock
import pytest

pytestmark = pytest.mark.integration






def create_test_config_file(tmp_path: Path) -> Path:
    config_content = """
[MISC]
LOGFILE_LOCATION = {logfile}
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 0
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 86400

[DIRECTORIES]
BACKUP_DIR = {backup_dir}
BACKUP.D_DIR = {backup_d_dir}
TEST_RESTORE_DIR = {restore_dir}

[AGE]
DIFF_AGE = 30
INCR_AGE = 15

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True
"""

    logfile = tmp_path / "dar-backup.log"
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    restore_dir = tmp_path / "restore"

    backup_dir.mkdir()
    backup_d_dir.mkdir()
    restore_dir.mkdir()

    config_path = tmp_path / "dar-backup.conf"
    config_path.write_text(config_content.format(
        logfile=logfile,
        backup_dir=backup_dir,
        backup_d_dir=backup_d_dir,
        restore_dir=restore_dir
    ))

    return config_path


def create_test_config_file_with_capture(tmp_path: Path, capture_limit: int) -> Path:
    config_path = create_test_config_file(tmp_path)
    config_text = config_path.read_text()
    config_text = config_text.replace(
        "COMMAND_TIMEOUT_SECS = 86400\n",
        f"COMMAND_TIMEOUT_SECS = 86400\nCOMMAND_CAPTURE_MAX_BYTES = {capture_limit}\n"
    )
    config_path.write_text(config_text)
    return config_path


def init_manager_runner(config_path: Path, monkeypatch) -> CommandRunner:
    import dar_backup.manager as manager

    manager.runner = None
    manager.logger = None

    monkeypatch.setattr(sys, "argv", ["manager", "--config-file", str(config_path)])
    monkeypatch.setattr(manager.argcomplete, "autocomplete", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(manager, "setup_logging", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr(manager, "get_logger", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr(
        manager,
        "get_binary_info",
        lambda *args, **kwargs: {"path": "dar_manager", "version": "0"}
    )

    def _stop_after_init(*_args, **_kwargs):
        raise SystemExit(0)

    monkeypatch.setattr(manager, "print_aligned_settings", _stop_after_init)

    with pytest.raises(SystemExit):
        manager.main()

    return manager.runner


def test_manager_command_capture_max_bytes_zero(tmp_path, monkeypatch):
    config_path = create_test_config_file_with_capture(tmp_path, 0)
    runner = init_manager_runner(config_path, monkeypatch)

    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.py') as f:
        f.write("import sys\nprint('out')\nprint('err', file=sys.stderr)\n")
        script_path = f.name

    try:
        result = runner.run(["python3", script_path])
    finally:
        os.remove(script_path)

    assert runner.default_capture_limit_bytes == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_manager_command_capture_max_bytes_1k_captures_stdout_stderr(tmp_path, monkeypatch):
    config_path = create_test_config_file_with_capture(tmp_path, 1024)
    runner = init_manager_runner(config_path, monkeypatch)

    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.py') as f:
        f.write("import sys\nprint('out')\nprint('err', file=sys.stderr)\n")
        script_path = f.name

    try:
        result = runner.run(["python3", script_path])
    finally:
        os.remove(script_path)

    assert runner.default_capture_limit_bytes == 1024
    assert "out" in result.stdout
    assert "err" in result.stderr


def test_manager_create_dbs(setup_environment: None, env: EnvData):
    """
    test that generated catalogs are created
    """
    config_settings = ConfigSettings(env.config_file)
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

 

    # remove any existing catalogs
    for root, dirs, files in os.walk(config_settings.backup_dir):
        for file in files:
            if re.search(r".db", file):
                os.remove(os.path.join(config_settings.backup_dir, file))   


    # remove any existing backup definitions
    for root, dirs, files in os.walk(config_settings.backup_d_dir):
        for file in files:
                os.remove(os.path.join(config_settings.backup_d_dir, file))   


    backup_definitions = generate_backup_defs(env, config_settings)

    # generate databases for catalogs for all backup definitions
    command = ['manager', '--create-db' ,'--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = runner.run(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")
    

    [is_catalog(element, config_settings, env) for element in backup_definitions]

    env.logger.info("All generated backup definitions have catalog databases created")


def is_catalog(generated_definition: Dict, config_settings: ConfigSettings, env: EnvData) -> bool:
    """
    Check if a generated backup definition resulted in a catalog database

    Params:
     - generated_definition: See doc for generate_backup_defs() for details on the Dict
     - config_settings
     - env

    Returns:
     - True if a catalog database was found

    Raises:
     - RunTimeError if the catalog database was not found
    """
    catalog_path = os.path.join(config_settings.backup_dir, f"{generated_definition['definition']}.db")
    if os.path.exists(catalog_path):
        env.logger.info(f"Catalog: '{catalog_path}' was created")
        return True
    else:
        raise RuntimeError(f"Catalog not created for backup definition '{catalog_path}'")





def test_manager_version(setup_environment: None, env: envdata.EnvData):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

 
    command = ['manager', '--version']
    process = runner.run(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


def test_manager_help(setup_environment: None, env: envdata.EnvData):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    command = ['manager', '--more-help']
    process = runner.run(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


def test_list_catalog(setup_environment: None, env: EnvData):
    """
    Add a backup to it's catalog database, then list catalogs
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    today_date = date.today().strftime("%Y-%m-%d")
    generate_catalog_db(env)
    files = generate_test_data_and_full_backup(env)

    command = ['manager', '--list-catalogs', '-d', 'example', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    env.logger.info(f"stdout:\n{stdout}")
    if process.returncode != 0:
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


    # Loop over the file names in the 'files' dictionary and verify they are present in stdout
    if f"example_FULL_{today_date}" not in stdout:
        raise Exception(f"File name f'example_FULL_{today_date}' not found in stdout")
    print("Archive catalog found in database")


def test_list_catalog_short_option(setup_environment: None, env: EnvData):
    """
    Add a backup to it's catalog database, then list catalogs
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    today_date = date.today().strftime("%Y-%m-%d")
    generate_catalog_db(env)
    files = generate_test_data_and_full_backup(env)

    command = ['manager', '-l', '-d', 'example', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    env.logger.info(f"stdout:\n{stdout}")
    if process.returncode != 0:
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")

    # Loop over the file names in the 'files' dictionary and verify they are present in stdout
    if f"example_FULL_{today_date}" not in stdout:
        raise Exception(f"File name f'example_FULL_{today_date}' not found in stdout")
    print("Archive catalog found in database")



def test_find_file(setup_environment: None, env: EnvData):
    """
    Add a backup to it's catalog database, then find some files in the catalog
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    
    ##
    ### Positive test
    ##
    today_date = date.today().strftime("%Y-%m-%d")
    generate_catalog_db(env)
    files = generate_test_data_and_full_backup(env)

    archive_name = f"example_FULL_{today_date}"
    command = ['manager', '--list-archive-contents', archive_name, '--config-file', env.config_file]

    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    env.logger.info(f"stdout:\n{stdout}")
    if process.returncode != 0:
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


    # Loop over the file names in the 'files' dictionary and verify they are present in stdout
    
    for file_name in files.keys():
        file_name = f"random-{file_name}.dat"  # files are named like this in generate_test_data_and_full_backup(env)
        file_path = os.path.join(env.data_dir, file_name)[1:]  # the leading / must be dropped
        env.logger.info(f"Find file: '{file_path}' in catalog(s)")
        command = ['manager', '--find-file' , file_path, '-d', 'example' ,'--config-file', env.config_file, '--log-stdout']
        process = runner.run(command)
        if process.returncode != 0:
            env.logger.error(f"stdout: {stdout}")  
            env.logger.error(f"stderr: {stderr}")  
            raise Exception(f"Command failed: {command}")

        stdout = process.stdout
        if not re.search(r"\s+(\d+).*?saved\s+", stdout):
            raise Exception(f"File name {file_path}' not found in any catalog")

    print("All files found in catalog(s)")


    ##
    ### Negative test
    ##
    non_existing_file = 'non-existing-file in catalogs'
    command = ['manager', '--find-file' , non_existing_file, '-d', 'example' ,'--config-file', env.config_file, '--log-stdout']
    process = runner.run(command)
    print(f"stdout:\n{stdout}")  
    print(f"stderr:\n{stderr}")  

    if process.returncode == 0:
        raise Exception(f"A found file must not be ported: {command}")

    if not process.returncode == 2:
        raise Exception(f"Negative test failed, file name {non_existing_file}' is not in any catalog")



def test_remove_specific_archive(setup_environment: None, env: EnvData):
    """
    verify deletion of catalog
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    ##
    ### Positive test
    ##
    today_date = date.today().strftime("%Y-%m-%d")
    generate_catalog_db(env)
    files = generate_test_data_and_full_backup(env)

    command = ['manager', '--add-specific-archive' ,f'example_FULL_{today_date}', '--config-file', env.config_file]
    process = runner.run(command)
    if process.returncode != 0:
        print(f"stdout:\n{process.stdout}")  
        print(f"stderr:\n{process.stderr}")  
        raise Exception(f"Command failed: {command}")

    command = ['manager', '--remove-specific-archive' ,f'example_FULL_{today_date}', '--config-file', env.config_file, '--log-level', 'trace', '--log-stdout']
    process = runner.run(command)

    assert process.returncode == 0, "Archive was not removed"

    command = ['manager', '--list-catalogs' ,'-d', 'example', '--config-file', env.config_file, '--log-level', 'trace', '--log-stdout']
    process = runner.run(command)
    print(process.stdout)


    ##
    ### Negative test
    ##
    non_existing_archive = "example_FULL_1970-01-01"
    command = ['manager', '--remove-specific-archive', non_existing_archive, '--config-file', env.config_file, '--log-level', 'trace', '--log-stdout']
    process = runner.run(command)
    env.logger.debug(process)
    assert process.returncode == 2, "manager did not return 2 due to removing a non-existing archive"




def test_list_archive_contents(setup_environment: None, env: EnvData):
    """
    verify listing the contents of an archive, given the archive name
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    today_date = date.today().strftime("%Y-%m-%d")
    generate_catalog_db(env)
    files = generate_test_data_and_full_backup(env)

    command = ['manager', '--list-archive-contents', f'example_FULL_{today_date}' ,'--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = runner.run(command, timeout=600)
    stdout, stderr = process.stdout, process.stderr
    env.logger.info(f"stdout:\n{stdout}")
    if process.returncode != 0:
        print(f"ERROR: stdout: {stdout}")  
        print(f"ERROR: stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")

    # Loop over the file names in the 'files' dictionary and verify they are present in stdout
    for file_name in files.keys():
        if file_name not in stdout:
            raise Exception(f"File name '{file_name}' not found in stdout")

    print("All file names are present in stdout")



def test_add_directory_to_catalog_db(setup_environment: None, env: EnvData):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['manager', '--add-dir' , env.backup_dir, '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    run_manager_adding(command, env)



def test_add_empty_directory_to_catalog_db(setup_environment: None, env: EnvData):
    """
    Verify no error if adding a directory with no dar archives
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['manager', '--add-dir' , env.backup_dir, '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    generate_test_data_and_backup = False
    run_manager_adding(command, env, generate_test_data_and_backup)



def test_add_archive_to_catalog_db(setup_environment: None, env: EnvData):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    today_date = date.today().strftime("%Y-%m-%d")
    command = ['manager', '--add-specific-archive' ,f'example_FULL_{today_date}', '--config-file', env.config_file, '--log-level', "trace", "--log-stdout"]
    run_manager_adding(command, env)



def run_manager_adding(command: List[str], env: EnvData, generate: bool=True):
    """
    run the supplied command to add an archive or a directory to the example.db catalog database
    list the catalog database to verify the backup was added

    Params:
      - command, a List containing the command to run
      - env, the EnvData 
      - generate, defaults to True, if False do not generate test data and do not run backup
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    today_date = date.today().strftime("%Y-%m-%d")
    generate_catalog_db(env)
    if generate:
        generate_test_data_and_full_backup(env)

    command = ['manager', '--add-dir' , env.backup_dir, '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")

    if not generate:
        if not re.search("No 'dar' archives found in directory", stdout):
            raise Exception("A note on no dar archives found should have been produced")
        env.logger.info("OK: Notice on no dar archives found was emitted")
        return


    # list catalogs
    command = ['manager', '--list-catalogs' ,'--config-file', env.config_file]
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")

    print(f"stdout: {stdout}")

    if generate:
        if not re.search(f"example_FULL_{today_date}", stdout):
            raise Exception(f"Catalog not found for backup definition f'example_FULL_{today_date}'")

    #TODO:  list contents of archive from catalog in database and verify

    print(f"Catalog for example_FULL_{today_date}.1.dar found in example.db") 



def generate_catalog_db(env: envdata.EnvData):
    # generate database for catalogs
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['manager', '--create-db' ,'--config-file', env.config_file]
    process = runner.run(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


def generate_test_data_and_full_backup(env: envdata.EnvData) -> Dict:
    """
    Returns the Dict with file names as keys
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    file_sizes = {
        '1byte': 1,
        '10bytes': 10,
        '100bytes': 100,
        '1000bytes': 1000,
        '10kB': 10 * 1024,
        '100kB': 100 * 1024,
        '1MB': 1024 * 1024,
        '10MB': 10 * 1024 * 1024
   }

    test_bitrot.generate_datafiles(env, file_sizes)
    command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', env.config_file]
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        print(f"dar stdout: {stdout}")
        print(f"dar stderr: {stderr}")
        raise RuntimeError("dar-backup failed to create a full backup") 
    return file_sizes


def generate_backup_defs(env, config_settings) -> List[Dict]:
    """
    Generate:
     - 3 dummy backup definitions
     - 1 definition with spaces in it's name
     - 1 definition with spaces and danish special letters

    Return:
     - A list of dicts with the following keys:
       - definition - name of a backup definition
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    definition_key = 'definition'
    result = []
    for i in range(3):
        backup_def = f"test{i}"
        with open(os.path.join(config_settings.backup_d_dir, backup_def), "a") as f:
            f.write('dummy data\n')
            result.append({definition_key: backup_def})
    
    element = {definition_key : 'backup definition with spaces'}
    with open(os.path.join(config_settings.backup_d_dir, element[definition_key]), "a") as f:
            f.write('dummy data\n')
    result.append(element)

    element = {definition_key : "backup definition with danish chars æøå ÆØÅ"}
    with open(os.path.join(config_settings.backup_d_dir, element[definition_key]), "a") as f:
            f.write('dummy data\n')
    result.append(element)

    return result


# --- 1. --more-help

def test_manager_more_help(tmp_path, monkeypatch):
    config_path = create_test_config_file(tmp_path)
    monkeypatch.setattr(sys, "argv", ["manager.py", "--more-help","--config-file", str(config_path)])
    with patch("builtins.print") as mock_print, patch("sys.exit") as mock_exit:
        import dar_backup.manager as mgr
        mgr.main()
        mock_print.assert_called_once()
        mock_exit.assert_called_once_with(0)

# --- 2. --version
def test_manager_version(tmp_path, monkeypatch):
    config_path = create_test_config_file(tmp_path)
    monkeypatch.setattr(sys, "argv", ["manager.py", "--version", "--config-file", str(config_path)])
    with patch("builtins.print") as mock_print, patch("sys.exit") as mock_exit:
        import dar_backup.manager as mgr

        print("=== DEBUG CONFIG FILE ===")
        print(config_path.read_text())
        print("=========================")

        mgr.main()
        mock_print.assert_any_call(f"{mgr.SCRIPTNAME} {mgr.about.__version__}")
        mock_exit.assert_called_once_with(0)

# --- 3. --add-specific-archive with empty value
def test_manager_add_specific_archive_empty(tmp_path, monkeypatch):
    config_path = create_test_config_file(tmp_path)
    monkeypatch.setattr(sys, "argv", ["manager.py", "--add-specific-archive", "", "--config-file", str(config_path)])
    with patch("sys.exit") as mock_exit:
        import dar_backup.manager as mgr

        print("=== DEBUG CONFIG FILE ===")
        print(config_path.read_text())
        print("=========================")

        mgr.main()
        mock_exit.assert_called_once_with(1)


# --- 4. --add-specific-archive and --remove-specific-archive together
def test_manager_add_and_remove_specific_archive(tmp_path, monkeypatch):
    config_path = create_test_config_file(tmp_path)
    monkeypatch.setattr(sys, "argv", ["manager.py", "--add-specific-archive", "a", "--remove-specific-archive", "b", "--config-file", str(config_path)])

    mock_logger = MagicMock()
    with patch("dar_backup.manager.setup_logging", return_value=mock_logger), patch("sys.exit") as mock_exit:
        import dar_backup.manager as mgr

        print("=== DEBUG CONFIG FILE ===")
        print(config_path.read_text())
        print("=========================")

        mgr.main()

    mock_logger.error.assert_any_call("you can't add and remove archives in the same operation, exiting")
    mock_exit.assert_called_once_with(1)


def test_manager_with_alternate_archive_dir(tmp_path, monkeypatch):
    """
    Test --alternate-archive-dir to ensure it overrides the default BACKUP_DIR.
    """
    # Create an alternate archive directory with dummy .1.dar file
    alternate_backup_dir = tmp_path / "alternate_backups"
    alternate_backup_dir.mkdir()
    dummy_dar_file = alternate_backup_dir / "example_FULL_2025-04-06.1.dar"
    dummy_dar_file.touch()

    # Create minimal config with dummy BACKUP_DIR
    config_path = create_test_config_file(tmp_path)

    # Use --create-db to trigger database creation from existing backup defs
    monkeypatch.setattr(sys, "argv", [
        "manager.py",
        "--add-dir", str(alternate_backup_dir),
        "--alternate-archive-dir", str(alternate_backup_dir),
        "--create-db",
        "--config-file", str(config_path),
        "--log-level", "debug",
        "--log-stdout"
    ])

    # Patch logger, CommandRunner and create_db
    with patch("dar_backup.manager.setup_logging") as mock_logger_setup, \
         patch("dar_backup.manager.CommandRunner") as mock_runner_class, \
         patch("dar_backup.manager.create_db") as mock_db_creator, \
         patch("sys.exit") as mock_exit:

        mock_logger = MagicMock()
        mock_logger_setup.return_value = mock_logger
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        mock_runner.run.return_value.returncode = 0

        # Create a valid backup definition (no underscores)
        backup_d_file = tmp_path / "backup.d" / "exampledef"
        backup_d_file.parent.mkdir(exist_ok=True)
        backup_d_file.write_text("-R /example\n")


        import dar_backup.manager as mgr
        mgr.main()

        # Assert that create_db was called at least once
        mock_db_creator.assert_called()



def test_create_db_handles_dar_manager_failure(tmp_path):
    from types import SimpleNamespace
    from dar_backup.manager import create_db

    dummy_def = "testdef"
    dummy_db_path = tmp_path / f"{dummy_def}.db"
    config = SimpleNamespace(backup_dir=tmp_path)

    mock_runner = MagicMock()
    mock_runner.run.return_value.returncode = 1
    mock_runner.run.return_value.stdout = "some stdout"
    mock_runner.run.return_value.stderr = "some stderr"

    mock_logger = MagicMock()

    result = create_db(dummy_def, config, mock_logger, mock_runner)

    # It should log the error and return non-zero
    assert result == 1
    mock_logger.error.assert_any_call(f'Something went wrong creating the database: "{dummy_db_path}"')
    mock_logger.error.assert_any_call("stderr: some stderr")
    mock_logger.error.assert_any_call("stdout: some stdout")




def test_list_catalogs_db_missing(tmp_path):
    from dar_backup.manager import list_catalogs

    config = SimpleNamespace(backup_dir=tmp_path)
    backup_def = "nonexistent_def"

    with patch("dar_backup.manager.logger") as mock_logger:
        result = list_catalogs(backup_def, config)

        expected_path = tmp_path / f"{backup_def}.db"
        mock_logger.error.assert_called_once_with(f'Database not found: "{expected_path}"')
        assert result.returncode == 1
        assert result.stderr == f'Database not found: "{expected_path}"'



def test_list_catalogs_command_failure(tmp_path):
    from dar_backup.manager import list_catalogs

    backup_def = "exampledef"
    db_path = tmp_path / f"{backup_def}.db"
    db_path.touch()  # simulate database presence

    config = SimpleNamespace(backup_dir=tmp_path)

    mock_process = MagicMock()
    mock_process.returncode = 1
    mock_process.stdout = "failure output"
    mock_process.stderr = "failure error"

    with patch("dar_backup.manager.runner", new=SimpleNamespace(run=MagicMock(return_value=mock_process))), \
         patch("dar_backup.manager.logger") as mock_logger:
        result = list_catalogs(backup_def, config)

        assert result.returncode == 1
        mock_logger.error.assert_any_call(f'Error listing catalogs for: "{db_path}"')
        mock_logger.error.assert_any_call("stderr: failure error")
        mock_logger.error.assert_any_call("stdout: failure output")


def test_cat_no_for_name_list_catalogs_fails(tmp_path):
    from dar_backup.manager import cat_no_for_name

    archive = "somearchive_FULL_2025-04-06"
    backup_def = "somearchive"  # what backup_def_from_archive() returns
    config = SimpleNamespace(backup_dir=tmp_path)

    mock_process = SimpleNamespace(
        returncode=1,  # Simulate failure
        stdout="",
        stderr="error"
    )

    with patch("dar_backup.manager.list_catalogs", return_value=mock_process), \
         patch("dar_backup.manager.logger") as mock_logger:
        result = cat_no_for_name(archive, config)

    assert result == -1
    mock_logger.error.assert_called_with(f"Error listing catalogs for backup def: '{backup_def}'")


def test_list_archive_contents_runner_fails(tmp_path):
    from dar_backup.manager import list_archive_contents

    archive = "example_FULL_2025-04-06"
    config = SimpleNamespace(backup_dir=tmp_path)

    # Simulate database file existing
    db_path = tmp_path / "example.db"
    db_path.touch()

    # Mock the process result
    mock_process = SimpleNamespace(
        returncode=1,
        stdout="mocked stdout",
        stderr="mocked stderr"
    )

    # Patch the entire runner object used inside manager.py
    with patch("dar_backup.manager.cat_no_for_name", return_value=1), \
         patch("dar_backup.manager.logger") as mock_logger, \
         patch("dar_backup.manager.runner", new=SimpleNamespace(run=MagicMock(return_value=mock_process))):
        
        result = list_archive_contents(archive, config)

    assert result == 1
    mock_logger.error.assert_any_call(f'Error listing catalogs for: "{str(db_path)}"')
    mock_logger.error.assert_any_call("stderr: mocked stderr")
    mock_logger.error.assert_any_call("stdout: mocked stdout")


def test_list_archive_contents_cat_not_found(tmp_path):
    from dar_backup.manager import list_archive_contents

    archive = "example_FULL_2025-04-06"
    config = SimpleNamespace(backup_dir=tmp_path)

    db_path = tmp_path / "example.db"
    db_path.touch()

    with patch("dar_backup.manager.cat_no_for_name", return_value=-1), \
         patch("dar_backup.manager.logger") as mock_logger:
        
        result = list_archive_contents(archive, config)

    assert result == 1
    mock_logger.error.assert_called_with(
        f"archive: '{archive}' not found in database: '{db_path}'"
    )


def test_list_archive_contents_runner_fails_isolated(tmp_path):
    from dar_backup.manager import list_archive_contents

    archive = "example_FULL_2025-04-06"
    config = SimpleNamespace(backup_dir=tmp_path)

    db_path = tmp_path / "example.db"
    db_path.touch()

    mock_process = SimpleNamespace(
        returncode=1,
        stdout="mocked stdout",
        stderr="mocked stderr"
    )

    with patch("dar_backup.manager.cat_no_for_name", return_value=5), \
         patch("dar_backup.manager.logger") as mock_logger, \
         patch("dar_backup.manager.runner", new=SimpleNamespace(run=MagicMock(return_value=mock_process))):
        
        result = list_archive_contents(archive, config)

    assert result == 1
    mock_logger.error.assert_any_call(f'Error listing catalogs for: "{str(db_path)}"')
    mock_logger.error.assert_any_call("stderr: mocked stderr")
    mock_logger.error.assert_any_call("stdout: mocked stdout")


def test_find_file_db_missing(tmp_path):
    from dar_backup.manager import find_file

    backup_def = "exampledef"
    fake_file = "some/path/to/file.txt"
    config = SimpleNamespace(backup_dir=tmp_path)

    with patch("dar_backup.manager.logger") as mock_logger:
        result = find_file(fake_file, backup_def, config)

    expected_db_path = tmp_path / f"{backup_def}.db"
    mock_logger.error.assert_called_once_with(f'Database not found: "{expected_db_path}"')
    assert result == 1


def test_add_specific_archive_dar_not_found(tmp_path):
    from dar_backup.manager import add_specific_archive

    config = SimpleNamespace(
        backup_dir=tmp_path,
        backup_d_dir=tmp_path
    )

    archive_name = "example_FULL_2025-04-06"
    # Ensure the required dar file is missing
    archive_test_path = tmp_path / f"{archive_name}.1.dar"

    with patch("dar_backup.manager.logger") as mock_logger:
        result = add_specific_archive(str(archive_name), config)

    mock_logger.error.assert_called_once_with(f'dar backup: "{archive_test_path}" not found, exiting')
    assert result == 1

#====================
def test_add_specific_archive_success(tmp_path):
    from dar_backup.manager import add_specific_archive

    archive_name = "example_FULL_2025-04-06"
    archive_path = tmp_path / f"{archive_name}.1.dar"
    archive_path.touch()

    backup_def = "example"
    (tmp_path / backup_def).touch()

    config = SimpleNamespace(
        backup_dir=tmp_path,
        backup_d_dir=tmp_path
    )

    mock_process = SimpleNamespace(returncode=0, stdout="success", stderr="")

    with patch("dar_backup.manager.runner") as mock_runner, \
         patch("dar_backup.manager.logger") as mock_logger:
        mock_runner.run.return_value = mock_process
        result = add_specific_archive(archive_name, config)

    mock_logger.info.assert_any_call(f'"{tmp_path / archive_name}" added to its catalog')
    #mock_logger.info.assert_any_call(f'"{tmp_path / archive_name}" added to it\'s catalog')
    assert result == 0


def test_add_specific_archive_warning(tmp_path):
    from dar_backup.manager import add_specific_archive

    archive_name = "example_FULL_2025-04-06"
    (tmp_path / f"{archive_name}.1.dar").touch()
    (tmp_path / "example").touch()

    config = SimpleNamespace(
        backup_dir=tmp_path,
        backup_d_dir=tmp_path
    )

    mock_process = SimpleNamespace(returncode=5, stdout="some warning", stderr="")

    with patch("dar_backup.manager.runner") as mock_runner, \
         patch("dar_backup.manager.logger") as mock_logger:
        mock_runner.run.return_value = mock_process
        result = add_specific_archive(archive_name, config)

    mock_logger.warning.assert_called_with(
    f'Something did not go completely right adding "{tmp_path / archive_name}" to its catalog, dar_manager error: "5"'
    )
    assert result == 5



def test_add_specific_archive_failure(tmp_path):
    from dar_backup.manager import add_specific_archive

    archive_name = "example_FULL_2025-04-06"
    (tmp_path / f"{archive_name}.1.dar").touch()
    (tmp_path / "example").touch()

    config = SimpleNamespace(
        backup_dir=tmp_path,
        backup_d_dir=tmp_path
    )

    mock_process = SimpleNamespace(returncode=42, stdout="error out", stderr="error err")

    with patch("dar_backup.manager.runner") as mock_runner, \
         patch("dar_backup.manager.logger") as mock_logger:
        mock_runner.run.return_value = mock_process

        result = add_specific_archive(archive_name, config)

    mock_logger.error.assert_any_call(f'something went wrong adding "{tmp_path / archive_name}" to its catalog, dar_manager error: "42"')
    mock_logger.error.assert_any_call("stderr: error err")
    mock_logger.error.assert_any_call("stdout: error out")
    assert result == 42


# =================00

from dar_backup.manager import add_specific_archive

def test_add_specific_archive_unexpected_error(tmp_path):
    archive_name = "test_FULL_2025-04-01"
    (tmp_path / f"{archive_name}.1.dar").touch()
    (tmp_path / "test").touch()

    config = SimpleNamespace(backup_dir=tmp_path, backup_d_dir=tmp_path)
    process = SimpleNamespace(returncode=42, stdout="weird error", stderr="unexpected failure")

    with patch("dar_backup.manager.runner") as mock_runner, \
         patch("dar_backup.manager.logger") as mock_logger:
        mock_runner.run.return_value = process
        result = add_specific_archive(archive_name, config)
        assert result == 42
        mock_logger.error.assert_any_call(
            f'something went wrong adding "{tmp_path / archive_name}" to its catalog, dar_manager error: "42"'
        )



from dar_backup.manager import main as manager_main

def test_list_archive_contents_arg(monkeypatch, tmp_path):
    """
    Test that the manager CLI exits cleanly when passed --list-archive-contents.

    This test simulates CLI invocation by setting sys.argv with a valid config file,
    and providing the --list-archive-contents option. It asserts that the tool exits
    via SystemExit (as expected for CLI behavior), regardless of whether the archive
    exists or not.

    The purpose is to validate argument parsing and early termination behavior,
    not functional success of listing contents.
    """
    # Create a minimal valid config file
    config_file = tmp_path / "dummy.conf"
    config_file.write_text("""\
[MISC]
LOGFILE_LOCATION = /tmp/test.log
MAX_SIZE_VERIFICATION_MB = 10
MIN_SIZE_VERIFICATION_MB = 1
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 30

[DIRECTORIES]
BACKUP_DIR = /tmp
BACKUP.D_DIR = /tmp
TEST_RESTORE_DIR = /tmp

[AGE]
DIFF_AGE = 30
INCR_AGE = 15

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = true
""")

    test_args = [
        "manager",
        "--list-archive-contents", "1",
        "-d", "example",
        "--config-file", str(config_file)
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit):
        manager_main()




def _test_list_archive_contents_arg(monkeypatch):
    test_args = ["manager", "--list-archive-contents", "1", "-d", "example", "--config-file", "dummy.conf"]
    monkeypatch.setattr(sys, "argv", test_args)
    with pytest.raises(SystemExit):
        manager_main()



from dar_backup import manager

@pytest.mark.parametrize("cli_args, expected_error", [
    (["prog", "--add-dir", " "], "archive dir not given"),
    (["prog", "--add-specific-archive", " "], "specific archive to add not given"),
    (["prog", "--remove-specific-archive", " "], "specific archive to remove not given"),
    (["prog", "--add-specific-archive", "arc", "--remove-specific-archive", "arc"], "you can't add and remove archives"),
    (["prog", "--add-dir", "foo", "--add-specific-archive", "arc"], "you cannot add both a directory and an archive"),
    (["prog", "-d", " "], "No backup definition given"),
    (["prog", "-d", "nonexistent"], "does not exist"),
    (["prog", "--list-archive-contents", " "], "--list-archive-contents <param> not given"),
    (["prog", "--find-file", "somefile"], "--find-file requires the --backup-def"),
    (["prog", "--alternate-archive-dir", "/nonexistent"], "Alternate archive dir '/nonexistent' does not exist"),
])
def test_manager_sanity_checks_exit(setup_environment, env, monkeypatch, caplog, cli_args, expected_error):
    # Use actual test config file provided by the fixture
    cli = cli_args + ["--config-file", env.config_file]
    monkeypatch.setattr(sys, "argv", cli)

    with pytest.raises(SystemExit) as e:
        manager.main()

    assert e.value.code == 1
    assert any(expected_error in record.message for record in caplog.records)




from dar_backup.config_settings import ConfigSettings  # Corrected import


from dar_backup.config_settings import ConfigSettings



@pytest.fixture
def mock_config(tmp_path):
    config_file = tmp_path / "mock_config.ini"
    config_file.write_text(r"""[MISC]
LOGFILE_LOCATION = /tmp/mock.log
MAX_SIZE_VERIFICATION_MB = 100
MIN_SIZE_VERIFICATION_MB = 10
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 60
[DIRECTORIES]
BACKUP_DIR = /tmp/mock_backups
TEST_RESTORE_DIR = /tmp/mock_restore
BACKUP.D_DIR = /tmp/mock_backup.d
[AGE]
DIFF_AGE = 30
INCR_AGE = 7
[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = true
""")
    return ConfigSettings(config_file=str(config_file))


def test_catalog_file_not_found(env, setup_environment, caplog):
    caplog.set_level("ERROR")
    result = list_catalog_contents(1, "backup01", env)
    assert result == 1
    assert 'Catalog database not found' in caplog.text


def test_catalog_command_success(env, setup_environment, capsys):
    mock_process = MagicMock()
    mock_process.stdout = "catalog contents"
    mock_process.stderr = ""
    mock_process.returncode = 0

    mock_runner = MagicMock()
    mock_runner.run.return_value = mock_process

    with patch("dar_backup.manager.runner", mock_runner), \
         patch("os.path.exists", return_value=True):
        result = list_catalog_contents(2, "backup01", env)
        captured = capsys.readouterr()
        assert result == 0
        assert "catalog contents" in captured.out



def test_catalog_command_failure(env, setup_environment, caplog):
    mock_process = MagicMock()
    mock_process.stdout = "stdout message"
    mock_process.stderr = "stderr message"
    mock_process.returncode = 2

    mock_runner = MagicMock()
    mock_runner.run.return_value = mock_process

    caplog.set_level("ERROR")

    with patch("dar_backup.manager.runner", mock_runner), \
         patch("os.path.exists", return_value=True):
        result = list_catalog_contents(3, "backup01", env)
        assert result == 2
        assert "Error listing catalogs" in caplog.text
        assert "stderr message" in caplog.text
        assert "stdout message" in caplog.text



def test_manager_db_dir_respected_by_dar_backup(env, setup_environment, tmp_path):
    """
    Verify that if MANAGER_DB_DIR is specified, the catalog database is created there by dar-backup during full backup.
    """
    manager_db_dir = tmp_path / "custom_catalogs"
    manager_db_dir.mkdir()

    with open(env.config_file, "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if line.strip() == "[DIRECTORIES]":
            insert_at = i + 1
            while insert_at < len(lines) and not lines[insert_at].startswith("["):
                insert_at += 1
            lines.insert(insert_at, f"MANAGER_DB_DIR = {manager_db_dir}\n")
            break

    with open(env.config_file, "w") as f:
        f.writelines(lines)

    config_settings = ConfigSettings(env.config_file)
    assert config_settings.manager_db_dir == str(manager_db_dir)

    generate_catalog_db(env)
    test_files = generate_test_data_and_full_backup(env)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = [
        "manager", "--list-catalogs", "-d", "example",
        "--config-file", env.config_file,
        "--log-level", "debug", "--log-stdout"
    ]
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    env.logger.info("=== list-catalogs stdout ===\n" + stdout)
    if process.returncode != 0:
        env.logger.error("=== list-catalogs stderr ===\n" + stderr)
        raise RuntimeError("manager --list-catalogs failed")

    expected_db = manager_db_dir / "example.db"
    assert expected_db.exists(), f"Catalog DB not found at expected path: {expected_db}"
    env.logger.info(f"✅ Catalog successfully created in MANAGER_DB_DIR: {expected_db}")

    today = date.today().strftime("%Y-%m-%d")
    archive_name = f"example_FULL_{today}"
    command = [
        "manager", "--list-archive-contents", archive_name,
        "--config-file", env.config_file,
        "--log-level", "debug", "--log-stdout"
    ]
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    env.logger.info("=== list-archive-contents stdout ===\n" + stdout)
    if process.returncode != 0:
        env.logger.error("=== list-archive-contents stderr ===\n" + stderr)
        raise RuntimeError("manager --list-archive-contents failed")

    for base in test_files:
        expected = f"random-{base}.dat"
        if expected not in stdout:
            raise AssertionError(f"Expected file '{expected}' not found in archive contents")

    env.logger.info("✅ All expected files are present in archive contents")




def get_db_dir(config_settings: ConfigSettings) -> str:
    """
    Return the correct directory for storing catalog databases.
    Uses manager_db_dir if set, otherwise falls back to backup_dir.
    """
    return config_settings.manager_db_dir or config_settings.backup_dir


def test_manager_db_dir_invalid_path_raises(env, setup_environment, tmp_path):
    """
    Negative test: if MANAGER_DB_DIR points to a non-writable or invalid directory, catalog creation should fail.
    """
    import shutil

    # Use a bogus or protected path
    invalid_db_dir = tmp_path / "nonexistent" / "bad_dir"

    with open(env.config_file, "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if line.strip() == "[DIRECTORIES]":
            insert_at = i + 1
            while insert_at < len(lines) and not lines[insert_at].startswith("["):
                insert_at += 1
            lines.insert(insert_at, f"MANAGER_DB_DIR = {invalid_db_dir}\n")
            break

    with open(env.config_file, "w") as f:
        f.writelines(lines)

    config_settings = ConfigSettings(env.config_file)
    assert config_settings.manager_db_dir == str(invalid_db_dir)

    # Remove directory to ensure it doesn't exist at runtime
    shutil.rmtree(invalid_db_dir, ignore_errors=True)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['manager', '--create-db', '--backup-def', 'example', '--config-file', env.config_file]
    process = runner.run(command)

    env.logger.debug(f"return code from 'db created': {process.returncode}")
    database = "example.db"
    database_path = os.path.join(get_db_dir(config_settings), database)

    if process.returncode == 0:
        env.logger.info(f'Database created: "{database_path}"')
    else:
        env.logger.error(f'Something went wrong creating the database: "{database_path}"')
        stdout, stderr = process.stdout, process.stderr
        env.logger.error(f"stderr: {stderr}")
        env.logger.error(f"stdout: {stdout}")

    assert process.returncode != 0, "Expected failure due to invalid MANAGER_DB_DIR path"
    env.logger.info("✅ Catalog creation failed as expected due to invalid MANAGER_DB_DIR")


def test_backup_def_from_archive_no_match_logs_error():
    from dar_backup.manager import backup_def_from_archive

    with patch("dar_backup.manager.logger") as mock_logger:
        result = backup_def_from_archive("invalidarchive")

    assert result is None
    mock_logger.error.assert_called_once()


def test_list_archive_contents_subprocess_empty_prints_info(tmp_path, capsys):
    import io
    from dar_backup.manager import list_archive_contents

    archive = "example_FULL_2025-04-06"
    db_path = tmp_path / "example.db"
    db_path.touch()

    config = SimpleNamespace(backup_dir=tmp_path, command_capture_max_bytes=1024)

    class FakeProcess:
        def __init__(self):
            self.returncode = 0
            self.stdout = io.BytesIO(b"header line\n")
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return None

    with patch("dar_backup.manager.cat_no_for_name", return_value=1), \
         patch("dar_backup.manager.runner", new=SimpleNamespace(default_capture_limit_bytes=1024)), \
         patch("dar_backup.manager._open_command_log", return_value=(None, None)), \
         patch("dar_backup.manager.logger", new=MagicMock()), \
         patch("dar_backup.manager.subprocess.Popen", return_value=FakeProcess()):
        result = list_archive_contents(archive, config)

    assert result == 0
    out = capsys.readouterr().out.strip()
    assert f"[info] Archive '{archive}' is empty." in out


def test_list_archive_contents_subprocess_filters_saved_lines(tmp_path, capsys):
    import io
    from dar_backup.manager import list_archive_contents

    archive = "example_FULL_2025-04-06"
    db_path = tmp_path / "example.db"
    db_path.touch()

    config = SimpleNamespace(backup_dir=tmp_path, command_capture_max_bytes=1024)
    output = (
        b"header line\n"
        b"[ Saved ] file1.txt\n"
        b"other line\n"
        b"[ Saved ] dir/file2.txt\n"
    )

    class FakeProcess:
        def __init__(self):
            self.returncode = 0
            self.stdout = io.BytesIO(output)
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return None

    with patch("dar_backup.manager.cat_no_for_name", return_value=1), \
         patch("dar_backup.manager.runner", new=SimpleNamespace(default_capture_limit_bytes=1024)), \
         patch("dar_backup.manager._open_command_log", return_value=(None, None)), \
         patch("dar_backup.manager.logger", new=MagicMock()), \
         patch("dar_backup.manager.subprocess.Popen", return_value=FakeProcess()):
        result = list_archive_contents(archive, config)

    assert result == 0
    out_lines = capsys.readouterr().out.strip().splitlines()
    assert out_lines == ["[ Saved ] file1.txt", "[ Saved ] dir/file2.txt"]


def test_add_specific_archive_missing_backup_def(tmp_path):
    from dar_backup.manager import add_specific_archive

    archive = "example_FULL_2025-04-06"
    (tmp_path / f"{archive}.1.dar").touch()
    config = SimpleNamespace(backup_dir=tmp_path, backup_d_dir=tmp_path)

    with patch("dar_backup.manager.logger") as mock_logger:
        result = add_specific_archive(archive, config)

    assert result == 1
    mock_logger.error.assert_called_once()


def test_add_specific_archive_old_archive_declined(tmp_path):
    from dar_backup.manager import add_specific_archive

    archive = "example_FULL_2025-04-01"
    (tmp_path / f"{archive}.1.dar").touch()
    (tmp_path / "example").touch()
    config = SimpleNamespace(backup_dir=tmp_path, backup_d_dir=tmp_path)

    list_output = "1\t/path\texample_FULL_2025-04-10"

    with patch("dar_backup.manager.subprocess.run") as mock_run, \
         patch("dar_backup.manager.confirm_add_old_archive", return_value=False), \
         patch("dar_backup.manager.logger") as mock_logger, \
         patch("dar_backup.manager.runner") as mock_runner:
        mock_run.return_value = SimpleNamespace(stdout=list_output)
        result = add_specific_archive(archive, config)

    assert result == 1
    mock_logger.info.assert_any_call(
        f"Archive {archive} skipped due to user declining to add older archive."
    )
    mock_runner.run.assert_not_called()


def test_add_specific_archive_catalog_list_failure_logs_warning(tmp_path):
    from dar_backup.manager import add_specific_archive

    archive = "example_FULL_2025-04-01"
    (tmp_path / f"{archive}.1.dar").touch()
    (tmp_path / "example").touch()
    config = SimpleNamespace(backup_dir=tmp_path, backup_d_dir=tmp_path)

    with patch("dar_backup.manager.subprocess.run", side_effect=subprocess.CalledProcessError(1, "dar_manager")), \
         patch("dar_backup.manager.runner") as mock_runner, \
         patch("dar_backup.manager.logger") as mock_logger:
        mock_runner.run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
        result = add_specific_archive(archive, config)

    assert result == 0
    mock_logger.warning.assert_called_once_with(
        "Could not determine latest catalog date for chronological check."
    )


def test_add_directory_no_archives_logs_info(tmp_path):
    from dar_backup.manager import add_directory

    args = SimpleNamespace(add_dir=str(tmp_path))
    config = SimpleNamespace()

    with patch("dar_backup.manager.logger") as mock_logger, \
         patch("dar_backup.manager.add_specific_archive") as mock_add:
        add_directory(args, config)

    mock_logger.info.assert_called_once_with(f"No 'dar' archives found in directory {args.add_dir}")
    mock_add.assert_not_called()


def test_add_directory_missing_dir_raises(tmp_path):
    from dar_backup.manager import add_directory

    args = SimpleNamespace(add_dir=str(tmp_path / "missing"))
    config = SimpleNamespace()

    with pytest.raises(RuntimeError, match="does not exist"):
        add_directory(args, config)


def test_add_directory_sorts_by_date_then_type(tmp_path):
    from dar_backup.manager import add_directory

    args = SimpleNamespace(add_dir=str(tmp_path))
    config = SimpleNamespace()
    filenames = [
        "example_DIFF_2025-01-02.1.dar",
        "example_FULL_2025-01-02.1.dar",
        "example_INCR_2025-01-02.1.dar",
        "example_INCR_2025-01-01.1.dar",
        "example_DIFF_2025-01-01.1.dar",
        "example_FULL_2025-01-01.1.dar",
    ]

    with patch("dar_backup.manager.os.listdir", return_value=filenames), \
         patch("dar_backup.manager.add_specific_archive") as mock_add, \
         patch("dar_backup.manager.logger"):
        add_directory(args, config)

    called_archives = [call.args[0] for call in mock_add.call_args_list]
    assert called_archives == [
        "example_FULL_2025-01-01",
        "example_DIFF_2025-01-01",
        "example_INCR_2025-01-01",
        "example_FULL_2025-01-02",
        "example_DIFF_2025-01-02",
        "example_INCR_2025-01-02",
    ]

def test_remove_specific_archive_failure_returns_one(tmp_path):
    from dar_backup.manager import remove_specific_archive

    config = SimpleNamespace(backup_dir=tmp_path)
    process = SimpleNamespace(returncode=1, stdout="bad", stderr="oops")

    with patch("dar_backup.manager.backup_def_from_archive", return_value="example"), \
         patch("dar_backup.manager.cat_no_for_name", return_value=1), \
         patch("dar_backup.manager.runner") as mock_runner, \
         patch("dar_backup.manager.logger") as mock_logger:
        mock_runner.run.return_value = process
        result = remove_specific_archive("example_FULL_2025-01-01", config)

    assert result == 1
    mock_logger.error.assert_any_call("bad")
    mock_logger.error.assert_any_call("oops")


def test_create_db_db_dir_missing(tmp_path):
    from dar_backup.manager import create_db

    missing_dir = tmp_path / "missing"
    config = SimpleNamespace(backup_dir=str(missing_dir))
    mock_logger = MagicMock()
    mock_runner = MagicMock()

    result = create_db("example", config, mock_logger, mock_runner)

    assert result == 1
    mock_logger.error.assert_called_once_with(f"DB dir does not exist: {missing_dir}")


def test_create_db_db_dir_not_directory(tmp_path):
    from dar_backup.manager import create_db

    db_file = tmp_path / "dbfile"
    db_file.write_text("not a dir")
    config = SimpleNamespace(backup_dir=str(db_file))
    mock_logger = MagicMock()
    mock_runner = MagicMock()

    result = create_db("example", config, mock_logger, mock_runner)

    assert result == 1
    mock_logger.error.assert_called_once_with(f"DB path exists but is not a directory: {db_file}")


def test_create_db_db_dir_not_writable(tmp_path):
    from dar_backup.manager import create_db

    db_dir = tmp_path / "dbdir"
    db_dir.mkdir()
    config = SimpleNamespace(backup_dir=str(db_dir))
    mock_logger = MagicMock()
    mock_runner = MagicMock()

    with patch("dar_backup.manager.os.access", return_value=False):
        result = create_db("example", config, mock_logger, mock_runner)

    assert result == 1
    mock_logger.error.assert_called_once_with(f"DB dir is not writable: {db_dir}")


def test_list_catalogs_success_runner_parses_and_sorts(tmp_path, capsys):
    from dar_backup.manager import list_catalogs

    backup_def = "example"
    db_path = tmp_path / f"{backup_def}.db"
    db_path.touch()

    config = SimpleNamespace(backup_dir=tmp_path)
    stdout = "\n".join(
        [
            "archive #",
            "dar path",
            "1\t/path\tbdef_FULL_2025-01-02",
            "2\t/path\tadef_FULL_2025-01-03",
            "3\t/path\tadef_FULL_2025-01-01",
        ]
    )
    process = SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    with patch("dar_backup.manager.runner", new=SimpleNamespace(run=MagicMock(return_value=process))), \
         patch("dar_backup.manager.logger", new=MagicMock()):
        result = list_catalogs(backup_def, config)

    assert result.returncode == 0
    out_lines = capsys.readouterr().out.strip().splitlines()
    assert out_lines == [
        "adef_FULL_2025-01-01",
        "adef_FULL_2025-01-03",
        "bdef_FULL_2025-01-02",
    ]
    assert "bdef_FULL_2025-01-02" in result.stdout


def test_list_catalogs_success_subprocess_parses(tmp_path):
    import io
    from dar_backup.manager import list_catalogs

    backup_def = "example"
    db_path = tmp_path / f"{backup_def}.db"
    db_path.touch()

    config = SimpleNamespace(backup_dir=tmp_path, command_capture_max_bytes=1024)
    output = (
        b"1\t/path\tadef_FULL_2025-01-01\n"
        b"2\t/path\tbdef_FULL_2025-01-02\n"
    )

    class FakeProcess:
        def __init__(self):
            self.returncode = 0
            self.stdout = io.BytesIO(output)
            self.stderr = io.BytesIO(b"")

        def wait(self, timeout=None):
            return None

    with patch("dar_backup.manager.runner", new=SimpleNamespace(default_capture_limit_bytes=1024)), \
         patch("dar_backup.manager._open_command_log", return_value=(None, None)), \
         patch("dar_backup.manager.logger", new=MagicMock()), \
         patch("dar_backup.manager.subprocess.Popen", return_value=FakeProcess()):
        result = list_catalogs(backup_def, config, suppress_output=True)

    assert result.returncode == 0
    assert "adef_FULL_2025-01-01" in result.stdout


def test_get_db_dir_prefers_manager_db_dir():
    from dar_backup.manager import get_db_dir

    config = SimpleNamespace(manager_db_dir="/tmp/db", backup_dir="/tmp/backup")
    assert get_db_dir(config) == "/tmp/db"



def test_manager_db_dir_invalid_path_without_backup_def(env, setup_environment, tmp_path):
    """
    Negative test: MANAGER_DB_DIR is invalid and --backup-def is omitted; catalog creation should fail.
    """
    import shutil





    invalid_db_dir = tmp_path / "nonexistent" / "unwritable"

    with open(env.config_file, "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if line.strip() == "[DIRECTORIES]":
            insert_at = i + 1
            while insert_at < len(lines) and not lines[insert_at].startswith("["):
                insert_at += 1
            lines.insert(insert_at, f"MANAGER_DB_DIR = {invalid_db_dir}\n")
            break

    with open(env.config_file, "w") as f:
        f.writelines(lines)

    config_settings = ConfigSettings(env.config_file)
    assert config_settings.manager_db_dir == str(invalid_db_dir)

    # Ensure directory is gone
    shutil.rmtree(invalid_db_dir, ignore_errors=True)

    # Create one dummy backup def
    backup_def_file = Path(config_settings.backup_d_dir) / "example"
    Path(config_settings.backup_d_dir).mkdir(parents=True, exist_ok=True)
    backup_def_file.touch()

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['manager', '--create-db', '--config-file', env.config_file]
    process = runner.run(command)

    env.logger.debug(f"return code from 'db created': {process.returncode}")
    assert process.returncode != 0, "Expected failure due to invalid MANAGER_DB_DIR with no backup-def"
    env.logger.info("✅ Batch catalog creation failed as expected due to invalid MANAGER_DB_DIR")



def test_manager_creates_all_catalogs(env, setup_environment, tmp_path):
    """
    Positive test: When MANAGER_DB_DIR is valid, and multiple backup definitions exist,
    manager should create all catalogs successfully.
    """
    valid_db_dir = tmp_path / "valid_catalogs"
    valid_db_dir.mkdir(parents=True, exist_ok=True)

    with open(env.config_file, "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if line.strip() == "[DIRECTORIES]":
            insert_at = i + 1
            while insert_at < len(lines) and not lines[insert_at].startswith("["):
                insert_at += 1
            lines.insert(insert_at, f"MANAGER_DB_DIR = {valid_db_dir}\n")
            break

    with open(env.config_file, "w") as f:
        f.writelines(lines)

    config_settings = ConfigSettings(env.config_file)

    backup_defs = ["example1", "example2", "example3"]
    for name in backup_defs:
        Path(config_settings.backup_d_dir).mkdir(parents=True, exist_ok=True)
        (Path(config_settings.backup_d_dir) / name).touch()

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['manager', '--create-db', '--config-file', env.config_file]
    process = runner.run(command)

    env.logger.debug(f"return code from batch create-db: {process.returncode}")
    assert process.returncode == 0, "Expected successful creation of all catalogs"

    for name in backup_defs:
        db_file = valid_db_dir / f"{name}.db"
        assert db_file.exists(), f"Expected catalog DB to exist: {
            
            
            db_file}"
        env.logger.info(f"✅ Found created catalog DB: {db_file}")



def test_manager_skips_existing_catalogs(env, setup_environment, tmp_path):
    """
    Test that manager skips existing catalog databases and only creates missing ones.
    """

    valid_db_dir = tmp_path / "valid_db_dir"
    valid_db_dir.mkdir(parents=True, exist_ok=True)

    with open(env.config_file, "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if line.strip() == "[DIRECTORIES]":
            insert_at = i + 1
            while insert_at < len(lines) and not lines[insert_at].startswith("["):
                insert_at += 1
            lines.insert(insert_at, f"MANAGER_DB_DIR = {valid_db_dir}\n")
            break

    with open(env.config_file, "w") as f:
        f.writelines(lines)

    config_settings = ConfigSettings(env.config_file)

    Path(config_settings.backup_d_dir).mkdir(parents=True, exist_ok=True)
    backup_defs = ["alpha", "beta", "gamma"]
    for name in backup_defs:
        (Path(config_settings.backup_d_dir) / name).touch()

    # Pre-create one DB file to simulate prior successful creation
    pre_existing_db = valid_db_dir / "beta.db"
    pre_existing_db.touch()
    pre_mtime = pre_existing_db.stat().st_mtime

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['manager', '--create-db', '--config-file', env.config_file]
    process = runner.run(command)

    assert process.returncode == 0, "Expected successful catalog creation"

    for name in backup_defs:
        db_file = valid_db_dir / f"{name}.db"
        assert db_file.exists(), f"Expected DB to exist: {db_file}"
        env.logger.info(f"✅ Verified DB file: {db_file}")

    post_mtime = pre_existing_db.stat().st_mtime
    assert pre_mtime == post_mtime, "Pre-existing DB should not be overwritten"
    env.logger.info(f"✅ Pre-existing DB '{pre_existing_db}' was preserved as expected")
