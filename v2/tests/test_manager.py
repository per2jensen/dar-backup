"""
Test manager.py, that `dar` catalogs are created correctly
"""
import os
import re
import dar_backup.config_settings
import envdata
import test_bitrot

from datetime import date
from dar_backup.util import run_command
from dar_backup.config_settings import ConfigSettings
from envdata import EnvData
from typing import Dict, List


def test_manager_create_dbs(setup_environment: None, env: EnvData):
    """
    test that generated catalogs are created
    """
    config_settings = ConfigSettings(env.config_file)


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
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")
    

    [is_catalog(element, config_settings, env) for element in backup_definitions]

    env.logger.info(f"All generated backup definitions have catalog databases created")


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
    command = ['manager', '--version']
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


def test_manager_help(setup_environment: None, env: envdata.EnvData):
    command = ['manager', '--more-help']
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


def test_list_catalog_contents(setup_environment: None, env: EnvData):
    """
    Add a backup to it's catalog database, then list the contents
    """
    today_date = date.today().strftime("%Y-%m-%d")
    generate_catalog_db(env)
    files = generate_test_data_and_full_backup(env)

    command = ['manager', '--list-catalog-contents', '1', '-d', 'example', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = run_command(command)
    stdout, stderr = process.stdout, process.stderr
    env.logger.info(f"stdout:\n{stdout}")
    if process.returncode != 0:
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


    # Loop over the file names in the 'files' dictionary and verify they are present in stdout
    for file_name in files.keys():
        if file_name not in stdout:
            raise Exception(f"File name '{file_name}' not found in stdout")

    print("All file names are present in stdout")



def test_find_file(setup_environment: None, env: EnvData):
    """
    Add a backup to it's catalog database, then find some files in the catalog
    """
    
    ##
    ### Positive test
    ##
    today_date = date.today().strftime("%Y-%m-%d")
    generate_catalog_db(env)
    files = generate_test_data_and_full_backup(env)

    command = ['manager', '--list-catalog-contents', '1', '-d', 'example', '--config-file', env.config_file]
    process = run_command(command)
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
        process = run_command(command)
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
    process = run_command(command)
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
    ##
    ### Positive test
    ##
    today_date = date.today().strftime("%Y-%m-%d")
    generate_catalog_db(env)
    files = generate_test_data_and_full_backup(env)

    command = ['manager', '--add-specific-archive' ,f'example_FULL_{today_date}', '--config-file', env.config_file]
    process = run_command(command)
    if process.returncode != 0:
        print(f"stdout:\n{process.stdout}")  
        print(f"stderr:\n{process.stderr}")  
        raise Exception(f"Command failed: {command}")

    command = ['manager', '--remove-specific-archive' ,f'example_FULL_{today_date}', '--config-file', env.config_file, '--log-level', 'trace', '--log-stdout']
    process = run_command(command)

    assert process.returncode == 0, "Archive was not removed"

    command = ['manager', '--list-catalog' ,'-d', 'example', '--config-file', env.config_file, '--log-level', 'trace', '--log-stdout']
    process = run_command(command)
    print(process.stdout)


    ##
    ### Negative test
    ##
    non_existing_archive = "example_FULL_1970-01-01"
    command = ['manager', '--remove-specific-archive', non_existing_archive, '--config-file', env.config_file, '--log-level', 'trace', '--log-stdout']
    process = run_command(command)
    env.logger.debug(process)
    assert process.returncode != 0, "manager returned success removing a non-existing archive"




def test_list_catalog_contents_fail(setup_environment: None, env: EnvData):
    """
    verify failing if params given to the list catalog contents operation
    """
    command = ['manager', '--list-catalog-contents', 'test', '-d', 'example', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = run_command(command)
    env.logger.info(f"Return code: {process.returncode}")
    assert process.returncode == 2, "argument to --list-catalog-contents must be an integer"


    command = ['manager', '--list-catalog-contents', '1', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = run_command(command)
    env.logger.info(f"Return code: {process.returncode}")
    assert process.returncode == 1, "--list-catalog-contents requires --backup-def  option"

    command = ['manager', '--list-catalog-contents', '1', '-d' , '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = run_command(command)
    env.logger.info(f"Return code: {process.returncode}")
    assert process.returncode == 2, "argument to --backup-def must be given"



def test_add_directory_to_catalog_db(setup_environment: None, env: EnvData):
    command = ['manager', '--add-dir' , env.backup_dir, '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    run_manager_adding(command, env)



def test_add_empty_directory_to_catalog_db(setup_environment: None, env: EnvData):
    """
    Verify no error if adding a directory with no dar archives
    """
    command = ['manager', '--add-dir' , env.backup_dir, '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    generate_test_data_and_backup = False
    run_manager_adding(command, env, generate_test_data_and_backup)



def test_add_archive_to_catalog_db(setup_environment: None, env: EnvData):
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
    today_date = date.today().strftime("%Y-%m-%d")
    generate_catalog_db(env)
    if generate:
        generate_test_data_and_full_backup(env)

    command = ['manager', '--add-dir' , env.backup_dir, '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = run_command(command)
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")

    if not generate:
        if not re.search(f"No 'dar' archives found in directory", stdout):
            raise Exception(f"A note on no dar archives found should have been produced")
        env.logger.info(f"OK: Notice on no dar archives found was emitted")
        return


    # list catalogs
    command = ['manager', '--list-catalog' ,'--config-file', env.config_file]
    process = run_command(command)
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
    command = ['manager', '--create-db' ,'--config-file', env.config_file]
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


def generate_test_data_and_full_backup(env: envdata.EnvData) -> Dict:
    """
    Returns the Dict with file names as keys
    """
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
    process = run_command(command)
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        print(f"dar stdout: {stdout}")
        print(f"dar stderr: {stderr}")
        raise RuntimeError(f"dar-backup failed to create a full backup") 
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
