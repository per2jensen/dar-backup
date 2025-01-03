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



def generate_3_backup_defs(env, config_settings):
    """
    Generate 3 dummy backup definitions
    """
    for i in range(3):
        backup_def = f"test{i}"
        with open(os.path.join(config_settings.backup_d_dir, backup_def), "a") as f:
            f.write('dummy data\n')



def test_manager_create_dbs(setup_environment, env):
    """
    Test 3 catalogs are created
    """
    config_settings = dar_backup.config_settings.ConfigSettings(env.config_file)


    # remove any existing catalogs
    for root, dirs, files in os.walk(config_settings.backup_dir):
        for file in files:
            if re.search(r".db", file):
                os.remove(os.path.join(config_settings.backup_dir, file))   


    # remove any existing backup definitions
    for root, dirs, files in os.walk(config_settings.backup_d_dir):
        for file in files:
                os.remove(os.path.join(config_settings.backup_d_dir, file))   


    generate_3_backup_defs(env, config_settings)

    # generate databases for catalogs for all backup definitions
    command = ['manager', '--create-db' ,'--config-file', env.config_file]
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.communicate()
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")
    

    for root, dirs, files in os.walk(config_settings.backup_d_dir):
        for file in files:
            if not os.path.exists(os.path.join(config_settings.backup_dir, f"{file}.db")):
                raise Exception(f"Catalog not created for backup definition '{file}'")


def test_manager_version(setup_environment, env):
    command = ['manager', '--version']
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.communicate()
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


def test_manager_help(setup_environment, env):
    command = ['manager', '--more-help']
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.communicate()
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


def test_manager_add_specific_archive(setup_environment, env):

    today_date = date.today().strftime("%Y-%m-%d")

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
    stdout,stderr = process.communicate()
    if process.returncode != 0:
        print(f"dar stdout: {stdout}")
        print(f"dar stderr: {stderr}")
        raise RuntimeError(f"dar-backup failed to create a full backup")
    

    # generate database for catalogs
    command = ['manager', '--create-db' ,'--config-file', env.config_file]
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.communicate()
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")
  
    # add archive to catalog
    command = ['manager', '--add-specific-archive' ,f'example_FULL_{today_date}', '--config-file', env.config_file, '--log-level', "trace"]
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.communicate()
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")

    # list catalogs
    command = ['manager', '--list-db' ,'--config-file', env.config_file]
    process = run_command(command)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")

    print(f"stdout: {stdout}")

    if not re.search(f"example_FULL_{today_date}", stdout):
        raise Exception(f"Catalog not found for backup definition f'example_FULL_{today_date}'")

    print(f"Catalog for example_FULL_{today_date}.1.dar found in example.db")  

