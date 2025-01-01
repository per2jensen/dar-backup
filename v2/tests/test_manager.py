"""
Test manager.py, that `dar` catalogs are created correctly
"""
import os
import re
import dar_backup.config_settings
import envdata

from dar_backup.util import run_command


def generate_3_backup_defs(env, config_settings):
    """
    Generate 3 backup definitions
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
    command = ['manager', '--added-help']
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.communicate()
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")
