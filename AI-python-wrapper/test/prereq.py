#!/usr/bin/env python3

import os
import shutil
import logging

UNIT_TEST_DIR = '/tmp/unit-test/'
BACKUP_DIR = os.path.join(UNIT_TEST_DIR, 'backups')
LOG_DIR = os.path.join(UNIT_TEST_DIR, 'logs')
CONF_DIR = os.path.join(UNIT_TEST_DIR, 'conf')
SRC_DIR = os.path.join(UNIT_TEST_DIR, 'src')

def setup_logging():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def create_directories():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(CONF_DIR, exist_ok=True)
    os.makedirs(SRC_DIR, exist_ok=True)

def copy_configuration_files():
    source_conf_file = os.path.join(os.path.dirname(__file__), 'backup_script.conf')
    target_conf_file = os.path.join(CONF_DIR, 'backup_script.conf')
    shutil.copyfile(source_conf_file, target_conf_file)

def setup_test_env(test_name):
    logging.info(f"Setting up test environment for {test_name}...")
    create_directories()
    copy_configuration_files()

    test_dir = os.path.join(UNIT_TEST_DIR, test_name)
    os.makedirs(test_dir, exist_ok=True)

    config_snippet_path = os.path.join(test_dir, 'backup.d')
    os.makedirs(config_snippet_path, exist_ok=True)

    config_file_path = os.path.join(CONF_DIR, 'backup_script.conf')

    return test_dir, config_snippet_path, config_file_path

def cleanup_test_env():
    logging.info("Cleaning up test environment...")
    if os.path.exists(UNIT_TEST_DIR):
        shutil.rmtree(UNIT_TEST_DIR)

def cleanup_dar_files():
    logging.info("Cleaning up existing .dar files...")
    if os.path.exists(BACKUP_DIR):
        for root, dirs, files in os.walk(BACKUP_DIR):
            for file in files:
                if file.endswith('.dar'):
                    os.remove(os.path.join(root, file))

if __name__ == "__main__":
    setup_logging()
    cleanup_test_env()
    setup_test_env('test-cleanup')
    cleanup_dar_files()
