#!/usr/bin/env python3

"""
Install dar-backup.py parallel to the bash version
"""
import os
import shutil
import logging

INSTALL_DIR = os.path.expanduser('~/programmer/dar-backup.py')
ARCHIVES_DIR = os.path.join(INSTALL_DIR, 'archives')
BIN_DIR = os.path.join(INSTALL_DIR, 'bin')
CONF_DIR = os.path.join(INSTALL_DIR, 'conf')
BACKUP_D_DIR = os.path.join(INSTALL_DIR, 'backup.d')


def create_directories():
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(ARCHIVES_DIR, exist_ok=True)
    os.makedirs(BIN_DIR, exist_ok=True)
    os.makedirs(BACKUP_D_DIR, exist_ok=True)
    os.makedirs(CONF_DIR, exist_ok=True)

def copy_bin_files():
    shutil.copy(os.path.join(os.path.dirname(__file__), '../src/dar-backup.py'), BIN_DIR)
    shutil.copy(os.path.join(os.path.dirname(__file__), '../src/cleanup.py'), BIN_DIR)


if __name__ == "__main__":
    create_directories()
    copy_bin_files()
