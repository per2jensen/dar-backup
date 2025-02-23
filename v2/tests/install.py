#!/usr/bin/env python3

"""
Install dar-backup.py parallel to the bash version
"""
import os
import shutil
import logging

INSTALL_DIR = os.path.expanduser(os.path.expandvars('~/programmer/dar-backup.py'))
ARCHIVES_DIR = os.path.join(INSTALL_DIR, 'archives')
BIN_DIR = os.path.join(INSTALL_DIR, 'bin')
CONF_DIR = os.path.join(INSTALL_DIR, 'conf')
BACKUP_D_DIR = os.path.join(INSTALL_DIR, 'backup.d')

print(f"BIN_DIR: {BIN_DIR}")


def create_directories():
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(ARCHIVES_DIR, exist_ok=True)
    os.makedirs(BIN_DIR, exist_ok=True)
    os.makedirs(BACKUP_D_DIR, exist_ok=True)
    os.makedirs(CONF_DIR, exist_ok=True)

def copy_bin_files():
    src_dir = os.path.join(os.path.dirname(__file__), '../src')
    for file in os.listdir(src_dir):
        if os.path.isfile(os.path.join(os.path.dirname(__file__), '../src', file)):
            shutil.copy(os.path.join(os.path.dirname(__file__), '../src', file), BIN_DIR)


if __name__ == "__main__":
    create_directories()
    copy_bin_files()
