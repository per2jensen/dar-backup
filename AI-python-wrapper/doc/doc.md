# Backup Script Documentation
Index

    Introduction
    Script Options
        --config-dir
        --config-file
        --list
        --restore
        --restore-dir
        --selection
        --list-contents
    Examples of Usage
        Creating a Backup
        Listing Available Backups
        Restoring a Backup
        Listing Contents of a Backup
    Interaction Details
    Logging and Error Handling
    Configuration Files
        conf/backup_script.conf
        .darrc

# Introduction

This document provides detailed information on how to use the backup script, including descriptions of all available options, how they interact with each other, and examples of usage.

Documented by ChatGPT Copilot :-)

# Script Options
--config-dir

    Description: Specifies the directory containing configuration snippets for the backups.
    Usage: --config-dir /path/to/config/directory
    Interaction: If specified, the script will look for backup configuration snippets in the provided directory.

--config-file

    Description: Specifies a single configuration snippet file to use for the backup.
    Usage: --config-file /path/to/config/file
    Interaction: If specified, the script will use this specific configuration snippet for the backup. If both --config-dir and --config-file are provided, --config-file will be used for that particular backup instance.

--list

    Description: Lists all available backups in the backup directory.
    Usage: --list
    Interaction: This option will list the base names of all backup archives without including slice numbers or the .dar extension. It can be combined with --selection to filter the listed contents.

--restore

    Description: Restores a specific backup file.
    Usage: --restore backup_name
    Interaction: Requires the base name of the backup to restore. Can be combined with --restore-dir and --selection to specify the restore directory and filter which files to restore.

--restore-dir

    Description: Specifies the directory to restore files to.
    Usage: --restore-dir /path/to/restore/directory
    Interaction: Used with --restore to specify where the restored files should be placed. If not specified, a default directory from the configuration will be used.

--selection

    Description: Specifies criteria for selecting specific files or directories within a backup.
    Usage: --selection "criteria"
    Interaction: Can be used with --list, --restore, and --list-contents to filter specific files or directories based on the provided criteria.

--list-contents

    Description: Lists the contents of a specific backup file.
    Usage: --list-contents backup_name
    Interaction: Lists the contents of the specified backup archive, using the -am option to show detailed metadata.

# Examples of Usage

## Creating a Backup

To create a backup using a configuration snippet from a specified directory:

python3 backup_script.py --config-dir /path/to/config/directory


To create a backup using a specific configuration file:

python3 backup_script.py --config-file /path/to/config/file

## Listing Available Backups

To list all available backups in the backup directory:


python3 backup_script.py --list

## Restoring a Backup

To restore a specific backup to the default restore directory:


python3 backup_script.py --restore backup_name

## To restore a specific backup to a specified directory:


python3 backup_script.py --restore backup_name --restore-dir /path/to/restore/directory

## To restore specific files or directories from a backup:


python3 backup_script.py --restore backup_name --selection "criteria"

## Listing Contents of a Backup

To list the contents of a specific backup:


python3 backup_script.py --list-contents backup_name

## To list the contents of a specific backup with selection criteria:


python3 backup_script.py --list-contents backup_name --selection "criteria"

# Interaction Details

    --config-dir vs. --config-file: If both options are provided, --config-file takes precedence for that particular backup instance.
    --restore with --restore-dir: Specifies the directory to restore the files to. If not provided, the default restore directory from the configuration is used.
    --selection: Can be combined with --list, --restore, and --list-contents to filter specific files or directories within a backup.

# Logging and Error Handling

    Logging: All operations are logged to the file specified in the configuration.
    Error Handling: Errors during backup and restore operations are logged, and appropriate actions (continuing to the next config snippet or exiting) are taken as per the function's logic.

# Configuration Files

## conf/backup_script.conf


[DEFAULT]
LOGFILE_LOCATION=/tmp/backup_script.log
BACKUP_DIR=/path/to/backup
TEST_RESTORE_DIR=/path/to/restore-test

## .darrc

# Default configuration file for dar
# Place this file in the user's home directory as .darrc or specify it with the -B option

extract:
  --comparison-field=ignore-owner

compress-exclusion:
    *.gz
    *.bz2
    *.xz
    *.zip
    *.rar
    *.7z
    *.tar
    *.tgz
    *.tbz2
    *.txz
    *.jpg
    *.jpeg
    *.png
    *.gif
    *.bmp
    *.tiff
    *.svg
    *.mp4
    *.avi
    *.mkv
    *.mov
    *.wmv
    *.flv
    *.mpeg
    *.mpg

