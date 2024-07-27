Sure! Here is the complete documentation of the script in Markdown format:

markdown

# Backup Script Documentation

This script allows you to create, verify, and manage backups using `dar` (Disk ARchive). It supports full and differential backups based on configuration snippets. Below you will find detailed documentation on the available options and how they interact.

## Index

1. [Configuration](#configuration)
2. [Usage](#usage)
3. [Options](#options)
4. [Examples](#examples)

## Configuration

Before using the script, ensure that the configuration file (`backup_script.conf`) is correctly set up. This configuration file should contain the following variables:

```ini
[DEFAULT]
LOGFILE_LOCATION=/tmp/backup_script.log
BACKUP_DIR=/tmp
TEST_RESTORE_DIR=/tmp/restore-test
BACKUP.D=/path/to/backup/configs

    LOGFILE_LOCATION: The location of the log file.
    BACKUP_DIR: The directory where backup archives will be stored.
    TEST_RESTORE_DIR: The directory where test restores will be performed.
    BACKUP.D: The directory containing the configuration snippets.

## Usage

The script can be run from the command line with various options to perform different tasks. Below are the available options and their descriptions.

### Options
-d, --backup-definition
Specifies the config snippet to use. The script will look for this config snippet in the directory specified by BACKUP.D in the configuration file.

--list
Lists available backups. By default, it lists both full and differential backups.

--restore <backup_file>
Restores a specific backup file. You can also specify the directory to restore files to using --restore-dir.

--restore-dir <restore_directory>
Specifies the directory to restore files to. If not provided, the directory specified by TEST_RESTORE_DIR in the configuration file will be used.

--selection <selection_criteria>
Specifies selection criteria for restoring specific files.


--list-contents <backup_file>
Lists the contents of a specific backup file.

--differential-backup
Performs a differential backup. If -d is specified, it performs a differential backup for that specific config snippet. Otherwise, it performs differential backups for all config snippets in the BACKUP.D directory.

# Examples
## List Available Backups

./backup_script.py --list

## Perform a Full Backup

./backup_script.py -d example_config_snippet

## Perform a Differential Backup

./backup_script.py --differential-backup -d example_config_snippet

## Restore a Specific Backup

./backup_script.py --restore example_FULL_2023-06-23 --restore-dir /path/to/restore/dir

## List Contents of a Specific Backup

./backup_script.py --list-contents example_FULL_2023-06-23

##How Options Interact

Full Backup: If you specify a backup definition with -d without the --differential-backup option, the script performs a full backup using the specified config snippet.
Differential 

Backup: If you specify the --differential-backup option with -d, the script performs a differential backup based on the latest full backup for the specified config snippet. If no full backup is found, it logs an error and skips the differential backup.

List Backups: The --list option lists all available backups, both full and differential. If combined with -d, it lists backups only for the specified config snippet.

Restore Backup: The --restore option restores a specified backup. If combined with --restore-dir, it restores the backup to the specified directory.

List Contents: The --list-contents option lists the contents of a specified backup file. It can be combined with --selection to list specific contents based on selection criteria.

This script is designed to provide a flexible and powerful way to manage your backups using dar. By understanding how these options interact, you can tailor the script to meet your specific backup and restore needs.