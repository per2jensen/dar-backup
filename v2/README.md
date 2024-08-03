# config file

The default configuration is located here: ~/.config/dar-backup/dar-backup.conf

# How to run 

1.
Config file default location is $HOME/.config/dar-backup/dar-backup.conf
Example:
````
[MISC]
LOGFILE_LOCATION=/home/user/dar-backup.log
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 1
NO_FILES_VERIFICATION = 5

[DIRECTORIES]
BACKUP_DIR = /home/user/mnt/dir/
BACKUP.D_DIR = /home/user/.config/dar-backup/backup.d/
TEST_RESTORE_DIR = /tmp/dar-backup/restore/

[AGE]
# age settings are in days
DIFF_AGE = 100
INCR_AGE = 40

[PAR2]
ERROR_CORRECTION_PERCENT = 5

[PREREQ]
SCRIPT_1 = /home/user/programmer/dar-backup/prereq/mount-microserver.sh
# SCRIPT_2 = <something>
# more here if necessary
````    

2.
Installation is currently in a venv. These commands are installed in the venv:
- dar-back
- cleanup

I have an alias in ~/.bashrc
````    
alias db=". ~/programmer/dar-backup.py/venv/bin/activate; dar-backup -v"
````    

Typing `db` at the command line gives this
````    
(venv) user@machine:~$ db
dar-backup alpha-0.4
dar-backup.py source code is here: https://github.com/per2jensen/dar-backup
Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.
````

`dar-backup -h` gives the usage output:
````
(venv) user@machine:~$ dar-backup -h
usage: dar-backup [-h] [--full-backup] [--differential-backup] [--incremental-backup] [-d BACKUP_DEFINITION]
                  [--config-file CONFIG_FILE] [--examples] [--list] [--list-contents LIST_CONTENTS]
                  [--selection SELECTION] [--restore RESTORE] [--restore-dir RESTORE_DIR] [--verbose]
                  [--log-level LOG_LEVEL] [--do-not-compare] [--version]

Backup and verify using dar backup definitions.

options:
  -h, --help            show this help message and exit
  --full-backup         Perform a full backup.
  --differential-backup
                        Perform differential backup.
  --incremental-backup  Perform incremental backup.
  -d BACKUP_DEFINITION, --backup-definition BACKUP_DEFINITION
                        Specific 'recipe' to select directories and files.
  --config-file CONFIG_FILE, -c CONFIG_FILE
                        Path to 'dar-backup.conf'
  --examples            Examples of using dar-backup.py.
  --list                List available archives.
  --list-contents LIST_CONTENTS
                        List the contents of the specified archive.
  --selection SELECTION
                        dar file selection for listing/restoring specific files/directories.
  --restore RESTORE     Restore specified archive.
  --restore-dir RESTORE_DIR
                        Directory to restore files to.
  --verbose             Print various status messages to screen
  --log-level LOG_LEVEL
                        `debug` or `trace`
  --do-not-compare      do not compare restores to file system
  --version, -v         Show version information.
````    

3.
You are ready to do backups of all your backup definitions, if your backup definitions are 
in place in BACKUP.D_DIR (see config file)
````    
dar-backup --full-backup 
````    

or a backup of a single definition
````    
dar-backup --full-backup -d <your backup definition>
````    




# list contents of an archive
```
. <the virtual evn>/bin/activate
dar-backup --list-contents example --selection "-X '*.xmp' -I '*2024-06-16*' -g home/pj/tmp/LUT-play"
deactivate
```
gives
```
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root	root	113 Mio	Sat May 11 16:16:48 2024	home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 10:46:30 2024	home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 09:17:42 2024	home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj	pj	50 Mio	Wed Jun 19 20:52:13 2024	home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj	pj	49 Mio	Sun Jun 16 12:52:22 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
```




# dar file selection exmaples

## select a directory
```
dar -l /tmp/example_FULL_2024-06-23  -g home/pj/tmp/LUT-play
```
gives
```
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root	root	113 Mio	Sat May 11 16:16:48 2024	home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 10:46:30 2024	home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 09:17:42 2024	home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj	pj	50 Mio	Wed Jun 19 20:52:13 2024	home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj	pj	49 Mio	Sun Jun 16 12:52:22 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	48 kio	Sat Jun 22 21:51:24 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	50 kio	Sat Jun 22 21:51:25 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_01.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:26 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_02.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:27 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_03.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:27 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_04.NEF.xmp
[Saved][ ]       [-L-][  97%][ ]  -rw-rw-r--   pj	pj	77 kio	Sat Jun 22 21:50:16 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_05.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	52 kio	Sat Jun 22 21:49:37 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_06.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:47 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_07.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:12 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_08.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:12 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_09.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:39 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_10.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:36 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_11.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:35 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_12.NEF.xmp
[Saved][ ]       [-L-][  88%][ ]  -rw-rw-r--   pj	pj	15 kio	Sat Jun 22 21:51:11 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_13.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj	pj	84 kio	Sat Jun 22 21:51:09 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_14.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj	pj	90 kio	Sat Jun 22 21:51:04 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_15.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:15 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_16.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:48 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_17.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:19 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_18.NEF.xmp
```


## select file dates in the directory:
```
dar -l /tmp/example_FULL_2024-06-23  -I '*2024-06-16*' -g home/pj/tmp/LUT-play
```
gives
```
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root	root	113 Mio	Sat May 11 16:16:48 2024	home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 10:46:30 2024	home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 09:17:42 2024	home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj	pj	50 Mio	Wed Jun 19 20:52:13 2024	home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj	pj	49 Mio	Sun Jun 16 12:52:22 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	48 kio	Sat Jun 22 21:51:24 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	50 kio	Sat Jun 22 21:51:25 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_01.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:26 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_02.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:27 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_03.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:27 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_04.NEF.xmp
[Saved][ ]       [-L-][  97%][ ]  -rw-rw-r--   pj	pj	77 kio	Sat Jun 22 21:50:16 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_05.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	52 kio	Sat Jun 22 21:49:37 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_06.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:47 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_07.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:12 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_08.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:12 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_09.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:39 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_10.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:36 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_11.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:35 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_12.NEF.xmp
[Saved][ ]       [-L-][  88%][ ]  -rw-rw-r--   pj	pj	15 kio	Sat Jun 22 21:51:11 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_13.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj	pj	84 kio	Sat Jun 22 21:51:09 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_14.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj	pj	90 kio	Sat Jun 22 21:51:04 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_15.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:15 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_16.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:48 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_17.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:19 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_18.NEF.xmp
```

## exclude .xmp files from that date
```
dar -l /tmp/example_FULL_2024-06-23 -X '*.xmp' -I '*2024-06-16*' -g home/pj/tmp/LUT-play
```
gives
```
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root	root	113 Mio	Sat May 11 16:16:48 2024	home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 10:46:30 2024	home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 09:17:42 2024	home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj	pj	50 Mio	Wed Jun 19 20:52:13 2024	home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj	pj	49 Mio	Sun Jun 16 12:52:22 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
```

Nice :-)



# Restoring

## a single file
```
. <the virtual env>/bin/activate
# the path/to/file is relative to the Root when the backup was taken
dar-backup --restore <archive_name> --selection "-g path/to/file"
deactivate
```

## .NEF from a specific date
```
. <the virtual env>/bin/activate
# the path/to/file is relative to the Root when the backup was taken
dar-backup --restore <archive_name>  --selection "-X '*.xmp' -I '*2024-06-16*' -g home/pj/tmp/LUT-play"
deactivate
```



