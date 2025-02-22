# Full, differential or incremental backups using 'dar' 

  The wonderful 'dar' [Disk Archiver] (https://github.com/Edrusb/DAR) is used for
  the heavy lifting, together with the par2 suite in these scripts.

## Table of Contents

- [Full, differential or incremental backups using 'dar'](#full-differential-or-incremental-backups-using-dar)
- [My use case](#my-use-case)
- [License](#license)
- [Status](#status)
  - [Breaking change in version 0.6.0](#breaking-change-in-version-060)
- [Homepage - Github](#homepage---github)
- [Requirements](#requirements)
- [Config file](#config-file)
- [How to run](#how-to-run)
  - [1](#1)
  - [2](#2)
  - [3](#3)
  - [4](#4)
  - [5](#5)
  - [6](#6)
- [.darrc](#darrc)
- [Systemctl examples](#systemctl-examples)
  - [Service: dar-back --incremental-backup](#service-dar-back---incremental-backup)
  - [Timer: dar-back --incremental-backup](#timer-dar-back---incremental-backup)
- [List contents of an archive](#list-contents-of-an-archive)
- [dar file selection examples](#dar-file-selection-examples)
  - [Select a directory](#select-a-directory)
  - [Select file dates in the directory](#select-file-dates-in-the-directory)
  - [Exclude .xmp files from that date](#exclude-xmp-files-from-that-date)
- [Restoring](#restoring)
  - [Default location for restores](#default-location-for-restores)
  - [--restore-dir option](#restore-dir-option)
  - [A single file](#a-single-file)
  - [A directory](#a-directory)
  - [.NEF from a specific date](#nef-from-a-specific-date)
- [Points of interest](#points-of-interest)
  - [dar manager databases](#dar-manager-databases)
  - [.darrc sets -vd -vf (since v0.6.4)](#darrc-sets--vd--vf-since-v064)
- [Reference](#reference)
  - [dar-backup.py](#dar-backuppy)
  - [manager.py](#managerpy)
  - [cleanup.py](#cleanuppy)
  - [clean-log.py](#clean-logpy)

## My use case

I have cloud storage mounted on a directory within my home dir. The filesystem is [FUSE based](https://www.kernel.org/doc/html/latest/filesystems/fuse.html), which gives it a few special features

- a non-privileged user (me :-)) can perform a mount
- a privileged user cannot look into the filesystem --> a backup script running as root is not suitable

 I needed the following:

- Backup my cloud storage to something local (cloud is convenient, but I want control over my backups)
- Backup primarily photos, video and different types of documents
- Have a simple non-complicated way of restoring, possibly years into the future. 'dar' fits that scenario with a single statically linked binary (kept with the archives). There is no need install/configure anything - restoring is simple and works well.
- During backup archives must be tested and a restore test (however small) performed
- Archives stored on a server with a reliable file system (easy to mount a directory over sshfs)
- Easy to verify archive's integrity, after being moved around.

 I do not need the encryption features of dar, as all storage is already encrypted.

## License

  These scripts are licensed under the GPLv3 license.
  Read more here: https://www.gnu.org/licenses/gpl-3.0.en.html, or have a look at the ["LICENSE"](https://github.com/per2jensen/dar-backup/blob/main/LICENSE) file in this repository.

## Status

As of August 8, 2024 I am using the alpha versions of `dar-backup` (alpha-0.5.9 onwards) in my automated backup routine.

As of February 13, 2025, I have changed the status from alpha --> beta, as the featureset is in place and the alphas have worked well for a very long time.

### Breaking change in version 0.6.0

Version 0.6.0 and forwards requires the config variable *COMMAND_TIMEOUT_SECS* in the config file.

## Homepage - Github

This 'dar-backup' package lives at: https://github.com/per2jensen/dar-backup/tree/main/v2

This python version is v2 of dar-backup, the first is made in bash.

## Requirements

- dar
- par2
- python3 :-)

On Ubuntu, install the requirements this way:

```` bash
    sudo apt install dar par2 python3
````

## Config file

The default configuration is expected here: ~/.config/dar-backup/dar-backup.conf

## How to run 

### 1

Config file default location is $HOME/.config/dar-backup/dar-backup.conf

Example:

```` code
[MISC]
LOGFILE_LOCATION=/home/user/dar-backup.log
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 1
NO_FILES_VERIFICATION = 5

# timeout in seconds for backup, test, restore and par2 operations
# The author has such `dar` tasks running for 10-15 hours on the yearly backups, so a value of 24 hours is used.
# If a timeout is not specified when using the util.run_command(), a default timeout of 30 secs is used.
COMMAND_TIMEOUT_SECS = 86400

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
# False means "do not generate par2 redundancy files"
ENABLED = True  

[PREREQ]
# SCRIPT_1 = /home/user/programmer/dar-backup/prereq/mount-server.sh
# SCRIPT_2 = <something>
# ...

[POSTREQ]
# SCRIPT_1 = /home/user/programmer/dar-backup/postreq/umount-server.sh
# SCRIPT_2 = <something>
# ...

````

### 2

Put your backup definitions in the directory $BACKUP.D_DIR (defined in the config file)

The name of the file is the `backup definition` name.

Make as many backup definitions as you need. Run them all in one go, or run one at a time using the `-d` option.

The `dar` [documentation](http://dar.linux.free.fr/doc/man/dar.html#COMMANDS%20AND%20OPTIONS) has good information on file selection.

Example of backup definition for a home directory

```` code

# Switch to ordered selection mode, which means that the following
# options will be considered top to bottom
 -am


# Backup Root dir
 -R /home/user

# Directories to backup below the Root dir
# if you want to take a backup of /home/user/Documents only, uncomment next line
#  -g Documents 

# Some directories to exclude below the Root dir (here Root directory is `/home/user` as set in the -R option)
 -P mnt
 -P tmp
 -P .cache
 -P .config/Code/CachedData
 -P .config/Code/Cache
 -P ".config/Code/Service Worker"
 -P .config/Code/logs
 -P snap/firefox/common/.cache
 
# compression level
 -z5

 # no overwrite, if you rerun a backup, 'dar' halts and asks what to do (and Quits due to the "-Q" given by dar-backup)
 -n
 
 # size of each slice in the archive
 --slice 10G


# bypass directores marked as cache directories
# http://dar.linux.free.fr/doc/Features.html
--cache-directory-tagging
````

### 3

Installation is currently in a venv. These commands are installed in the venv:

- dar-back
- cleanup
- manager
- clean-log

To install, create a venv and run pip:

```` bash
mkdir $HOME/tmp
cd $HOME/tmp
python3 -m venv venv    # create the virtual environment 
. venv/bin/activate     # activate the virtual env
pip install dar-backup  # run pip to install `dar-backup`
````

I have an alias in ~/.bashrc pointing to my venv:

```` bash
alias db=". ~/tmp/venv/bin/activate; dar-backup -v"
````

Typing `db` at the command line gives this

```` bash
(venv) user@machine:~$ db
dar-backup 0.6.9
dar-backup.py source code is here: https://github.com/per2jensen/dar-backup
Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.
````

### 4

Generate the archive catalog database(s). 
`dar-backup` expects the catalog databases to be in place, it does not automatically create them (by design)

```` bash
manager --create-db
````

### 5

You are ready to do backups of all your backup definitions, if your backup definitions are 
in place in BACKUP.D_DIR (see config file)

```` bash
dar-backup --full-backup 
````

If you want to see dar-backup's log entries in the terminal, use the `--log-stdout` option. This is also useful if dar-backup is started by systemd.

If you want more log messages, use the `--log-level debug` option.

If you want a backup of a single definition, use the `-d <backup definition>` option. The definition's name is the filename of the definition in the `backup.d` config directory.

```` bash
dar-backup --full-backup -d <your backup definition>
````

### 6

Deactivate the virtual environment

```` bash
deactivate
````

## .darrc

The package includes a default `.darrc` file which configures `dar`.

You can override the default `.darrc` using the `--darrc` option.

The default `.darrc` contents are as follows:

```` code
#  .darrc configuration file for `dar` as used by the `dar-backup` script.
#  `dar-backup` lives here: https://github.com/per2jensen/dar-backup


##############################################################

#  target: verbose

#  remove comments belov for dar being more verbose

verbose:

# shows files teated due to filtering inclusion or no filtering at all

# -vt

# shows skipped files du to exclusion

# -vs

# shows diretory currently being processed
# dar-backup logs `dar` stdout in real time, so directories being processed are now shown in the log file.
# this is quite useful in long running jobs
 -vd 

# shows detailed messages, not related to files and directories
# -vm

# shows summary of each treated directory, including average compression
# dar-backup logs `dar` stdout in real time, so directories being processed are now shown in the log file.
# this is quite useful in long running jobs
 -vf

# equivalent to "-vm -vs -vt"
# -va


restore-options:
# don't restore File Specific Attributes
#--fsa-scope none

# ignore owner, useful when used by a non-privileged user
--comparison-field=ignore-owner


# Exclude specific file types from compression
compress-exclusion:

# First setting case insensitive mode on:
-an
-ag

-Z    "*.gz"
-Z    "*.bz2"
-Z    "*.xz"
-Z    "*.zip"
-Z    "*.rar"
-Z    "*.7z"
-Z    "*.tar"
-Z    "*.tgz"
-Z    "*.tbz2"
-Z    "*.txz"
# Exclude common image file types from compression
-Z    "*.jpg"
-Z    "*.jpeg"
-Z    "*.png"
-Z    "*.gif"
-Z    "*.bmp"
-Z    "*.tiff"
-Z    "*.svg"
-Z    "*.ico"
-Z    "*.webp"
# The author uses Nikon compressed NEFs raw files
-Z    "*.NEF"
# Exclude common movie file types from compression
-Z    "*.mp4"
-Z    "*.avi"
-Z    "*.mkv"
-Z    "*.mov"
-Z    "*.wmv"
-Z    "*.flv"
-Z    "*.mpeg"
-Z    "*.mpg"

# These are zip files. Not all are compressed, but considering that they can
# get quite large it is probably more prudent to leave this uncommented.
-Z    "*.pk3"
-Z    "*.zip"

-Z    "*.lz4"
-Z    "*.zoo"

-Z    "*.Po"
-Z    "*.aar"
-Z    "*.bx"
-Z    "*.chm"
-Z    "*.doc"
-Z    "*.epub"
-Z    "*.f3d"
-Z    "*.gpg"
-Z    "*.htmlz"
-Z    "*.iix"
-Z    "*.iso"
-Z    "*.jin"
-Z    "*.ods"
-Z    "*.odt"
-Z    "*.ser"
-Z    "*.svgz"
-Z    "*.swx"
-Z    "*.sxi"
-Z    "*.whl"
-Z    "*.wings"


# Dar archives (may be compressed).
-Z    "*.dar"

# Now we swap back to case sensitive mode for masks which is the default
#mode:
-acase
````

## Systemctl examples

I have dar-backup scheduled to run via systemd --user settings.

The files are located in: ~/.config/systemd/user

Once the .service and .timer files are in place, timers must be enabled and started.

```` bash
systemctl --user enable dar-inc-backup.timer
systemctl --user start  dar-inc-backup.timer
systemctl --user daemon-reload
````

Verify your timers are set up as you want:

```` bash
systemctl --user list-timers
````

## Service: dar-back --incremental-backup

File:  dar-inc-backup.service

```` code
[Unit]
Description=dar-backup INC
StartLimitIntervalSec=120
StartLimitBurst=1
[Service]
Type=oneshot
TimeoutSec=infinity
RemainAfterExit=no
ExecStart=/bin/bash -c '. /home/user/programmer/dar-backup.py/venv/bin/activate && dar-backup --incremental-backup --verbose'
````

## Timer: dar-back --incremental-backup

File:  dar-inc-backup.timer

```` code
[Unit]
Description=dar-backup INC timer

[Timer]
OnCalendar=*-*-04/3 19:03:00
Persistent=true

[Install]
WantedBy=timers.target
````

## list contents of an archive

```` bash
. <the virtual evn>/bin/activate
dar-backup --list-contents example_FULL_2024-06-23 --selection "-X '*.xmp' -I '*2024-06-16*' -g home/pj/tmp/LUT-play"
deactivate
````

gives

``` code
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root	root	113 Mio	Sat May 11 16:16:48 2024	home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 10:46:30 2024	home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 09:17:42 2024	home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj	pj	50 Mio	Wed Jun 19 20:52:13 2024	home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj	pj	49 Mio	Sun Jun 16 12:52:22 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
```

## dar file selection exmaples

### select a directory

``` bash
dar -l /tmp/example_FULL_2024-06-23  -g home/pj/tmp/LUT-play
```

gives

```` code
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
````

### select file dates in the directory:

``` bash
dar -l /tmp/example_FULL_2024-06-23  -I '*2024-06-16*' -g home/pj/tmp/LUT-play
```

gives

``` code
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

### exclude .xmp files from that date

``` bash
dar -l /tmp/example_FULL_2024-06-23 -X '*.xmp' -I '*2024-06-16*' -g home/pj/tmp/LUT-play

```

gives

``` code
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root	root	113 Mio	Sat May 11 16:16:48 2024	home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 10:46:30 2024	home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 09:17:42 2024	home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj	pj	50 Mio	Wed Jun 19 20:52:13 2024	home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj	pj	49 Mio	Sun Jun 16 12:52:22 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
```

Nice :-)

## Restoring

### default location for restores

dar-backup will use the TEST_RESTORE_DIR location as the Root for restores, if the --restore-dir option has not been supplied.

See example below to see where files are restored to.

### --restore-dir option

When the --restore-dir option is used for restoring, a directory must be supplied.

The directory supplied functions as the Root of the restore operation.

**Example**:

A backup has been taken using this backup definition:

``` code
-R /
-g home/user/Documents
```

When restoring and using `/tmp` for --restore-dir, the restored files can be found in `/tmp/home/user/Documents`

### a single file

``` code
. <the virtual env>/bin/activate
dar-backup --restore <archive_name> --selection "-g path/to/file"
deactivate

```

### a directory

``` bash
. <the virtual env>/bin/activate
dar-backup --restore <archive_name> --selection "-g path/to/directory"
deactivate
```

### .NEF from a specific date

``` bash
. <the virtual env>/bin/activate
dar-backup --restore <archive_name>  --selection "-X '*.xmp' -I '*2024-06-16*' -g home/pj/tmp/LUT-play"
deactivate
```

## Points of interest

### dar manager databases

`dar-backup` now saves archive catalogs in dar catalog databases.

This makes it easier to restore to a given date when having many FULL, DIFF and INCR archives.

### .darrc sets -vd -vf (since v0.6.4)

These .darrc settings make `dar` print the current directory being processed (-vd) and some stats after (-vf)
This is very useful in very long running jobs to get an indication that the backup is proceeding normally.

if --log-stdout is used the information would be picked up by systemd and logged by journald.½

The log file can get quite cluttered, if you want the clutter to be removed, run the `clean-log`script.

## Reference

### dar-backup.py

This script is responsible for managing the backup creation and validation process. It supports the following options:

``` code
--full-backup                     Perform a full backup.
--differential-backup             Perform a differential backup.
--incremental-backup              Perform an incremental backup.
--backup-definition <name>        Specify the backup definition file.
--alternate-reference-archive <file>  Use a different archive for DIFF/INCR backups.
--config-file <path>              Specify the path to the configuration file.
--darrc <path>                    Specify an optional path to .darrc.
--examples                        Show examples of using dar-backup.py.
--list                            List available backups.
--list-contents <archive>         List the contents of a specified archive.
--selection <params>              Define file selection for listing/restoring.
--restore <archive>               Restore a specified archive.
--restore-dir <path>              Directory to restore files to.
--verbose                         Enable verbose output.
--log-level <level>               Set log level (debug, trace, etc.).
--log-stdout                      Also print log messages to stdout.
--do-not-compare                  Do not compare restores to file system.
--version                         Show version and license information.
```

### manager.py

This script manages `dar` databases and catalogs. Available options include:

``` code
--create-db                     Create missing databases for all backup definitions.
--alternate-archive-dir <path>   Use this directory instead of BACKUP_DIR in the config file.
--add-dir <path>                 Add all archive catalogs in this directory to databases.
-d, --backup-def <name>          Restrict to work only on this backup definition.
--add-specific-archive <file>    Add this archive to the catalog database.
--remove-specific-archive <file> Remove this archive from the catalog database.
-l, --list-catalogs              List catalogs in databases for all backup definitions.
--list-catalog-contents <num>    List contents of a catalog by archive number.
--list-archive-contents <file>   List contents of an archive’s catalog.
--find-file <file>               Search catalogs for a specific file.
--verbose                        Enable verbose output.
--log-level <level>              Set log level.
```

### cleanup.py

This script cleans up old backups and manages storage. Supported options:

``` code
--prune-older-than <days>   Remove backups older than the specified number of days.
--keep-last <num>           Retain only the last <num> backups.
--dry-run                   Show what would be deleted without actually deleting.
--backup-dir <path>         Specify the backup directory.
--verbose                   Enable verbose output.
--help                      Show this help message and exit.
```

### clean-log.py

This script removes excessive logging output from `dar` logs, improving readability and efficiency. Available options:

``` code
-f, --file <path>          Specify the log file(s) to be cleaned.
-c, --config-file <path>   Specify the configuration file (default: ~/.config/dar-backup/dar-backup.conf).
--dry-run                  Show which lines would be removed without modifying the file.
-v, --version              Display version and licensing information.
```
