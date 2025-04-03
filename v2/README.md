<!-- markdownlint-disable MD024 -->
# Full, differential or incremental backups using 'dar'

[![codecov](https://codecov.io/gh/per2jensen/dar-backup/branch/main/graph/badge.svg)](https://codecov.io/gh/per2jensen/dar-backup)

The wonderful 'dar' [Disk Archiver](https://github.com/Edrusb/DAR) is used for
the heavy lifting, together with the par2 suite in these scripts.

This is the `Python` based **version 2** of `dar-backup`.

## Table of Contents

- [Full, differential or incremental backups using 'dar'](#full-differential-or-incremental-backups-using-dar)
- [My use case](#my-use-case)
- [License](#license)
- [Status](#status)
  - [GPG Signing key](#gpg-signing-key)
  - [Breaking change in version 0.6.0](#breaking-change-in-version-060)
- [Homepage - Github](#homepage---github)
- [Requirements](#requirements)
- [Principles](#dar-backup-principles)
- [How to run](#how-to-run)
  - [1 - installation](#1---installation)
  - [2 - configuration](#2---configuration)
  - [3 - generate catalog databases](#3---generate-catalog-databases)
  - [4 - do FULL backups](#4---do-full-backups)
  - [5 - deactivate venv](#5---deactivate-venv)
- [Config](#config)
  - [Config file](#config-file)
  - [.darrc](#darrc)
  - [Backup definition](#backup-definition-example)
- [Systemd examples](#systemctl-examples)
  - [Generate systemd files](#generate-systemd-files)
  - [Service: dar-back --incremental-backup](#service-dar-backup---incremental-backup)
  - [Timer: dar-back --incremental-backup](#timer-dar-backup---incremental-backup)
- [List contents of an archive](#list-contents-of-an-archive)
- [dar file selection examples](#dar-file-selection-examples)
  - [Select a directory](#select-a-directory)
  - [Select file dates in the directory](#select-file-dates-in-the-directory)
  - [Exclude .xmp files from that date](#exclude-xmp-files-from-that-date)
- [Restoring](#restoring)
  - [Default location for restores](#default-location-for-restores)
  - [--restore-dir option](#--restore-dir-option)
  - [A single file](#a-single-file)
  - [A directory](#a-directory)
  - [.NEF from a specific date](#nef-from-a-specific-date)
  - [Restore test fails with exit code 4](#restore-test-fails-with-exit-code-4)
  - [Restore test fails with exit code 5](#restore-test-fails-with-exit-code-5)
- [Par2](#par2)
  - [Par2 to verify/repair](#par2-to-verifyrepair)
  - [Par2 create redundancy files](#par2-create-redundancy-files)
- [Points of interest](#points-of-interest)
  - [Merge FULL with DIFF, creating new FULL](#merge-full-with-diff-creating-new-full)
  - [dar manager databases](#dar-manager-databases)
  - [Performance tip due to par2](#performance-tip-due-to-par2)
  - [.darrc sets -vd -vf (since v0.6.4)](#darrc-sets--vd--vf-since-v064)
  - [Separate log file for command output](#separate-log-file-for-command-output)
  - [Skipping cache directories](#skipping-cache-directories)
  - [Progress bar + current directory](#progress-bar-and-current-directory)
- [Todo](#todo)
- [Reference](#reference)
  - [Test coverage report](#test-coverage)
  - [dar-backup](#dar-backup-options)
  - [manager](#manager-options)
  - [cleanup](#cleanup-options)
  - [clean-log](#clean-log-options)
  - [installer](#installer-options)
  - [dar-backup-systemd](#dar-backup-systemd)
  
## My use case

I have cloud storage mounted on a directory within my home dir. The filesystem is [FUSE based](https://www.kernel.org/doc/html/latest/filesystems/fuse.html), which gives it a few special features

- a non-privileged user can perform a mount
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
  Read more here: [GNU CPL 3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), or have a look at the ["LICENSE"](https://github.com/per2jensen/dar-backup/blob/main/LICENSE) file in this repository.

## Status

As of August 8, 2024 I am using the alpha versions of `dar-backup` (alpha-0.5.9 onwards) in my automated backup routine.

As of February 13, 2025, I have changed the status from alpha --> beta, as the featureset is in place and the alphas have worked well for a very long time.

### GPG Signing key

To increase the security and authenticity of dar-backup packages, all releases from v2-beta-0.6.18 onwards will be digitally signed using the GPG key below.

🔐 GPG Signing Key Details

```` text
Name:        Per Jensen (author of dar-backup)
Email:       dar-backup@pm.me
Primary key: 4592 D739 6DBA EFFD 0845  02B8 5CCE C7E1 6814 A36E
Signing key: B54F 5682 F28D BA36 22D7  8E04 58DB FADB BBAC 1BB1
Created:     2025-03-29
Expires:     2030-03-28
Key type:    ed25519 (primary, SC)  
Subkeys:     ed25519 (S), ed25519 (A), cv25519 (E)
````

🔏 Where to Find Release Signatures

PyPI does *Not* host .asc Signature Files

Although the `dar-backup` packages on PyPI are GPG-signed, PyPI itself does **not support uploading** .asc detached signature files alongside `.whl` and `.tar.gz` artifacts.

Therefore, you will not find `.asc` files on PyPI.

✅ Where to Get `.asc` Signature Files

You can always download the signed release artifacts and their `.asc` files from the official GitHub Releases page:

📁 GitHub Releases for `dar-backup`

Each release includes:

- `dar_backup-x.y.z.tar.gz`

- `dar_backup-x.y.z.tar.gz.asc`

- `dar_backup-x.y.z-py3-none-any.whl`

- `dar_backup-x.y.z-py3-none-any.whl.asc`

🔐 How to Verify a Release from GitHub

1. Import the GPG public key:

   ```` bash
   curl https://keys.openpgp.org/vks/v1/by-fingerprint/4592D7396DBAEFFD084502B85CCEC7E16814A36E | gpg --import
   ````

2. Download the wheel or tarball and its .asc signature from the GitHub.

3. Run GPG to verify it:

   ```` bash
   gpg --verify dar_backup-x.y.z.tar.gz.asc dar_backup-x.y.z.tar.gz
   # or
   gpg --verify dar_backup-x.y.z-py3-none-any.whl.asc dar_backup-x.y.z-py3-none-any.whl
   ````

4. If the signature is valid, you'll see:

   ```` text
   gpg: Good signature from "Per Jensen (author of dar-backup) <dar-backup@pm.me>"
   ````

🛡️ Reminder: Verify the signing subkey

Only this subkey is used to sign PyPI packages:

```` text
B54F 5682 F28D BA36 22D7  8E04 58DB FADB BBAC 1BB1
````

You can view it with:

```` bash
gpg --list-keys --with-subkey-fingerprints dar-backup@pm.me
````

### Breaking change in version 0.6.0

Version 0.6.0 and forwards requires the config variable *COMMAND_TIMEOUT_SECS* in the config file.

## Homepage - Github

'dar-backup' package lives here: [Github - dar-backup](https://github.com/per2jensen/dar-backup/tree/main/v2)

This python version is v2 of dar-backup, v1 is made in bash.

## Requirements

- dar
- par2
- python3

On Ubuntu, install the requirements this way:

```` bash
    sudo apt install dar par2 python3
````

## dar-backup principles

### dar-backup

`dar-backup` is built in a way that emphasizes getting backups. It loops over the [backup definitions](#backup-definition-example), and in the event of a failure while backing up a backup definition, dar-backup shall log an error and start working on the next backup definition.

There are 3 levels of backups, FULL, DIFF and INCR.

- The author does a FULL yearly backup once a year. This includes all files in all directories as defined in the backup definition(s) (assuming `-d` was not given).
- The author makes a DIFF once a month. The DIFF backs up new and changed files **compared** to the **FULL** backup.

  - No DIFF backups are taken until a FULL backup has been taken for a particular backup definition.

- The author takes an INCR backup every 3 days. An INCR backup includes new and changed files **compared** to the **DIFF** backup.
  
  - So, a set of INCR's will contain duplicates (this might change as I become more used to use the catalog databases)
  
  - No INCR backups are taken until a DIFF backup has been taken for a particular backup definition.

After each backup of a backup definition, `dar-backup` tests the archive and then performs a few restore operations of random files from the archive (see [dar-backup.conf](#config-file)). The restored files are compared to the originals to check if the restore went well.

`dar-backup` skips doing a backup of a backup definition if an archive is already in place. So, if you for some reason need to take a new backup on the same date, the first archive must be deleted (I recommend using [cleanup](#cleanup-1)).

### cleanup

The `cleanup` application deletes DIFF and INCR if the archives are older than the thresholds set up in the configuration file.

`cleanup` will only remove FULL archives if the option  `--cleanup-specific-archives` is used. It requires the user to confirm deletion of FULL archives.

### manager

`dar`has the concept of catalogs which can be exported and optionally be added to a catalog database. That database makes it much easier to restore the correct version of a backed up file if for example a target date has been set.

`dar-backup` adds archive catalogs to their databases (using the `manager` script). Should the operation fail, `dar-backup` logs an error and continue with testing and restore validation tests.

## How to run

📦 All official dar-backup releases from v2-beta-0.6.18 are signed with GPG.

See more [here](#gpg-signing-key).

### 1 - installation

Installation is currently in a venv. These commands are installed in the venv:

- dar-back
- cleanup
- manager
- clean-log
- installer

Note:

The module `inputimeout` is installed into the venv and used for the confirmation input (with a 30 second timeout)

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
dar-backup 0.6.12
dar-backup.py source code is here: https://github.com/per2jensen/dar-backup
Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.
````

### 2 - configuration

The dar-backup installer is non-destructive and stops if some of the default directories exist.

Run the installer

```` bash
installer --install
````

The output is

```` text
Directories created: `/home/user/dar-backup/` and `/home/user/.config/dar-backup`
Config file deployed to /home/user/.config/dar-backup/dar-backup.conf
Default backup definition deployed to /home/user/.config/dar-backup/backup.d/default
1. Now run `manager --create-db` to create the catalog database.
2. Then you can run `dar-backup --full-backup` to create a backup.
3. List backups with `dar-backup --list`
4. List contents of a backup with `dar-backup --list-contents <backup-name>`
````

### 3 - generate catalog databases

Generate the archive catalog database(s).

`dar-backup` expects the catalog databases to be in place, it does not automatically create them (by design)

```` bash
manager --create-db
````

### 4 - do FULL backups

Prereq:
[Backup definitions](#backup-definition-example) are in place in BACKUP.D_DIR (see [config file](#config-file)).

You are ready to do backups of all your backup definitions.

```` bash
dar-backup --full-backup 
````

If you want to see dar-backup's log entries in the terminal, use the `--log-stdout` option. This can be useful if dar-backup is started by systemd.

If you want more log messages, use the `--verbose` or `--log-level debug` for even more.

If you want a backup of a single definition, use the `-d <backup definition>` option. The definition's name is the filename of the definition in the `backup.d` config directory.

```` bash
dar-backup --full-backup -d <your backup definition>
````

### 5 - deactivate venv

Deactivate the virtual environment (venv)

```` bash
deactivate
````

## Config

### Config file

The configuration file's default location is: ~/.config/dar-backup/dar-backup.conf

If you have your config file somewhere else, use the `--config` option to point to it.

Tilde `~` and environment variables can be used in the paths for various file locations.

```` code
[MISC]
LOGFILE_LOCATION=~/.dar-backup.log
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 1
NO_FILES_VERIFICATION = 5
# timeout in seconds for backup, test, restore and par2 operations
# The author has such `dar` tasks running for 10-15 hours on the yearly backups, so a value of 24 hours is used.
# If a timeout is not specified when using the util.run_command(), a default timeout of 30 secs is used.
COMMAND_TIMEOUT_SECS = 86400

[DIRECTORIES]
BACKUP_DIR = /some/where/dar-backup/backups/
BACKUP.D_DIR = /some/where/dar-backup/backup.d
TEST_RESTORE_DIR = /tmp/dar-backup/restore/

[AGE]
# age settings are in days
DIFF_AGE = 100
INCR_AGE = 40

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True

# scripts to run before the backup to setup the environment
[PREREQ]
SCRIPT_1 = ls -l /tmp
#SCRIPT_2 = another_script.sh

[POSTREQ]
SCRIPT_1 = df -h
#SCRIPT_2 = another_script.sh
````

### .darrc

The package includes a default `darrc` file which configures `dar`.

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

### Backup definition example

This piece of configuration is a [backup definition](#backup-definition-example). It is placed in the BACKUP.D_DIR (see config file description).
The name of the file is the name of the backup definition.

You can use as many backup definitions as you need.

```` code
 # Switch to ordered selection mode, which means that the following
 # options will be considered top to bottom
 -am

# Backup Root Dir
# This is the top directory, where the backups start.
#Directories mentioned below, are relative to the Root Dir.
 -R /home/user/

# Directories to backup below the Root dir
# uncomment the next line to backup only the Documents directory
# -g Documents

# Directories to exclude below the Root dir
 -P mnt
 -P tmp
 -P .cache
 -P .config/Code/CachedData
 
# compression level
 -z5

# no overwrite, if you rerun a backup, 'dar' halts and asks what to do
# due to the -Q option given to `dar`, the program will terminate and give en error.
 -n
 
# size of each slice in the archive
 --slice 7G

# bypass directores marked as cache directories
# http://dar.linux.free.fr/doc/Features.html
# https://bford.info/cachedir/
--cache-directory-tagging
````

## Generate systemd files

The command `dar-backup-systemd` can generate and optionally install systemd units and timers.

The timers are set as the author uses them, modify to your taste and needs.

Example run:

```` bash
dar-backup-systemd --venv /home/user/tmp/venv --dar-path /home/user/.local/dar/bin
Generated dar-full-backup.service and dar-full-backup.timer
  → Fires on: *-12-30 10:03:00
Generated dar-diff-backup.service and dar-diff-backup.timer
  → Fires on: *-*-01 19:03:00
Generated dar-incr-backup.service and dar-incr-backup.timer
  → Fires on: *-*-04/3 19:03:00
Generated dar-clean.service and dar-clean.timer
  → Fires on: *-*-* 21:07:00
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

## Service: dar-backup --incremental-backup

This is an exmaple of a systemd user service unit.

File:  dar-incr-backup.service

```` bash
/tmp/test$ dar-backup-systemd --venv '$HOME/programmer/dar-backup.py/venv'  --dar-path '$HOME/.local/dar/bin'

Generated dar-full-backup.service and dar-full-backup.timer
  → Fires on: *-12-30 10:03:00
Generated dar-diff-backup.service and dar-diff-backup.timer
  → Fires on: *-*-01 19:03:00
Generated dar-incr-backup.service and dar-incr-backup.timer
  → Fires on: *-*-04/3 19:03:00
Generated dar-cleanup.service and dar-cleanup.timer
  → Fires on: *-*-* 21:07:00
/tmp/test$ 
(venv) /tmp/test$ 
(venv) /tmp/test$ cat dar-incr-backup.service 
[Unit]
Description=dar-backup INCR
StartLimitIntervalSec=120
StartLimitBurst=1

[Service]
Type=oneshot
TimeoutSec=infinity
RemainAfterExit=no


ExecStart=/bin/bash -c 'PATH=$HOME/.local/dar/bin:$PATH && . $HOME/programmer/dar-backup.py/venv/bin/activate && dar-backup -I --verbose --log-stdout'
````

## Timer: dar-backup --incremental-backup

This is an example of a systemd user timer

File:  dar-incr-backup.timer

```` code
[Unit]
Description=dar-backup INCR timer

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
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root   root    113 Mio   Sat May 11 16:16:48 2024        home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj     pj      113 Mio   Sun Jun 23 10:46:30 2024        home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj     pj      113 Mio   Sun Jun 23 09:17:42 2024        home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj     pj      50 Mio    Wed Jun 19 20:52:13 2024        home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj     pj      49 Mio    Sun Jun 16 12:52:22 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
```

## dar file selection examples

### select a directory

``` bash
dar -l /tmp/example_FULL_2024-06-23  -g home/pj/tmp/LUT-play
```

gives

```` code
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root   root    113 Mio   Sat May 11 16:16:48 2024        home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj     pj      113 Mio   Sun Jun 23 10:46:30 2024        home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj     pj      113 Mio   Sun Jun 23 09:17:42 2024        home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj     pj      50 Mio    Wed Jun 19 20:52:13 2024        home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj     pj      49 Mio    Sun Jun 16 12:52:22 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      48 kio    Sat Jun 22 21:51:24 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      50 kio    Sat Jun 22 21:51:25 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_01.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      51 kio    Sat Jun 22 21:51:26 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_02.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      51 kio    Sat Jun 22 21:51:27 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_03.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      51 kio    Sat Jun 22 21:51:27 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_04.NEF.xmp
[Saved][ ]       [-L-][  97%][ ]  -rw-rw-r--   pj     pj      77 kio    Sat Jun 22 21:50:16 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_05.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      52 kio    Sat Jun 22 21:49:37 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_06.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:47 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_07.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:51:12 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_08.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:51:12 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_09.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:39 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_10.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:36 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_11.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:35 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_12.NEF.xmp
[Saved][ ]       [-L-][  88%][ ]  -rw-rw-r--   pj     pj      15 kio    Sat Jun 22 21:51:11 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_13.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj     pj      84 kio    Sat Jun 22 21:51:09 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_14.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj     pj      90 kio    Sat Jun 22 21:51:04 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_15.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:51:15 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_16.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:48 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_17.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:19 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_18.NEF.xmp
````

### select file dates in the directory

``` bash
dar -l /tmp/example_FULL_2024-06-23  -I '*2024-06-16*' -g home/pj/tmp/LUT-play
```

gives

``` code
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ] drwxr-xr-x   root    root    113 Mio   Sat May 11 16:16:48 2024        home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj     pj      113 Mio   Sun Jun 23 10:46:30 2024        home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj     pj      113 Mio   Sun Jun 23 09:17:42 2024        home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj     pj      50 Mio    Sed Jun 19 20:52:13 2024        home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj     pj      49 Mio    Sun Jun 16 12:52:22 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      48 kio    Sat Jun 22 21:51:24 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      50 kio    Sat Jun 22 21:51:25 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_01.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      51 kio    Sat Jun 22 21:51:26 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_02.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      51 kio    Sat Jun 22 21:51:27 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_03.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      51 kio    Sat Jun 22 21:51:27 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_04.NEF.xmp
[Saved][ ]       [-L-][  97%][ ]  -rw-rw-r--   pj     pj      77 kio    Sat Jun 22 21:50:16 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_05.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj     pj      52 kio    Sat Jun 22 21:49:37 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_06.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:47 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_07.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:51:12 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_08.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:51:12 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_09.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:39 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_10.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:36 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_11.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:35 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_12.NEF.xmp
[Saved][ ]       [-L-][  88%][ ]  -rw-rw-r--   pj     pj      15 kio    Sat Jun 22 21:51:11 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_13.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj     pj      84 kio    Sat Jun 22 21:51:09 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_14.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj     pj      90 kio    Sat Jun 22 21:51:04 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_15.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:51:15 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_16.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:48 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_17.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj     pj      24 kio    Sat Jun 22 21:50:19 2024        home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_18.NEF.xmp
```

### exclude .xmp files from that date

``` bash
dar -l /tmp/example_FULL_2024-06-23 -X '*.xmp' -I '*2024-06-16*' -g home/pj/tmp/LUT-play

```

gives

```` code
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root   root    113 Mio   Sat May 11 16:16:48 2024        home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj     pj      113 Mio   Sun Jun 23 10:46:30 2024        ome/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj     pj      113 Mio   Sun Jun 23 09:17:42 2024        ome/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj     pj      50 Mio    Wed Jun 19 20:52:13 2024      ` ome/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj     pj      49 Mio    Sun Jun 16 12:52:22 2024      ` home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
````

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

### restore test fails with exit code 4

"dar" in newer versions emits a question about file ownership, which is "answered" with a "no" via the "-Q" option. That in turn leads to an error code 4.

Thus the dar option "--comparison-field=ignore-owner" has been placed in the supplied [.darrc](#darrc) file (located in the virtual environment where dar-backup is installed).

This causes dar to restore without an error.

It is a good option when using dar as a non-privileged user.

### restore test fails with exit code 5

If exit code 5 is emitted on the restore test, FSA (File System specific Attributes) could be the cause.

That (might) occur if you backup a file stored on one type of filesystem, and restore it on another type.
My home directory is on a btrfs filesystem, while /tmp (for the restore test) is on zfs.

The restore test can result in an exit code 5, due to the different filesystems used. In order to avoid the errors, the "option "--fsa-scope none" can be used. That will restult in FSA's not being restored.

If you need to use this option, un-comment it in the [.darrc](#darrc) file (located in the virtual environment where dar-backup is installed)

## Par2

### Par2 to verify/repair

You can run a par2 verification on an archive like this:

```` bash
for file in <archive>*.dar.par2; do
  par2 verify "$file"
done
````

if there are problems with a slice, try to repair it like this:

```` bash
  par2 repair <archive>.<slice number>.dar.par2
````

### Par2 create redundancy files

If you have merged archives, you will need to create the .par2 redundency files manually.
Here is an example

```` bash
for file in <some-archive>_FULL_yyyy-mm-dd.*; do
  par2 c -r5 -n1 "$file"
done
````

where "c" is create, -r5 is 5% redundency and -n1 is 1 redundency file

## Points of interest

### Merge FULL with DIFF, creating new FULL

Over time, the DIFF archives become larger and larger. At some point one wishes to create a new FULL archive to do DIFF's on.
One way to do that, is to let dar create a FULL archive from scratch, another is to merge a FULL archive with a DIFF, and from there do DIFF's until they once again gets too large for your taste.

I do backups of my homedir. Here it is shown how a FULL archive is merged with a DIFF, creating a new FULL archive.

```` bash
dar --merge pj-homedir_FULL_2021-09-12  -A pj-homedir_FULL_2021-06-06  -@pj-homedir_DIFF_2021-08-29 -s 12G

# test the new FULL archive
dar -t pj-homedir_FULL_2021-09-12

# create Par2 redundancy files
for file in pj-homedir_FULL_yyyy-mm-dd.*.dar; do
  par2 c -r5 -n1 "$file"
done

````

### dar manager databases

`dar-backup` now saves archive catalogs in dar catalog databases.

This makes it easier to restore to a given date when having many FULL, DIFF and INCR archives.

If the manager does not add an archive to it's catalog database, `dar-backup` will log an error and continue. The important part is verify the archive is usable and continue to other backup definitions.

### Performance tip due to par2

This [dar benchmark page](https://dar.sourceforge.io/doc/benchmark.html) has an interesting note on the slice size.

Slice size should be smaller than available RAM, apparently a large performance hit can be avoided keeping the par2 data in memory.

### .darrc sets -vd -vf (since v0.6.4)

These [.darrc](#darrc) settings make `dar` print the current directory being processed (-vd) and some stats after (-vf)

This is very useful in very long running jobs to get an indication that the backup is proceeding normally.

### Separate log file for command output

Dar-backup's log file is called `dar-backup.log`.

In order to not clutter that log file with the output of commands being run, a new secondary log file has been introduced `dar-backup-commands.log`.

The secondary log file can get quite cluttered, if you want to remove the clutter, run the `clean-log`script with the `--file` option, or simply delete it.

### Skipping cache directories

The author uses the `--cache-directory-tagging` option in his [backup definitions](#backup-definition-example).

The effect is that directories with the [CACHEDIR.TAG](https://bford.info/cachedir/) file are not backed up. Those directories contain content fetched from the net, which is of an ephemeral nature and probably not what you want to back up.

If the option is not in the backup definition, the cache directories are backed up as any other.

### Progress bar and current directory

If you run dar-backup interactively in a "normal" console on your computer,
dar-backup displays 2 visual artifacts to show progress.

1. a progress bar that fills up and starts over
2. a status line showing the directory being backed up. If the directory is big and takes time to backup, the line is not changing, but you will probably know there is a lot to backup.

The indicators are not shown if dar-backup is run from systemd or if it is used in terminal multiplexers like `tmux` or `screen`. So no polluting of journald logs.

## Todo

- Look into a way to move the .par2 files away from the `dar` slices, to maximize chance of good redundancy.
- Add option to dar-backup to use the `dar` option `--fsa-scope none`

## Reference

### test coverage

Running

```` bash
pytest --cov=dar_backup tests/
````

results for version 0.6.17 in this report:

```` code
---------- coverage: platform linux, python 3.12.3-final-0 -----------
Name                                                              Stmts   Miss  Cover
-------------------------------------------------------------------------------------
venv/lib/python3.12/site-packages/dar_backup/__about__.py             1      0   100%
venv/lib/python3.12/site-packages/dar_backup/__init__.py              0      0   100%
venv/lib/python3.12/site-packages/dar_backup/clean_log.py            68     14    79%
venv/lib/python3.12/site-packages/dar_backup/cleanup.py             196     53    73%
venv/lib/python3.12/site-packages/dar_backup/config_settings.py      66      8    88%
venv/lib/python3.12/site-packages/dar_backup/dar_backup.py          464     99    79%
venv/lib/python3.12/site-packages/dar_backup/installer.py            46     46     0%
venv/lib/python3.12/site-packages/dar_backup/manager.py             316     72    77%
venv/lib/python3.12/site-packages/dar_backup/util.py                162     34    79%
-------------------------------------------------------------------------------------
TOTAL                                                              1319    326    75%
````

### dar-backup options

This script does backups, validation and restoring. It has the following options:

``` code
-F, --full-backup                    Perform a full backup.
-D, --differential-backup            Perform a differential backup.
-I, --incremental-backup             Perform an incremental backup.
-d, --backup-definition <name>       Specify the backup definition file.
--alternate-reference-archive <file> Use a different archive for DIFF/INCR backups.
-c, --config-file <path>             Specify the path to the configuration file.
--darrc <path>                       Specify an optional path to .darrc.
--examples                           Show examples of using dar-backup.py.
-l, --list                           List available backups.
--list-contents <archive>            List the contents of a specified archive.
--selection <params>                 Define file selection for listing/restoring.
--restore <archive>                  Restore a specified archive.
-r, --restore-dir <path>             Directory to restore files to.
--verbose                            Enable verbose output.
--suppress-dar-msg                   Filter out this from the darrc: "-vt", "-vs", "-vd", "-vf", "-va"
--log-level <level>                  `debug` or `trace`, default is `info`.
--log-stdout                         Also print log messages to stdout.
--do-not-compare                     Do not compare restores to file system.
-v --version                         Show version and license information.
```

### manager options

This script manages `dar` databases and catalogs. Available options:

``` code
-c, --config-file                    Path to dar-backup.conf
--create-db                          Create missing databases for all backup definitions.
--alternate-archive-dir <path>       Use this directory instead of BACKUP_DIR in the config file.
--add-dir <path>                     Add all archive catalogs in this directory to databases.
-d, --backup-def <name>              Restrict to work only on this backup definition.
--add-specific-archive <archive>     Add this archive to the catalog database.
--remove-specific-archive <archive>  Remove this archive from the catalog database.
-l, --list-catalogs                  List catalogs in databases for all backup definitions.
--list-catalog-contents <num>        List contents of a catalog by catalog number.
--list-archive-contents <archive>    List contents of an archive’s catalog, given the archive name.
--find-file <file>                   Search catalogs for a specific file.
--verbose                            Enable verbose output.
--log-level <level>                  `debug` or `trace`, default is `info`", default="info".
```

### cleanup options

This script cleans up old backups and par2 files. Supported options:

``` code
-d, --backup-definition                           Backup definition to cleanup.
-c, --config-file                                 Path to 'dar-backup.conf'
-v, --version                                     Show version & license information.
--alternate-archive-dir                           Clean up in this directory instead of the default one.
--cleanup-specific-archives "<archive>, <>, ..."  Comma separated list of archives to cleanup.
-l, --list                                       List available archives (filter using the -d option).
--verbose                                         Print various status messages to screen.
--log-level <level>                               `debug` or `trace`, default is `info`", default="info".
--log-stdout                                      Print log messages to stdout.
--test-mode                                       This is used when running pytest test cases
```

### clean-log options

This script removes excessive logging output from `dar` logs, improving readability and efficiency. Available options:

``` code
-f, --file <path>          Specify the log file(s) to be cleaned.
-c, --config-file <path>   Path to dar-backup.conf.
--dry-run                  Show which lines would be removed without modifying the file.
-v, --version              Display version and licensing information.
-h, --help                 Displays usage info
```

### installer options

Sets up `dar-backup`for a user.

It is non-destructive and stops if directories are already in place.

Create directories:

- ~/.config/dar-backup/
  - ~/.config/dar-backup/backup.d/
- ~/dar-backup/
  - ~/dar-backup/backups
  - ~/dar-backup/restore

Sets up demo config files:

- ~/.config/dar-backup/dar-backup.conf
- ~/.config/dar-backup/backup.d/default

``` code
-i, --install              Sets up `dar-backup`.
-v, --version              Display version and licensing information.
-h, --help                 Displays usage info
```

### dar-backup-systemd

Generates and optionally install systemd user service units and timers

``` code
-h, --help           Show this help message and exit
--venv VENV          Path to the Python venv with dar-backup
--dar-path DAR_PATH  Optional path to dar binary's directory
--install            Install the units to ~/.config/systemd/user
```
