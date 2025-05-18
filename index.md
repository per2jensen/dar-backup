<!-- markdownlint-disable MD024 -->
# `dar-backup`

**Reliable DAR backups, automated in clean Python**

[![codecov](https://codecov.io/gh/per2jensen/dar-backup/branch/main/graph/badge.svg)](https://codecov.io/gh/per2jensen/dar-backup)
[![PyPI version](https://img.shields.io/pypi/v/dar-backup.svg)](https://pypi.org/project/dar-backup/)
[![PyPI Downloads](https://img.shields.io/badge/dynamic/json?color=blue&label=Total%20Downloads&query=total&url=https%3A%2F%2Fraw.githubusercontent.com%2Fper2jensen%2Fdar-backup%2Fmain%2Fdownloads.json)](https://pypi.org/project/dar-backup/)
[![# clones](https://img.shields.io/badge/dynamic/json?color=deeppink&label=%23%20clones&query=total_clones&url=https%3A%2F%2Fraw.githubusercontent.com%2Fper2jensen%2Fdar-backup%2Fmain%2Fv2%2Fdoc%2Fclones.json)](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/weekly_clones.png)

The wonderful 'dar' [Disk Archiver](https://github.com/Edrusb/DAR) is used for
the heavy lifting, together with the par2 suite in these scripts.

This is the `Python` based [**version 2**](https://github.com/per2jensen/dar-backup/tree/main/v2) of `dar-backup`.

## TL;DR

`dar-backup` is a Python-powered CLI for creating and validating full, differential, and incremental backups using `dar` and `parchive`. Designed for long-term restore integrity, even on user-space filesystems like FUSE.

## Table of Contents

- [My use case](#my-use-case)
- [Features](#features)
- [License: GPL-3-0](#license)
- [Changelog version 2](https://github.com/per2jensen/dar-backup/blob/main/v2/Changelog.md)
- [Quick Guide](#quick-guide)
- [Status (late beta)](#status)
  - [GPG Signing key](#gpg-signing-key)
  - [Breaking change in version 0.6.0](#breaking-change-in-version-060)
- [Homepage - Github](#homepage---github)
- [Requirements](#requirements)
- [Principles](#dar-backup-principles)
- [Config](#config)
  - [Config file](#config-file)
  - [.darrc](#darrc)
  - [Backup definition](#backup-definition-example)
- [Systemd examples](#systemctl-examples)
  - [Generate systemd files](#generate-systemd-files)
  - [Service: dar-back --incremental-backup](#service-dar-backup---incremental-backup)
  - [Timer: dar-back --incremental-backup](#timer-dar-backup---incremental-backup)
  - [Systemd timer note](#systemd-timer-note)
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
  - [Shell Autocompletion](#shell-autocompletion)
- [Todo](#todo)
- [Known Limitations / Edge Cases](#known-limitations--edge-cases)
- [Reference](#reference)
  - [CLI Tools Overview](#cli-tools-overview)
  - [Test coverage report](#test-coverage)
  - [dar-backup](#dar-backup-options)
  - [manager](#manager-options)
  - [cleanup](#cleanup-options)
  - [clean-log](#clean-log-options)
  - [dar-backup-systemd](#dar-backup-systemd-options)
  - [Installer](#installer-options)
  - [demo](#demo-options)
  
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

## Features

- The battle tested [dar](https://github.com/Edrusb/DAR) Disk Archiver is used for the actual backups - it comes highly recommended.
- Backup with test of backup and (configurable) restore tests of files with comparison to source
- [Redundancy files](#par2) created for patching bitrot of the archives (size configurable)
- Simple [backup definitions](#backup-definition-example) defining what to backup (as many as you need)
- [Backup catalogs](#dar-manager-databases) in databases, optionally on a disk different from the backups
- Flexible and precise logging
- Bash and zsh shell autocompletion for a nice CLI experience, [available completions](#shell-autocompletion):
  
  - Options for `dar-backup`, `cleanup`, `manager`
  - Backup definitions
  - Archives - filtered to backup definition if given
  - Catalogs - filtered to backup definition if given

- `dar-backup` is easy to install and configure.

- ✅ The author has used dar-backup since > 4 years, and has been saved multiple times.

## License

  These scripts are licensed under the GPLv3 license.
  Read more here: [GNU CPL 3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), or have a look at the ["LICENSE"](https://github.com/per2jensen/dar-backup/blob/main/LICENSE) file in this repository.

## Quick Guide

This purpose of this quick guide is to show how `dar-backup` works in a few simple steps.

The package include a `demo`application, that can help you set up `dar-backup` quickly.

> ⚠️ **Assumption**
>
> The demo program uses these directories in your home directory:
>
> - $HOME/dar-backup
> - $HOME/.config/dar-backup
>
> It is assumed they **do not exist** before running the demo.
>
> The example is done on my Ubuntu based pc.
> Python **>= 3.9** is required

<br>

**Let's roll** with installation, backup, list backup content, restore & restore check

```bash
sudo apt -y install dar par2 python3 python3-venv
INSTALL_DIR=/tmp/dar-backup
mkdir "$INSTALL_DIR"
cd "$INSTALL_DIR"
python3 -m venv venv    # create the virtual environment 
. venv/bin/activate     # activate the virtual environment
pip install dar-backup  # run pip to install `dar-backup`
```

<details>

<summary>🎯 Install details</summary>

```bash
(venv) $ INSTALL_DIR=/tmp/dar-backup
mkdir "$INSTALL_DIR"
cd "$INSTALL_DIR"
python3 -m venv venv    # create the virtual environment 
. venv/bin/activate     # activate the virtual environment
pip install dar-backup  # run pip to install `dar-backup`
Collecting dar-backup
  Downloading dar_backup-0.6.21-py3-none-any.whl.metadata (88 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 88.5/88.5 kB 3.7 MB/s eta 0:00:00
Collecting argcomplete>=3.6.2 (from dar-backup)
  Using cached argcomplete-3.6.2-py3-none-any.whl.metadata (16 kB)
Collecting inputimeout>=1.0.4 (from dar-backup)
  Using cached inputimeout-1.0.4-py3-none-any.whl.metadata (2.2 kB)
Collecting rich>=13.0.0 (from dar-backup)
  Using cached rich-14.0.0-py3-none-any.whl.metadata (18 kB)
Collecting markdown-it-py>=2.2.0 (from rich>=13.0.0->dar-backup)
  Using cached markdown_it_py-3.0.0-py3-none-any.whl.metadata (6.9 kB)
Collecting pygments<3.0.0,>=2.13.0 (from rich>=13.0.0->dar-backup)
  Using cached pygments-2.19.1-py3-none-any.whl.metadata (2.5 kB)
Collecting mdurl~=0.1 (from markdown-it-py>=2.2.0->rich>=13.0.0->dar-backup)
  Using cached mdurl-0.1.2-py3-none-any.whl.metadata (1.6 kB)
Downloading dar_backup-0.6.21-py3-none-any.whl (101 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 101.9/101.9 kB 16.2 MB/s eta 0:00:00
Using cached argcomplete-3.6.2-py3-none-any.whl (43 kB)
Using cached inputimeout-1.0.4-py3-none-any.whl (4.6 kB)
Using cached rich-14.0.0-py3-none-any.whl (243 kB)
Using cached markdown_it_py-3.0.0-py3-none-any.whl (87 kB)
Using cached pygments-2.19.1-py3-none-any.whl (1.2 MB)
Using cached mdurl-0.1.2-py3-none-any.whl (10.0 kB)
Installing collected packages: pygments, mdurl, inputimeout, argcomplete, markdown-it-py, rich, dar-backup
Successfully installed argcomplete-3.6.2 dar-backup-0.6.21 inputimeout-1.0.4 markdown-it-py-3.0.0 mdurl-0.1.2 pygments-2.19.1 rich-14.0.0
```

</details>

<br>

```bash
demo --install          # see reference section for options tweaking the install

manager --create-db

dar-backup --full-backup

dar-backup --list-contents $(dar-backup --list |tail -n 1 | cut -d " " -f1)
```

<details>

<summary>🎯 --list details</summary>

```bash
(venv) $ demo --install
Directories created.
File generated at '/home/user/.config/dar-backup/backup.d/demo'
File generated at '/home/user/.config/dar-backup/dar-backup.conf'
1. Now run `manager --create-db` to create the catalog database.
2. Then you can run `dar-backup --full-backup` to create a backup.
3. List backups with `dar-backup --list`
4. List contents of a backup with `dar-backup --list-contents <backup-name>`



(venv) $ manager --create-db 
========== Startup Settings ==========
manager.py:     0.7.1
Config file:    /home/user/.config/dar-backup/dar-backup.conf
Logfile:        /home/user/dar-backup/dar-backup.log
dar_manager:    /home/user/.local/dar/bin/dar_manager
dar_manager v.: 1.9.0
======================================



(venv) $ dar-backup --full-backup
========== Startup Settings ==========
dar-backup.py:    0.7.1
dar path:         /home/user/.local/dar/bin/dar
dar version:      2.7.17
Script directory: /home/user/git/dar-backup/v2/src/dar_backup
Config file:      /home/user/.config/dar-backup/dar-backup.conf
.darrc location:  /home/user/git/dar-backup/v2/src/dar_backup/.darrc
======================================



(venv) $ dar-backup --list-contents $(dar-backup --list |tail -n 1 | cut -d " " -f1)
========== Startup Settings ==========
dar-backup.py:    0.7.1
dar path:         /home/user/.local/dar/bin/dar
dar version:      2.7.17
Script directory: /home/user/git/dar-backup/v2/src/dar_backup
Config file:      /home/user/.config/dar-backup/dar-backup.conf
.darrc location:  /home/user/git/dar-backup/v2/src/dar_backup/.darrc
======================================
[Saved][-]       [-L-][  49%][ ]  drwx------   user user  8 kio Sat May 17 13:13:59 2025  .config
[Saved][-]       [-L-][  49%][ ]  drwxrwxr-x   user user  8 kio Tue May  6 20:55:40 2025  .config/dar-backup
[Saved][-]       [-L-][  48%][ ]  drwxrwxr-x   user user  6 kio Sat May 17 13:26:21 2025  .config/dar-backup/backup.d
[Saved][ ]       [-L-][  40%][ ]  -rw-rw-r--   user user  764 o Sun Feb 23 21:23:01 2025  .config/dar-backup/backup.d/media-files
[Saved][ ]       [-L-][  41%][ ]  -rw-rw-r--   user user  933 o Sun Feb 23 21:23:15 2025  .config/dar-backup/backup.d/pCloudDrive
[Saved][ ]       [-L-][  48%][ ]  -rw-rw-r--   user user  1 kio Sun Mar 16 10:40:29 2025  .config/dar-backup/backup.d/test
[Saved][ ]       [-L-][  48%][ ]  -rw-rw-r--   user user  824 o Tue May 13 17:00:52 2025  .config/dar-backup/backup.d/default
[Saved][ ]       [-L-][  48%][ ]  -rw-rw-r--   user user  1 kio Sat May  3 10:40:33 2025  .config/dar-backup/backup.d/user-homedir
[Saved][ ]       [-L-][  54%][ ]  -rw-rw-r--   user user  1 kio Sat May 17 18:17:40 2025  .config/dar-backup/backup.d/demo
[Saved][ ]       [-L-][  55%][ ]  -rw-rw-r--   user user  1 kio Sat May 17 18:17:40 2025  .config/dar-backup/dar-backup.conf
```

</details>

<br>

```bash
dar-backup --restore $(dar-backup --list |tail -n 1 | cut -d " " -f1)  --verbose

# prove the files have been restored
find $HOME/dar-backup/restore
```

<details>

<summary>🎯 --restore details</summary>

```bash
(venv) $ dar-backup --verbose --restore $(dar-backup --list |tail -n 1 | cut -d " " -f1)
========== Startup Settings ==========
dar-backup.py:    0.7.1
dar path:         /home/user/.local/dar/bin/dar
dar version:      2.7.17
Script directory: /home/user/git/dar-backup/v2/src/dar_backup
Config file:      /home/user/.config/dar-backup/dar-backup.conf
.darrc location:  /home/user/git/dar-backup/v2/src/dar_backup/.darrc
Backup.d dir:     /home/user/.config/dar-backup/backup.d
Backup dir:       /home/user/dar-backup/backups
Restore dir:      /home/user/dar-backup/restore
Logfile location: /home/user/dar-backup/dar-backup.log
PAR2 enabled:     True
--do-not-compare: False
======================================



(venv) $ find ~/dar-backup/restore/
/home/user/dar-backup/restore/
/home/user/dar-backup/restore/.config
/home/user/dar-backup/restore/.config/dar-backup
/home/user/dar-backup/restore/.config/dar-backup/backup.d
/home/user/dar-backup/restore/.config/dar-backup/backup.d/media-files
/home/user/dar-backup/restore/.config/dar-backup/backup.d/pCloudDrive
/home/user/dar-backup/restore/.config/dar-backup/backup.d/test
/home/user/dar-backup/restore/.config/dar-backup/backup.d/default
/home/user/dar-backup/restore/.config/dar-backup/backup.d/user-homedir
/home/user/dar-backup/restore/.config/dar-backup/backup.d/demo
/home/user/dar-backup/restore/.config/dar-backup/dar-backup.conf
```

</details>

<br>

> ✅ **Next steps**
>
> Tinker with `demo's` options:
>
> - --root-dir      (perhaps $HOME)
> - --dir-to-backup (perhaps Pictures)
> - --backup-dir    (perhaps /media/user/big-disk)
>
> See log file: `cat "$HOME/dar-backup/dar-backup.log"`
>
> Checkout [systemd timers and services](#generate-systemd-files)
>
> Checkout [shell autocompletion (very nice !)](#shell-autocompletion)
>
> Checkout the [reference section](#reference)

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

## systemd timer note

📅 OnCalendar syntax is flexible — you can tweak backup schedules easily. Run systemd-analyze calendar to preview timers.

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

### Shell autocompletion

The `dar-backup`, `manager`, and `cleanup` scripts now support dynamic Bash tab-completion, making them easier and faster to use.

✅ Features

- Autocomplete for all long options (--config-file, --restore, etc.)

- Dynamic suggestions based on your config:

- --backup-definition shows available definitions from backup.d/

- show relevant archives when a backup definition has been chosen:

  dar-backup: --restore, --list-contents, and --alternate-reference-archive

  cleanup: --cleanup-specific-archives

  manager:  --add-specific-archive, --remove-specific-archive
  
- Supports paths like ~ and $HOME correctly

#### Use it

Try typing:

```bash
dar-backup --<TAB>
```

You should see all available flags like --full-backup, --restore, etc.

Try completion of backup definition and then list contents:

```bash
    dar-backup --backup-definition <TAB>
    dar-backup -d <the chosen backup-definition> --list-contents <TAB>
```

#### Enabling Bash completion

Try auto completion in your session:

```bash
eval "$(register-python-argcomplete dar-backup)"
eval "$(register-python-argcomplete cleanup)"
eval "$(register-python-argcomplete manager)"
```

To make it persistent across sessions, add this to your ~/.bashrc:

```bash
# Enable autocompletion for dar-backup
eval "$(register-python-argcomplete dar-backup)"
eval "$(register-python-argcomplete cleanup)"
eval "$(register-python-argcomplete manager)"
```

Then reload your shell:

```bash
source ~/.bashrc
```

#### Enable Zsh Completion

If you're using Zsh, add this to your .zshrc:

```zsh
autoload -U bashcompinit
bashcompinit
eval "$(register-python-argcomplete dar-backup)"
eval "$(register-python-argcomplete cleanup)"
eval "$(register-python-argcomplete manager)"
```

Then reload Zsh:

```zsh
source ~/.zshrc
```

## Todo

- Look into a way to move the .par2 files away from the `dar` slices, to maximize chance of good redundancy.
- Add option to dar-backup to use the `dar` option `--fsa-scope none`

## Known Limitations / Edge Cases

Does not currently encrypt data (by design — relies on encrypted storage)

One backup definition per file

.par2 files created for each slice (may be moved in future)

## Projects these scripts benefit from

 1. [The wonderful dar achiver](https://github.com/Edrusb/DAR)
 2. [The Parchive suite](https://github.com/Parchive)
 3. [shellcheck - a bash linter](https://github.com/koalaman/shellcheck)
 4. [Ubuntu of course :-)](https://ubuntu.com/)
 5. [PyPI](https://pypi.org/)
 6. Tracking PyPI downloads with [pypi-total-downloads-tracker](https://github.com/per2jensen/pypi-total-downloads-tracker)

## Reference

### CLI Tools Overview

| Command              | Description                               |
|----------------------|-------------------------------------------|
| [dar-backup](#dar-backup-options)| Perform full, differential, or incremental backups with verification and restore testing |
| [manager](#manager-options)      | Maintain and query catalog databases for archives |
| [cleanup](#cleanup-options)      | Remove outdated DIFF/INCR archives (and optionally FULLs) |
| [clean-log](#clean-log-options)  | Clean up excessive log output from dar command logs |
| [dar-backup-systemd](#dar-backup-systemd-options) | Generate (and optionally install) systemd timers and services for automated backups |
| [installer](#installer-options)  | Set up directories and optionally create catalog databases according to a config file |
| [demo](#demo-options)            | Set up required directories and config files for a demo|

### test coverage

Running

```bash
pytest --cov=dar_backup tests/
```

Results for a version 0.6.19 in this report:

```text
Name                                   Stmts   Miss  Cover
----------------------------------------------------------
src/dar_backup/__about__.py                1      0   100%
src/dar_backup/__init__.py                 0      0   100%
src/dar_backup/clean_log.py               68     13    81%
src/dar_backup/cleanup.py                196     17    91%
src/dar_backup/command_runner.py          80      3    96%
src/dar_backup/config_settings.py         66      7    89%
src/dar_backup/dar_backup.py             539     56    90%
src/dar_backup/dar_backup_systemd.py      56      7    88%
src/dar_backup/installer.py               59      6    90%
src/dar_backup/manager.py                403     54    87%
src/dar_backup/rich_progress.py           70      7    90%
src/dar_backup/util.py                   231     24    90%
----------------------------------------------------------
TOTAL                                   1769    194    89%
```

### Dar-backup options

This script does backups including par2 redundancy, validation and restoring.

Available options:

```bash
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
-v, --version                         Show version and license information.
```

### Manager Options

This script manages `dar` databases and catalogs.

Available options:

```bash
-c, --config-file <path>             Path to dar-backup.conf.
--create-db                          Create missing databases for all backup definitions.
--alternate-archive-dir <path>       Use this directory instead of BACKUP_DIR in the config file.
--add-dir <path>                     Add all archive catalogs in this directory to databases.
-d, --backup-def <name>              Restrict operations to this backup definition.
--add-specific-archive <archive>     Add a specific archive to the catalog database.
--remove-specific-archive <archive>  Remove a specific archive from the catalog database.
-l, --list-catalogs                  List catalogs in databases for all backup definitions.
--list-archive-contents <archive>    List the contents of an archive’s catalog by archive name.
--find-file <file>                   Search catalogs for a specific file.
--verbose                            Enable verbose output.
--log-level <level>                  Set log level (`debug` or `trace`, default is `info`).
```

### Cleanup options

This script removes old backups and par2 files according to `[AGE]` settings in config file.

Catalogs in catalog databases are also removed.

Supported options:

```bash
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

### Clean-log options

This script removes excessive logging output from `dar` logs, improving readability and efficiency. Available options:

```bash
-f, --file <path>          Specify the log file(s) to be cleaned.
-c, --config-file <path>   Path to dar-backup.conf.
--dry-run                  Show which lines would be removed without modifying the file.
-v, --version              Display version and licensing information.
-h, --help                 Displays usage info
```

### Dar-backup-systemd options

Generates and optionally install systemd user service units and timers.

```bash
-h, --help           Show this help message and exit
--venv VENV          Path to the Python venv with dar-backup
--dar-path DAR_PATH  Optional path to dar binary's directory
--install            Install the units to ~/.config/systemd/user
```

### Installer options

Sets up `dar-backup` according to provided config file.

The installer creates the necessary backup catalog databases if `--create-db` is given.

```bash
--config                 Sets up `dar-backup`.
--create-db              Create backup catalog databases. Add it to --config
--install-autocompletion Add bash or zsh auto completion - idempotent
--remove-autocompletion  Remove the auto completion from bash or zsh
-v, --version            Display version and licensing information.
-h, --help               Displays usage info
```

### Demo options

Sets up `dar-backup` in a demo configuration.

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

```bash
-i, --install       Sets up `dar-backup`.
--root-dir          Specify the root directory for the backup.
--dir-to-backup     Directory to backup, relative to the root directory.
--backup-dir        Directory where backups and redundancy files are put.
--override          By default, the script will not overwrite existing files or directories.
                    Use this option to override this behavior.
--generate          Generate config files and put them in /tmp/ for inspection
                    without writing to $HOME.
-v, --version       Display version and licensing information.
-h, --help          Displays usage info
```
