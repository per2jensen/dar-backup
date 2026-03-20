# Quick Guide

The purpose of this quick guide is to show how `dar-backup` works in a few simple steps.

The package includes a `demo` application that can help you set up `dar-backup` quickly.

> ⚠️ **Assumption**
>
> The demo program uses these directories in your home directory:
>
> - $HOME/dar-backup
> - $HOME/.config/dar-backup
>
> It is assumed they **do not exist** before running the demo.
>
> Python **>= 3.11** is required

<br>

**Let's roll** with installation, backup, list backup content, restore & restore check

The demo is known to work on an Ubuntu 24.04 clean VM as delivered from `Multipass`

```bash
sudo apt -y install dar par2 python3 python3-venv
INSTALL_DIR=/tmp/dar-backup
mkdir "$INSTALL_DIR"
cd "$INSTALL_DIR"
python3 -m venv venv    # create the virtual environment
. venv/bin/activate     # activate the virtual environment
pip install dar-backup  # run pip to install `dar-backup` into the virtual environment
```

<details>

<summary>🎯 Install details</summary>

```bash
(venv) $ pip install dar-backup
...
Successfully installed argcomplete-3.6.2 dar-backup-1.1.2 inputimeout-1.0.4 markdown-it-py-3.0.0 mdurl-0.1.2 pygments-2.19.1 rich-14.0.0
```

</details>

Setup the demo configurations and show a few operations

<br>

```bash
# See reference section for options tweaking the install
demo --install

# create catalog database
manager --create-db

# FULL backup as defined in backup definition `demo`
dar-backup --full-backup

# List the contents of the backup
dar-backup --list-contents demo_FULL_$(date '+%F')
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
manager.py:     1.1.2
Config file:    /home/user/.config/dar-backup/dar-backup.conf
Logfile:        /home/user/dar-backup/dar-backup.log
dar_manager:    /home/user/.local/dar/bin/dar_manager
dar_manager v.: 1.9.0
======================================



(venv) $ dar-backup --full-backup
========== Startup Settings ==========
dar-backup.py:    1.1.2
dar path:         /home/user/.local/dar/bin/dar
dar version:      2.7.19
Script directory: /home/user/git/dar-backup/v2/src/dar_backup
Config file:      /home/user/.config/dar-backup/dar-backup.conf
.darrc location:  /home/user/git/dar-backup/v2/src/dar_backup/.darrc
======================================



(venv) $ dar-backup --list-contents demo_FULL_$(date '+%F')
========== Startup Settings ==========
dar-backup.py:    1.1.2
dar path:         /home/user/.local/dar/bin/dar
dar version:      2.7.19
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

Perform a restore and show the restored files

```bash
# Restore all files in the backup
dar-backup --restore demo_FULL_$(date '+%F') --verbose

# Prove the files have been restored to directory as configured
find $HOME/dar-backup/restore
```

<details>

<summary>🎯 --restore details</summary>

```bash
(venv) $ dar-backup --restore demo_FULL_$(date '+%F') --verbose
========== Startup Settings ==========
dar-backup.py:    1.1.2
dar path:         /home/user/.local/dar/bin/dar
dar version:      2.7.19
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
> Play with `demo`'s options:
>
> - --root-dir      (perhaps $HOME)
> - --dir-to-backup (perhaps Pictures)
> - --backup-dir    (perhaps /media/user/big-disk)
>
> See log file: `cat "$HOME/dar-backup/dar-backup.log"`
>
> Checkout [systemd timers and services](systemd-setup.md)
>
> Checkout [shell autocompletion (very nice !)](shell-completion.md)
>
> Checkout the [CLI reference](cli-reference.md)
