# Quick Guide

The purpose of this quick guide is to show how `dar-backup` works in a few simple steps.

The package includes a `demo` application that can help you set up `dar-backup` quickly.

> **From version 1.1.11 the demo never touches your home directory**
>
> It only ever creates/uses these 3 directories under `/tmp`:
>
> - `/tmp/dar-backup` — backups and the log file
> - `/tmp/dar-backup-conf` — `dar-backup.conf` and `backup.d/`
> - `/tmp/dar-backup-data-dirs` — sample data to back up, and the restore-test area
>
> It is assumed they **do not exist** before running the demo. Remove them first with:
>
> ```bash
> demo --cleanup
> ```
>
> Python **>= 3.11** is required

<br>

**Let's roll** with installation, backup, list backup content, restore & restore check

The demo is known to work on an Ubuntu 24.04 clean VM as delivered from `Multipass`

```bash
sudo apt -y install dar par2 python3 python3-venv
INSTALL_DIR=/tmp/dar-backup-venv
mkdir "$INSTALL_DIR"
cd "$INSTALL_DIR"
python3 -m venv venv    # create the virtual environment
. venv/bin/activate     # activate the virtual environment
pip install dar-backup  # run pip to install `dar-backup` into the virtual environment
```

<details>

<summary> Install details</summary>

```bash
(venv) $ pip install dar-backup
...
Successfully installed argcomplete-3.6.2 dar-backup-1.1.10 inputimeout-1.0.4 markdown-it-py-3.0.0 mdurl-0.1.2 pygments-2.19.1 rich-14.0.0
```

</details>

<br>

Setup the demo configurations and show a few operations

```bash
# See reference section for options tweaking the install
demo --install
```

<details>

<summary> --install details</summary>

```bash
(venv) $ demo --install
Directories created.
File generated at '/tmp/dar-backup-conf/backup.d/demo'
File generated at '/tmp/dar-backup-conf/dar-backup.conf'
Sample data generated at '/tmp/dar-backup-data-dirs/dir1'
1. Point dar-backup/manager at the demo config: export DAR_BACKUP_CONFIG_FILE=/tmp/dar-backup-conf/dar-backup.conf
2. Now run `manager --create-db` to create the catalog database.
3. Then you can run `dar-backup --full-backup` to create a backup.
4. List backups with `dar-backup --list`
5. List contents of a backup with `dar-backup --list-contents <backup-name>`
```

</details>

<br>

Set the environment variable that points to the config file
```bash
# dar-backup.conf isn't in dar-backup's default lookup location ($HOME),
# so point it there for the rest of this session
export DAR_BACKUP_CONFIG_FILE=/tmp/dar-backup-conf/dar-backup.conf
```

<br>

Create the catalog database

```bash
# create catalog database
manager --create-db  --verbose
```

<details>

<summary>  create catalog database</summary>

```bash
(venv) $ manager --create-db  --verbose
========== Startup Settings ==========
manager:                   1.1.10
Operation:                 create-db
Config file:               /tmp/dar-backup-conf/dar-backup.conf
Backup dir:                /tmp/dar-backup/backups
Logfile:                   /tmp/dar-backup/dar-backup.log
Trace log:                 /tmp/dar-backup/dar-backup.trace.log
Logfile max size (bytes):  26214400
Logfile backup count:      5
--alternate-archive-dir:   
--remove-specific-archive: 
--relocate-archive-path:   
dar_manager:               /home/user/.local/dar/bin/dar_manager
dar_manager v.:            1.9.0
======================================
```

</details>

<br>

Do a FULL backup
```bash
# FULL backup as defined in backup definition `demo`
dar-backup --full-backup  --verbose
```

<details>

<summary> FULL backup</summary>

```bash
(venv) $ dar-backup --full-backup  --verbose
========== Startup Settings ==========
dar-backup:               1.1.10
Operation:                FULL backup
dar path:                 /home/pj/.local/dar/bin/dar
dar version:              2.7.21
Script directory:         /home/pj/git/dar-backup/v2/src/dar_backup
Config file:              /tmp/dar-backup-conf/dar-backup.conf
.darrc location:          /home/pj/git/dar-backup/v2/src/dar_backup/.darrc
Backup.d dir:             /tmp/dar-backup-conf/backup.d
Backup dir:               /tmp/dar-backup/backups
Restore dir:              /tmp/dar-backup-data-dirs/restore
Logfile location:         /tmp/dar-backup/dar-backup.log
Trace log:                /tmp/dar-backup/dar-backup.trace.log
Logfile max size (bytes): 26214400
Logfile backup count:     5
PAR2 enabled:             True
--do-not-compare:         [!] False
======================================
```

</details>

<br>

```bash
# List the contents of the backup
dar-backup --list-contents demo_FULL_$(date '+%F')
```

<details>

<summary> --list contents details</summary>

```text
(venv) $ dar-backup --list-contents demo_FULL_$(date '+%F')
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   user	user	2 kio	Sat Jul 11 09:20:03 2026	dir1
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   user	user	644 o	Sat Jul 11 09:20:03 2026	dir1/color.jpg
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   user	user	41 o	Sat Jul 11 09:20:03 2026	dir1/color.txt
[Saved][-]       [---][-----][ ]  lrwxrwxrwx   user	user	0	Sat Jul 11 09:20:03 2026	dir1/dar-backup.conf.symlink
[Saved][ ]       [-L-][  56%][ ] *-rw-rw-r--   user	user	4 kio	Sat Jul 11 09:20:03 2026	dir1/dar-backup.conf.hardlink
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   user	user	1 kio	Sat Jul 11 09:20:03 2026	dir1/dir2
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   user	user	644 o	Sat Jul 11 09:20:03 2026	dir1/dir2/color.jpg
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   user	user	46 o	Sat Jul 11 09:20:03 2026	dir1/dir2/color.txt
[Saved][-]       [---][-----][ ]  lrwxrwxrwx   user	user	0	Sat Jul 11 09:20:03 2026	dir1/dir2/dar-backup.conf.symlink
[Saved][ ]       [-L-][  56%][ ] *-rw-rw-r--   user	user	4 kio	Sat Jul 11 09:20:03 2026	dir1/dir2/dar-backup.conf.hardlink
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   user	user	695 o	Sat Jul 11 09:20:03 2026	dir1/dir2/dir3
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   user	user	644 o	Sat Jul 11 09:20:03 2026	dir1/dir2/dir3/color.jpg
[Saved][ ]       [-L-][     ][ ]  -rw-rw-r--   user	user	51 o	Sat Jul 11 09:20:03 2026	dir1/dir2/dir3/color.txt
[Saved][-]       [---][-----][ ]  lrwxrwxrwx   user	user	0	Sat Jul 11 09:20:03 2026	dir1/dir2/dir3/dar-backup.conf.symlink
[Saved][ ]       [-L-][  56%][ ] *-rw-rw-r--   user	user	4 kio	Sat Jul 11 09:20:03 2026	dir1/dir2/dir3/dar-backup.conf.hardlink
```

</details>

<br>

Perform a restore and show the restored files

```bash
# Restore all files in the backup
dar-backup --restore demo_FULL_$(date '+%F') --verbose

# Prove the files have been restored to directory as configured
find /tmp/dar-backup-data-dirs/restore
```

<details>

<summary> --restore details</summary>

```bash
(venv) $ dar-backup --restore demo_FULL_$(date '+%F') --verbose
========== Startup Settings ==========
dar-backup:               1.1.10
Operation:                restore
dar path:                 /home/user/.local/dar/bin/dar
dar version:              2.7.21
Script directory:         /home/user/git/dar-backup/v2/src/dar_backup
Config file:              /tmp/dar-backup-conf/dar-backup.conf
.darrc location:          /home/user/git/dar-backup/v2/src/dar_backup/.darrc
Backup.d dir:             /tmp/dar-backup-conf/backup.d
Backup dir:               /tmp/dar-backup/backups
Restore dir:              /tmp/dar-backup-data-dirs/restore
Logfile location:         /tmp/dar-backup/dar-backup.log
Trace log:                /tmp/dar-backup/dar-backup.trace.log
Logfile max size (bytes): 26214400
Logfile backup count:     5
PAR2 enabled:             True
--do-not-compare:         [!] False
======================================
Success: all backups completed



(venv) $ find /tmp/dar-backup-data-dirs/restore/
/tmp/dar-backup-data-dirs/restore/
/tmp/dar-backup-data-dirs/restore/dir1
/tmp/dar-backup-data-dirs/restore/dir1/color.jpg
/tmp/dar-backup-data-dirs/restore/dir1/color.txt
/tmp/dar-backup-data-dirs/restore/dir1/dar-backup.conf.symlink
/tmp/dar-backup-data-dirs/restore/dir1/dar-backup.conf.hardlink
/tmp/dar-backup-data-dirs/restore/dir1/dir2
/tmp/dar-backup-data-dirs/restore/dir1/dir2/color.jpg
/tmp/dar-backup-data-dirs/restore/dir1/dir2/color.txt
/tmp/dar-backup-data-dirs/restore/dir1/dir2/dar-backup.conf.symlink
/tmp/dar-backup-data-dirs/restore/dir1/dir2/dar-backup.conf.hardlink
/tmp/dar-backup-data-dirs/restore/dir1/dir2/dir3
/tmp/dar-backup-data-dirs/restore/dir1/dir2/dir3/color.jpg
/tmp/dar-backup-data-dirs/restore/dir1/dir2/dir3/color.txt
/tmp/dar-backup-data-dirs/restore/dir1/dir2/dir3/dar-backup.conf.symlink
/tmp/dar-backup-data-dirs/restore/dir1/dir2/dir3/dar-backup.conf.hardlink
```

</details>

<br>

> **Next steps**
>
> Play with `demo`'s options:
>
> - --root-dir      (perhaps $HOME)
> - --dir-to-backup (perhaps Pictures)
> - --backup-dir    (perhaps /media/user/big-disk)
>
> See log file: `cat /tmp/dar-backup/dar-backup.log`
>
> Remove everything the demo created: `demo --cleanup`
>
> Checkout [systemd timers and services](systemd-setup.md)
>
> Checkout [shell autocompletion (very nice !)](shell-completion.md)
>
> Checkout the [CLI reference](cli-reference.md)
