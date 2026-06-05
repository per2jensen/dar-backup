# dar Tips and Techniques

Back to [README](../../README.md)

- [dar Tips and Techniques](#dar-tips-and-techniques)
  - [List contents of an archive](#list-contents-of-an-archive)
  - [dar file selection examples](#dar-file-selection-examples)
    - [Select a directory](#select-a-directory)
    - [Select files with "Z50" in the file name and exclude .xmp files](#select-files-with-z50-in-the-file-name-and-exclude-xmp-files)
  - [Your restore tests fail with `METADATA_MISMATCH`](#your-restore-tests-fail-with-metadata_mismatch)
  - [Merge FULL with DIFF, creating new FULL](#merge-full-with-diff-creating-new-full)
  - [dar manager databases](#dar-manager-databases)
  - [.darrc sets -vd -vf (since v0.6.4)](#darrc-sets--vd--vf-since-v064)
  - [Separate log file for command output](#separate-log-file-for-command-output)
  - [Trace Logging (Debug details)](#trace-logging-debug-details)
  - [Skipping cache directories](#skipping-cache-directories)
  - [Protecting long backups from systemd-oomd](#protecting-long-backups-from-systemd-oomd)
    - [Solution: run dar-backup as a systemd service](#solution-run-dar-backup-as-a-systemd-service)
    - [Timer example](#timer-example)
    - [Timer vs service enabling](#timer-vs-service-enabling)
    - [Example script run by service](#example-script-run-by-service)

## List contents of an archive

```bash
# Activate your virtual environment
source <the virtual env>/bin/activate
dar-backup --list-contents media-files_INCR_2025-05-10
# Deactivate when done
deactivate
```

Note: `--list-contents` does not touch the restore directory. Cleanup only runs for operations that actually write to `TEST_RESTORE_DIR` (backup verification or a restore to the default location).

gives something like

```text
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   user user  2 Gio   Sat May 10 14:15:07 2025  home/user
[Saved][ ]       [-L-][  93%][ ]  -rw-rw-r--   user user  29 kio  Fri May  9 16:45:38 2025  home/user/data/2023/2023-02-11-Udstilling-Fredericia/DSC_0568.NEF.xmp
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   user user  2 Gio   Fri May  9 12:49:04 2025  home/user/data/2025
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   user user  193 Mio Thu May  8 15:59:17 2025  home/user/data/2025/2025-05-09-Viltrox-25mm-AIR
[Saved][ ]       [-L-][   1%][X]  -rw-rw-r--   user user  15 Mio  Thu May  8 15:52:27 2025  home/user/data/2025/2025-05-09-Viltrox-25mm-AIR/DSC_0563.NEF
```

## dar file selection examples

> **Quoting matters**
>
> Always pass `--selection` as `--selection="-I '*.NEF'"` to ensure it's treated as a single argument.
>
> Avoid splitting `--selection` and the string into separate tokens.

**Why does --selection give "expected one argument" error?**

This happens when the shell splits the quoted string or interprets globs before `dar-backup` sees them.
Use:   `--selection="-I '*.NEF'"`
Avoid: `--selection "-I '*.NEF'"`

> **Tip:** See [dar's documentation](http://dar.linux.free.fr/doc/man/dar.html#COMMANDS%20AND%20OPTIONS)

> **Tip:** To filter all the empty directories away that `dar` emits when listing  contents, append this grep:
>
> ```bash
> |grep -vE '\s+d[rwx-]{9}\s'
>```
>
>Example using the grep to discard directory noise from `dar's` output:
>
> ```bash
> dar-backup --list-contents media-files_INCR_2025-05-10 --selection="-I '*Z50*' -X '*.xmp'" | grep -vE '\s+d[rwx-]{9}\s'
>```

### Select a directory

Select files and sub directories in `home/user/data/2025/2025-05-09-Roskilde-Nordisk-udstilling`

```bash
dar-backup --list-contents media-files_INCR_2025-05-10 --selection="-g 'home/user/data/2025/2025-05-09-Roskilde-Nordisk-udstilling'"
```

### Select files with "Z50" in the file name and exclude .xmp files

```bash
dar-backup --list-contents media-files_INCR_2025-05-10 --selection="-I '*Z50*' -X '*.xmp'"
```

---

## Your restore tests fail with `METADATA_MISMATCH`

You are probably running `dar-backup` as root. Dar-backup injects `--comparison-field=ignore-owner` to `dar` on restores to make life easy for non-root users.

As root is it advised to add the `dar-backup` option `--preserve-ownership` as this makes `dar` restore files with the recorded uid:gid.

From `dar's` [manual page](http://dar.linux.free.fr/doc/man/dar.html):

```test

`--comparison-field=ignore-owner`:

all fields are considered except ownership.

This is useful when dar is used by a non-privileged user. It will not consider a file has changed just because of a uid or gid mismatch and at restoration dar will not even try to set the file ownership.

```

---

## Merge FULL with DIFF, creating new FULL

Over time, the DIFF archives become larger and larger. At some point one wishes to create a new FULL archive to do DIFF's on.
One way to do that, is to let dar create a FULL archive from scratch, another is to merge a FULL archive with a DIFF, and from there do DIFF's until they once again gets too large for your taste.

I do backups of my homedir. Here it is shown how a FULL archive is merged with a DIFF, creating a new FULL archive.

```bash
dar --merge user-homedir_FULL_2021-09-12  -A user-homedir_FULL_2021-06-06  -@user-homedir_DIFF_2021-08-29 -s 12G

# test the new FULL archive
dar -t user-homedir_FULL_2021-09-12

# create Par2 redundancy files
for file in user-homedir_FULL_yyyy-mm-dd.*.dar; do
  par2 c -r5 -n1 "$file"
done
```

---

## dar manager databases

`dar-backup` now saves archive catalogs in dar catalog databases.

This makes it easier to restore to a given date when having many FULL, DIFF and INCR archives.

If the manager does not add an archive to it's catalog database, `dar-backup` will log an error and continue. The important part is verify the archive is usable and continue to other backup definitions.

---

## .darrc sets -vd -vf (since v0.6.4)

These [.darrc](config-reference.md#darrc) settings make `dar` print the current directory being processed (-vd) and some stats after (-vf)

This is very useful in very long running jobs to get an indication that the backup is proceeding normally.

The `dar` output is streamed to the `dar-backup-commands.log` file.

---

## Separate log file for command output

Dar-backup's log file is called `dar-backup.log`.

In order to not clutter that log file with the output of commands being run, a new secondary log file has been introduced `dar-backup-commands.log`.

The secondary log file can get quite cluttered, if you want to remove the clutter, run the `clean-log` script with the `--file` option, or simply delete it.

---

## Trace Logging (Debug details)

To keep the main log file clean while preserving essential debugging information, `dar-backup` creates a separate trace log file (e.g., `dar-backup.trace.log`) alongside the main log.

- **Main Log (`dar-backup.log`)**: Contains clean, human-readable INFO/ERROR messages. Stack traces are suppressed here.
- **Trace Log (`dar-backup.trace.log`)**: Captures ALL messages at `DEBUG` level, including full exception stack traces. Use this file for debugging crashes or unexpected behavior.

You can configure the rotation of this file in `[MISC]`:

```ini
[MISC]
# ... other settings ...
TRACE_LOG_MAX_BYTES = 10485760  # 10 MB default
TRACE_LOG_BACKUP_COUNT = 1      # Keep 1 old trace file (default)
```

---

## Skipping cache directories

The author uses the `--cache-directory-tagging` option in his backup definitions.

The effect is that directories with the [CACHEDIR.TAG](https://bford.info/cachedir/) file are not backed up. Those directories contain content fetched from the net, which is of an ephemeral nature and probably not what you want to back up.

If the option is not in the backup definition, the cache directories are backed up as any other.

---

## Protecting long backups from systemd-oomd

Large backups — especially media collections — cause the Linux kernel to fill the page cache with file data. On desktop systems running `systemd-oomd`, this can trigger an unexpected kill: `systemd-oomd` monitors memory pressure in your user session cgroup (`/user.slice/user-1000.slice/…`) and will sacrifice the largest cgroup in the session — often your terminal emulator — when pressure exceeds its threshold for more than 20 seconds. The backup process dies with it, leaving a corrupt archive and no trace in `dmesg`.

You can confirm this happened with:

```bash
journalctl -u systemd-oomd --since "yesterday" | grep -i killed
```

A line like this is the smoking gun:

```text
Killed …/app-org.gnome.Terminal.slice/vte-spawn-….scope due to memory pressure for
/user.slice/… being 78.16% > 50.00% for > 20s with reclaim activity
```

### Solution: run dar-backup as a systemd service

A systemd service runs under `/system.slice`, completely outside the user session that `systemd-oomd` monitors. The service is immune to user-session OOM kills regardless of memory pressure.

Use `OOMScoreAdjust=-300` to make the kernel's own OOM killer also deprioritise the backup process as a kill candidate (lower is more protected; -1000 would make it unkillable).

Example service file template ( /etc/systemd/system/dar-diff-backups.service ):

```ini
[Unit]
Description=DAR DIFF backups
Wants=network-online.target
After=network-online.target
OnFailure=dar-backup-notify@%n

[Service]
Type=oneshot
WorkingDirectory=/root
UMask=0002

# Runs in system.slice — outside the user session systemd-oomd watches
Slice=backup.slice

# Warm up automounts before starting
ExecStartPre=/usr/bin/mkdir -p /var/log/dar-backup
ExecStartPre=/usr/bin/touch /mnt/dar/warmup
ExecStartPre=/usr/bin/touch /mnt/par2/warmup
ExecStartPre=/usr/bin/touch /mnt/manager/warmup
ExecStartPre=/usr/local/bin/dar --version

ExecStart=/usr/local/sbin/dar-diff-backups.sh

StandardOutput=journal+console
StandardError=journal+console

# Prefer "resistant", not "unkillable" — lower score = less likely to be killed
OOMScoreAdjust=-300

# Lower priority so the desktop stays responsive
Nice=5
IOSchedulingClass=best-effort
IOSchedulingPriority=4

CPUAccounting=yes
MemoryAccounting=yes
IOAccounting=yes

TimeoutStartSec=0

Environment=PYTHONUNBUFFERED=1
Environment=PATH=/opt/dar-backup/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/log/dar-backup /mnt/dar /mnt/par2 /mnt/manager /data/tmp/restore /opt/dar-backup
RestrictSUIDSGID=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

### Timer example

```bash
/etc/systemd/system# cat dar-diff-backups.timer 
[Unit]
Description=dar-backup DIFF timer

[Timer]
OnCalendar=*-*-01 20:03:00
OnBootSec=5min
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
```

### Timer vs service enabling

Only enable the **timer** — not the service. The timer owns the schedule; enabling the service would cause it to start independently at boot.

```bash
systemctl daemon-reload
systemctl enable dar-diff-backups.timer   # correct
# systemctl enable dar-diff-backups.service  # do NOT enable
```

Monitor a running backup with:

```bash
journalctl -u dar-diff-backups.service -f
```

### Example script run by service

```bash
$ cat /usr/local/sbin/dar-diff-backups.sh 

#!/bin/bash
#
#  Run backup definitions in separate processes, try to minimize memory usage
#  Observe the --preserve-ownership option, because this is run by root
#
set -euo pipefail

CONF="/opt/dar-backup/dar-backup.conf"

# Put your definitions here in order.
# (You can generate this list if dar-backup has a "list definitions" command.)
mapfile -t DEFS < <(/opt/dar-backup/venv/bin/dar-backup -c "$CONF" --list-definitions)

result=0

for d in "${DEFS[@]}"; do
  [[ -z "$d" ]] && continue
  echo "==> running: $d"
  set +e
  /opt/dar-backup/venv/bin/dar-backup -D -d "$d" -c "$CONF" --preserve-ownership  --log-stdout  --verbose
  rc=$?
  set -e

  case "$rc" in
    0) ;;
    2) echo "==> soft failure (ignored): $d" ;;
    *) echo "==> HARD FAILURE (rc=$rc): $d" >&2; result=1;;
  esac
done

exit "$result"
```
