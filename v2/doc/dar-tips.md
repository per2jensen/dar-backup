# dar Tips and Techniques

Back to [README](../../README.md)

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
