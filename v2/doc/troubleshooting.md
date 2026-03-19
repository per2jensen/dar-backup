# Troubleshooting

Back to [README](../../README.md)

## Limitations on File Names with Special Characters

`dar-backup` strictly validates all command-line arguments passed to its internal execution engine to protect against command injection and shell-based attacks. As part of this security measure, certain characters are disallowed in user-provided inputs — particularly those that carry special meaning in shell environments:

Disallowed characters include:

```text
\$ & ; | > < ` \n
```

### Why this matters

When restoring specific files using the --selection argument or similar mechanisms, filenames that contain one or more of these characters (e.g., file_with_currency$.txt) cannot be safely passed as command-line arguments. As a result, attempting to restore such a file by name using the CLI will result in a validation error.

- These files are still backed up and restored automatically as part of normal FULL, DIFF, or INCR operations.
- They cannot be explicitly specified for restore using CLI options like --selection="-g path/to/file_with_currency$.txt".

### Blocked characters

| Character | Reason Blocked                  |
|----------:|---------------------------------|
| `;`       | Shell command separator         |
| `&`       | Background execution operator   |
| `\|`      | Pipe operator                   |
| `<` / `>` | Redirection operators           |
| `#`       | Shell comment                   |
| `` ` ``   | Command substitution            |
| `"` / `'` | Quoting that may be unbalanced  |

### Workaround: restore the parent directory

If you need to restore such a file, perform a restore of the entire directory using a more general selection (e.g., --selection="-g path/to/parent-directory") and manually retrieve the restored file afterward.

### Workaround: use `dar` directly

You can always restore the file manually using the `dar` command-line utility itself, bypassing any CLI restrictions imposed by dar-backup.

Example:

```bash
    dar -x /path/to/backup/example -g "weird#name.txt"
```

Where:

- `/path/to/backup/example` is the base name of the archive (without `.dar`, `.1.dar`, etc.).
- `"weird#name.txt"` is the exact filename with the special character(s).

You may need to quote the argument or escape characters depending on your shell.

### How to locate files with forbidden characters

To search for such files inside the archive:

```bash
    dar -l /path/to/backup/example | grep '[#;<>|&]'
```

This will help you identify files that require manual restoration.

### Summary

- Forbidden characters are blocked **only** in CLI arguments to maintain safety.
- Files containing these characters are **still archived and restorable**.
- Use `dar` directly for full manual control when restoring such files.

---

## Backup fails with error code 2

If you see something like this in the log file

````bash
2026-02-07 20:03:45,763 - INFO - ===> Starting INCR backup for /opt/dar-backup/backup.d/user-homedir
2026-02-07 20:03:45,878 - ERROR - Unexpected error during backup
2026-02-07 20:03:45,880 - ERROR - Error during INCR backup process for user-homedir: Unexpected error during backup: CommandResult:
  Return code: 2
  Note: <none>
  STDOUT: Error met while opening the last slice: Data corruption met at end of slice, unknown flag found. Trying to open the archive using the first slice.
````

it could be the DIFF file the INCR job is inspecting that has an error.

In this instance it was due to me doing a hard reboot during the DIFF backup due to a nfs issue, and did not clean up afterwards.

I looked at the trace log file to get more information and found this

````bash
2026-02-07 20:03:45,763 - DEBUG - Executing command: dar -c /mnt/dar/user-homedir_INCR_2026-02-07 -N -B /opt/dar-backup/venv/lib/python3.12/site-packages/dar_backup/.darrc -B /opt/dar-backup/backup.d/user-homedir -Q compress-exclusion verbose -A /mnt/dar/user-homedir_DIFF_2026-02-01 (timeout=86400s)
2026-02-07 20:03:45,764 - DEBUG - Process started pid=93372 cwd=/root
2026-02-07 20:03:45,840 - ERROR - FATAL error, aborting operation: Data corruption met at end of slice, unknown flag found
````

Running a test of the DIFF archive showed the error

````bash
dar -t /mnt/dar/user-homedir_DIFF_2026-02-01
````

which showed the archive is not healthy, so instead of making an INCR, I did a DIFF

````bash
dar-backup -D -d user-homedir --log-stdout
````

Now all is well again :-)

---

## Backup warning about error code 5

`dar-backup` treats this as a warning because a usable dar backup (usually) is the result.

It is good practice to check up on such warnings, to get a sense of the amount of errors and
make sure the backup is useful to you.

During a backup, `dar` may report exit code 5 alongside a summary like:

```txt
13 inode(s) failed to be saved (filesystem error)
```

without making it immediately obvious which files were affected. To find the
failing files, search the `dar-backup` command output log for I/O errors:

```bash
grep -i "error\|failed\|cannot\|permission" ~/dar-backup/dar-backup-commands.log
```

You will see lines like:

```txt
Error while saving /path/to/file.pdf: Error while reading from file: Input/output error
```

### FUSE-mounted filesystems (pCloud, rclone, sshfs, etc.)

A common cause of exit code 5 is a stale or corrupt local cache in a
FUSE-mounted filesystem. This is a known issue with the pCloud Linux client's
Crypto Folder in particular: the FUSE driver reports a file as present (and
`file` or `ls` will show it), but reading its  contents fails mid-stream
with an I/O error. The file itself is healthy on the server — the fault lies
in the local cache.

**Diagnosis:**

```bash
# ls shows the file with correct size
ls -lh "/path/to/pCloudDrive/Crypto Folder/somefile.pdf"

# but reading it fails
cat "/path/to/pCloudDrive/Crypto Folder/somefile.pdf" > /dev/null
# cat: ...: Input/output error
```

If the file downloads correctly via the cloud provider's web interface, the
cache is the culprit.

**Fix — clear the pCloud cache before backup:**

Kill the pCloud client, clear its cache, and restart it before running
`dar-backup`. The pre-backup hook is the right place for this. A script is
provided in `scripts/pre-backup-pcloud-cache-clear.sh`.

The script:

1. Sends SIGTERM to pCloud and waits for it to exit cleanly, releasing all
   file handles before the cache is touched
2. Falls back to SIGKILL if pCloud does not stop within a few seconds
3. Clears the cache directory
4. Restarts pCloud and waits until the Crypto Folder is accessible, with a
   configurable timeout — exiting with code 1 if the folder is not ready
   (e.g. because the Crypto Folder has not been unlocked), which will abort
   the backup cleanly rather than proceeding against an inaccessible mount

See [`scripts/pre-backup-pcloud-cache-clear.sh`](../../scripts/pre-backup-pcloud-cache-clear.sh)
for the full script and configuration notes.

---

## Restore test fails with exit code 4

`dar` in newer versions emits a question about file ownership, which is "answered" with a "no" via the "-Q" option. That in turn leads to an error code 4.

Thus the dar option `--comparison-field=ignore-owner` has been placed in the supplied [.darrc](config-reference.md#darrc) file (located in the virtual environment where dar-backup is installed).

This causes dar to restore without an error.

It is a good option when using dar as a non-privileged user.

---

## Restore test fails with exit code 5

If exit code 5 is emitted on the restore test, FSA (File System specific Attributes) could be the cause.

That (might) occur if you backup a file stored on one type of filesystem, and restore it on another type.
My home directory is on a btrfs filesystem, while /tmp (for the restore test) is on zfs.

The restore test can result in an exit code 5, due to the different filesystems used. In order to avoid the errors, the option `--fsa-scope none` can be used. That will restult in FSA's not being restored.

If you need to use this option, un-comment it in the [.darrc](config-reference.md#darrc) file (located in the virtual environment where dar-backup is installed)

---

## Known Limitations / Edge Cases

- Does not currently encrypt data (by design — relies on encrypted storage)
  - PKI contemplated for a future release

- One backup definition per file in backups.d/
  - this assumption is built deep into `dar-backup`
