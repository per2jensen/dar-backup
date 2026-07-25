# Advanced restore procedures

Back to the [restore operator guide](restoring.md).

These procedures answer specialized questions and expose more of DAR's native
behavior. Read the target-safety warning for each procedure before running it.

## In-place overwrite restores

Use `--overwrite-restore-target` only when restoring to a separate staging
tree is impractical, usually because the destination filesystem cannot hold
both the existing tree and a complete restored tree.

This option modifies the requested directory **in place**. There is no later
`mv`, atomic publication, snapshot, or automatic rollback. An interruption,
DAR error, disappearing slice, full filesystem, or target-path replacement
can leave a mixture of old and restored data. A nonzero exit means the target
must be inspected or recovered from a known-good snapshot before it is used.

### Fast incident checklist

Before starting:

1. Stop services, login sessions, sync tools, deployment agents, cleanup jobs,
   and every other writer that can reach the target.
2. Confirm the archive/PITR chain and run `--pitr-report-first` for PITR when
   appropriate.
3. Snapshot the target if the filesystem supports snapshots and space permits.
4. Check free space. In-place restore avoids a second complete tree, but new
   files, file growth, metadata, copy-on-write extents, and temporary work
   still consume space.
5. Inspect ownership, modes, and ACLs. Do not recursively change a live tree
   merely to make the preflight pass.
6. Decide whether backup deletion records should remove target paths. The
   default processes them; `--no-deleted` ignores them.
7. Keep the terminal and log visible. The safety preflight can be lengthy and
   logs before it begins, approximately every ten seconds while scanning, and
   again when it completes.

Direct named-archive restore:

```bash
dar-backup --restore homedir_FULL_2026-07-25 \
  --restore-dir /home/alice \
  --overwrite-restore-target \
  --log-stdout --verbose
```

PITR:

```bash
manager --backup-def homedir \
  --restore-path . \
  --when "2026-07-25 14:00" \
  --target /home/alice \
  --pitr-report-first \
  --overwrite-restore-target \
  --log-stdout --verbose
```

Direct overwrite requires an explicit `--restore-dir`; it never falls back to
`TEST_RESTORE_DIR`. PITR already requires an explicit `--target`. These home
examples assume the `homedir` backup definition uses `/home/alice` as its DAR
filesystem root, so archive path `.` is the home tree. If the archive was
created relative to `/`, selecting `home/alice` below target `/home/alice`
would instead create `/home/alice/home/alice`; inspect the backup definition
and catalog paths before running the command.

### What the safety preflight accepts

The target is opened, descriptor-bound, and locked before the complete
existing target tree is inspected. This whole-target safety preflight does not
estimate only the requested selection. DAR does not start until the scan
completes.

The preflight does not stop at the first blocker. It reports every distinct
problem it finds, up to 100, so an operator can investigate a useful batch
instead of fixing and rerunning one path at a time. If problem 100 is reached,
the scan stops immediately to keep the log bounded and reports that
additional problems may exist. An unreadable entry or directory is itself a
problem; the preflight skips the part it cannot inspect and continues through other
branches while the limit permits.

Every existing directory must:

- Be owned by a trusted UID.
- Have no group-write or other-write mode bit.
- Have no extended POSIX access or default ACL.

For a normal user restore, the restoring UID and target-root owner are the
same trusted identity. For a root-run restore into a user-owned target, both
root and the target-root owner's UID are trusted. This permits, for example,
root-owned administrative directories inside Alice's private home as well as
Alice-owned directories. It does not trust arbitrary third-party owners.

Modes such as `0700`, `0750`, and `0755` do not grant write access to another
identity and can pass. Modes such as `0770`, `0775`, and `0777` fail, even
when the group is a private user group. This is deliberately conservative:
group membership can change, and the restore cannot prove that no other
process holds that identity.

Check a proposed home target without changing it:

```bash
target="/home/alice"
find "${target}" -xdev -type d -perm /022 -print
find "${target}" -xdev -type d ! -user alice ! -user root -printf '%u %m %p\n'
getfacl -R -p -- "${target}"
df -h -- "${target}"
```

The first `find` should print nothing. Review every line from the ownership
check. `getfacl` output containing only the ordinary owner/group/other entries
is not an extended ACL; named users, named groups, mask entries created for
them, or default ACLs require investigation.

The preflight does not follow symlinks. For selected PITR paths, any existing
symlink in the selected path is rejected. Descriptor binding prevents
replacement of the target pathname from redirecting DAR elsewhere; identity
checks before and after every DAR extraction also make a pathname replacement
fail the operation. If replacement occurs after DAR starts, output can be in
the renamed original directory, so preserve both pathnames for diagnosis.

### Home directories, ownership, and `--ignore-ownership`

A non-root user can restore into that user's own private home tree when all
directories meet the rules above. `RESTORE_OWNERSHIP = no` is the default and
makes dar-backup pass `--comparison-field=ignore-owner`, so DAR does not try
to recreate archived uid/gid values that the user cannot assign.

Use `--ignore-ownership` to force that behavior for one run. It does **not**
weaken the preflight and does not ignore current target ownership; it changes
only which archived uid/gid values DAR attempts to apply. Restored entries
will normally be owned by the restoring user.

Use `--preserve-ownership` or `RESTORE_OWNERSHIP = yes` only for a root-run
restore that must recreate the archived identities. Preserving ownership does
not make an untrusted or writable target pass the preflight.

If a home restore fails with:

```text
ERROR: Overwrite safety preflight failed: found 3 problem(s) after inspecting 12,404 entries.
  1. directory '/home/alice/shared-a' is writable by another identity (group or other write permission is set).
  2. directory '/home/alice/shared-b' is owned by untrusted uid 1002; trusted uid(s): 1000.
  3. could not open directory '/home/alice/mounted-data' safely: Permission denied
No restore data was written.
```

the restore did not start. Inspect every reported directory and determine who
uses it. Prefer stopping the writer, restoring a narrower path to private
staging, or taking a snapshot. Do not automatically run recursive `chmod`,
`chown`, or `setfacl`; that can break applications and erase intentional
sharing.

After correcting the understood problems, rerun the command. The entire
preflight runs again. If the previous report stopped at 100, another batch may
appear; repeat investigation until a complete scan reports no problems. A
shorter later list does not prove that an earlier permission change was safe:
review what changed and retain the logs from every attempt.

### Deletions and free-space behavior

Without `--no-deleted`, deletion records in eligible DIFF/INCR archives are
applied and can remove existing target paths. This is normally required to
reconstruct the captured filesystem state. With `--no-deleted`, those records
are ignored and paths deleted in backup history may survive in the target.

In-place overwrite helps when there is not enough free space for a complete
staging copy, but it is not a zero-space restore. Measure the restored data,
not the compressed archive size, and leave operational headroom. If space
runs out after DAR starts, the target is partial and there is no rollback.

### Limits and failure recovery

`--overwrite-restore-target` does not permit protected destinations. `/etc`,
`/root`, `/var`, `/usr`, and the other protected system paths remain rejected.
The planned `--disregard-protected-dirs` option is independent and is not
implemented yet. Restoring `/etc` through dar-backup therefore still requires
private staging followed by a deliberate system recovery procedure.

If an overwrite restore fails after DAR begins:

1. Keep services and users stopped.
2. Preserve the complete log and exit status.
3. Do not treat unchanged-looking files as proof that nothing was modified.
4. Locate the original descriptor-bound directory if the target pathname was
   renamed or replaced.
5. Verify/repair archives and resolve capacity or permissions.
6. Roll back a known-good filesystem snapshot if available. Otherwise,
   restore again from a verified archive into a known state; do not assume a
   blind rerun repairs every partial change.

## Restore a file by its mtime

This is different from PITR:

- PITR asks: “What filesystem state had the backup captured by time T?”
- `dar_manager -w` asks: “Which saved version of this file has the newest
  recorded mtime at or before T?”

| You want | Use |
| --- | --- |
| Filesystem state captured by the backup closest to a point in time | PITR |
| A file version selected by when its content was last modified | `dar_manager -w` |

This procedure requires DAR 2.7.21.RC1 or later. Earlier versions had a DST
date-parsing bug that could silently omit files during standard-time months.

### Safety warning

This is a direct `dar_manager` command. It bypasses dar-backup's protected
directory checks, empty-target checks, selected-path checks, and cooperative
restore lock. Create a dedicated empty target and verify the `-R` argument
inside `-e` before executing it.

### Find the catalog

dar-backup stores one catalog per backup definition. It normally resides in
`MANAGER_DB_DIR` and is named `<definition>.db`, for example `homedir.db`.

List the archive versions containing a path:

```bash
dar_manager -B /path/to/homedir.db \
  -f relative/path/to/file.txt
```

Example output:

```text
1  Fri Mar 21 06:56:21 2026  saved
2  Fri Mar 21 06:56:31 2026  saved
```

Restore the newest recorded mtime at or before the requested time:

```bash
mkdir /tmp/mtime-restore-empty
dar_manager -B /path/to/homedir.db \
  -w "2026/03/21-07:00:00" \
  -r relative/path/to/file.txt \
  -e "-R /tmp/mtime-restore-empty -wa -Q"
```

- `-w` uses local time in `YYYY/MM/DD-HH:MM:SS` format.
- `-r` is the relative catalog path without a leading slash.
- `-e` passes options to DAR extraction.
- `-wa` permits DAR to overwrite, which is why the target must be dedicated
  and empty.

`dar_manager -r` can select versions across a FULL → DIFF → INCR history.
However, a rename keeps the file's old mtime, so mtime selection may return a
name that did not exist at the requested point. Use
[PITR](restoring-pitr.md) when archive-date-accurate state matters.

## Inspecting a DIFF or INCR archive

Sometimes only the entries saved in one archive are needed. A DIFF contains
all changes since its FULL. An INCR contains changes since its reference DIFF.
Neither archive necessarily contains unchanged files.

Restoring a DIFF or INCR by itself can encounter deletion records referring to
files absent from the empty target. `--no-deleted` tells DAR to skip those
deletion records and extract only saved entries.

Inspect an INCR:

```bash
. <the virtual env>/bin/activate
dar-backup --restore my-backup_INCR_2026-06-01 \
  --restore-dir /tmp/incr-look-empty \
  --no-deleted \
  --log-stdout --verbose
deactivate
```

Inspect a DIFF:

```bash
. <the virtual env>/bin/activate
dar-backup --restore my-backup_DIFF_2026-05-27 \
  --restore-dir /tmp/diff-look-empty \
  --no-deleted \
  --log-stdout --verbose
deactivate
```

These commands still use dar-backup's direct-restore safety policy: the target
must be empty and non-protected. Files unchanged since the reference archive
will not appear because they were not saved in this archive.

`--no-deleted` also exists for PITR, though it is rarely needed because PITR
applies the selected archive chain in order. It changes DAR's handling of
deletion records during extraction; it does not make a single-file PITR
restore ignore a newer `removed` catalog state.

## Advanced archive selection

Direct archive restore accepts DAR selection expressions through
`--selection`, while keeping dar-backup in control of the extraction root.

Restore files matching a date in their names, exclude XMP files, and restrict
the search to one archived directory:

```bash
dar-backup --restore <archive-name> \
  --restore-dir /tmp/selected-restore-empty \
  --selection="-I '*2024-06-16*' -X '*.xmp' -g home/user/tmp/LUT-play" \
  --log-stdout --verbose
```

Target redirection, batch, and command-execution options are rejected inside
`--selection`: `-R`/`--fs-root`, `-B`/`--batch`,
`-E`/`--execute`, and `-F`/`--ref-execute`.

## Birth time and FSA restoration

DAR can restore Filesystem Specific Attributes (FSA), including:

- File birth/creation time (`btime`).
- Linux inode flags such as immutable (`i`), append-only (`a`), no-atime
  (`A`), synchronous writes (`S`), and data journaling (`j`).

### The btrfs btime problem

btrfs can expose a birth time whose nanosecond component is outside the POSIX
range. DAR records it, but the kernel rejects it during restore:

```text
cannot set birth time of file, value too high for the system integer type
```

Browser-profile SQLite files under snap confinement are a common trigger.

### Disable FSA restoration

The shipped `.darrc` contains a commented `--fsa-scope none` in its
`restore-options` section. Uncomment it to skip FSA restoration.

Consequences:

- Birth times are not restored.
- Linux inode flags are not restored, including immutable and append-only.
- File content, permissions, standard timestamps, and ownership when enabled
  remain separate from FSA and continue to be restored.

Do not disable FSA if the backup relies on inode flags such as `chattr +i`.
For typical home and desktop data, skipping problematic birth times may be an
acceptable tradeoff.

## Raw DAR restores

Invoking `dar` directly is sometimes necessary for forensic or recovery work,
but it bypasses every dar-backup target-safety policy. Before doing so:

1. Create a new empty target.
2. Resolve and inspect the target path with `realpath`.
3. Confirm every `-R`, `-B`, and execution-related option.
4. Run archive integrity checks before extraction when damage is suspected.
5. Treat any interrupted or non-zero extraction as incomplete.

Prefer the `dar-backup --restore` or `manager --restore-path` entry points
whenever they can express the required operation.
