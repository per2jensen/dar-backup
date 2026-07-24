# Advanced restore procedures

Back to the [restore operator guide](restoring.md).

These procedures answer specialized questions and expose more of DAR's native
behavior. Read the target-safety warning for each procedure before running it.

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
