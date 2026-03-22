# Restoring

Back to [README](../../README.md)

## Point-in-Time Recovery (PITR)

### What PITR promises

dar-backup selects archives by **archive creation date**, not by file mtime.

> **PITR contract:** restore the state of the filesystem as it was captured by the
> most recent backup on or before the requested date.

This means `--when "2026-03-01 12:00"` restores from the newest archive whose
*backup run* completed at or before that timestamp — regardless of when individual
files inside it were last modified.

This is intentionally different from tools that filter by file mtime. A file that
was renamed (not modified) keeps its old mtime, so a mtime-based filter would
incorrectly include the renamed file in a restore to a point before the rename
happened. dar-backup avoids this by anchoring selection to the archive creation
date. See [pitr-archive-date-vs-file-mtime.md](pitr-archive-date-vs-file-mtime.md)
for the full analysis.

---

Use the `manager` CLI to restore files as they existed at a specific time:

```bash
. <the virtual env>/bin/activate
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path tmp/path/to/file.txt \
  --when "2026-01-29 15:00:39" \
  --target /tmp/restore_pitr \
  --log-stdout --verbose
deactivate
```

Restore a directory (same idea, but the path is a directory):

```bash
. <the virtual env>/bin/activate
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path tmp/path/to/directory/ \
  --when "2026-01-29 15:00:39" \
  --target /tmp/restore_pitr \
  --log-stdout --verbose
deactivate
```

Dry-run the archive chain selection before restoring:

```bash
. <the virtual env>/bin/activate
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path tmp/path/to/directory \
  --when "2026-01-29 15:00:39" \
  --pitr-report \
  --log-stdout --verbose
deactivate
```

**Notes**:

- `--restore-path` must be a relative path as stored in the catalog (no leading slash).
- If a restore path is a **directory** and its name has no file extension, add a trailing `/` to make the intent explicit (e.g., `photos/2026/01/`). This avoids ambiguity with file paths that also lack extensions.
  - Example (directory name has no extension):
    - `manager --backup-def <definition> --restore-path "Automatic Upload/Per - iPhone/2026/01/" --when "now" --target /tmp/restore_pitr`
- `--target` is required to avoid accidental restores into the current working directory.
- Protected targets are blocked (e.g., `/etc`, `/usr`, `/bin`, `/var`, `/root`, `/boot`, `/lib`, `/proc`, `/sys`, `/dev`).
- `--pitr-report` does a **dry-run** chain selection; if it reports missing archives, a restore will fail until the catalog is rebuilt or missing archives are restored.
- `--pitr-report-first` runs the same chain report before a restore and aborts if any archive is missing (useful as a safety preflight).
- `--when` accepts natural-language date expressions via `dateparser`. Examples:
  - `"now"`
  - `"2 weeks ago"`
  - `"2025-10-05 14:30"`
  - `yesterday 23:00`
- PITR restores use the catalog to select the correct archive chain (FULL → DIFF → INCR) and then restore **directly with `dar`** in that order.
  - This avoids interactive `dar_manager` prompts (e.g., non‑monotonic mtimes often seen on pCloud/FUSE).
  - Directories can get a **new mtime** when files inside them are added/removed; the chain restore ensures the correct tree is rebuilt even if mtimes look "too new".
- Missing archives:
  - PITR uses the latest FULL, the latest DIFF after that FULL, and the latest INCR after that DIFF.
  - If any archive slice in that chain is missing on disk, PITR restore **fails** and logs which archive slices are missing.
  - A short Discord notice is sent (if configured) so missing archives are visible immediately.
- Relocating archive paths in the catalog:
  - The catalog stores **absolute archive paths**. If archives move (or a mountpoint changes), the catalog will still point to the old path.
  - This can happen when manager DBs are moved to another disk and the archives are re-added from a different mountpoint.
  - Use the built-in relocate command to rewrite a path prefix in-place:
    - Dry run:
      - `manager --relocate-archive-path /old/path /new/path --relocate-archive-path-dry-run --backup-def <definition>`
    - Apply:
      - `manager --relocate-archive-path /old/path /new/path --backup-def <definition>`
  - Example (move `/home/pj/mnt/dar` to `/mnt/dar`):
    - `manager --relocate-archive-path /home/pj/mnt/dar /mnt/dar --backup-def pCloudDrive`
  - Alternative quick fix: create a symlink from the old path to the new path.
- Rebuilding a catalog after archive loss:
  - If PITR fails due to missing archives, the catalog may no longer match what is actually on disk.
  - You can rebuild the catalog from the remaining archives and then retry PITR (with the understanding that older restore points may no longer be possible).
  - Example:
    - `manager --create-db --config-file <dar-backup.conf>`
    - `manager --add-dir <backup_dir> --backup-def <definition> --config-file <dar-backup.conf>`
  - Or add individual archives:
    - `manager --add-specific-archive <path/to/archive> --config-file <dar-backup.conf>`

Example of the issue:

1) FULL backup at 10:00 with `/data/photos/`
2) You add files at 11:00 (directory mtime updates)
3) DIFF backup at 11:05
4) You request PITR restore of `/data/photos/` at 10:30

`dar_manager -w` may say "directory did not exist before that time" because the directory mtime is now 11:00+.
The fallback still restores the correct tree as of 10:30 by applying the archive chain.

## Restore a file by its mtime (file-version restore)

This is different from PITR. Instead of asking *"what did the backup look like at time T?"*,
you ask *"give me the version of this file whose last-modified time was at or before T"*.

dar's native `dar_manager -w` does exactly this. It selects the archive that recorded the
file with the most recent **mtime ≤ the given date**.

**When to use this instead of PITR:**

| You want... | Use |
| --- | --- |
| The filesystem state captured by the backup closest to a point in time | PITR (`manager --when`) |
| A specific version of a file by when it was last modified | `dar_manager -w` (this section) |

**Requirement:** dar ≥ 2.7.21.RC1 — earlier versions had a DST bug in date parsing that caused
`-w` to silently miss files during standard-time months. See
[dar_manager_w_dst_bug_report.md](dar_manager_w_dst_bug_report.md) for details.

### Step 1 — find the database file

dar-backup stores one catalog database per backup definition. By default these live in the
directory configured as `MANAGER_DB_DIR` in your `dar-backup.conf`. The filename is
`<definition>.db`, e.g. `homedir.db`.

### Step 2 — look up which archives contain the file

```bash
dar_manager -B /path/to/homedir.db -f relative/path/to/file.txt
```

Output lists each archive number that holds the file together with the recorded mtime:

```text
1  Fri Mar 21 06:56:21 2026  saved
2  Fri Mar 21 06:56:31 2026  saved
```

### Step 3 — restore using the mtime filter

```bash
dar_manager -B /path/to/homedir.db \
  -w "2026/03/21-07:00:00" \
  -r relative/path/to/file.txt \
  -e "-R /tmp/mtime-restore -wa -Q"
```

- `-w` date format is `YYYY/MM/DD-HH:MM:SS` in local time.
- `-r` is the relative path as stored in the catalog (no leading slash).
- `-e` passes extra options to `dar` for the actual extraction; `-wa` overwrites
  existing files, `-Q` suppresses interactive prompts.
- The restored file appears under `/tmp/mtime-restore/relative/path/to/file.txt`.

### Caveats

- `dar_manager -r` **does** work across a FULL → DIFF → INCR chain — finding the right
  archive for each file across the full backup history is its core purpose. For each
  requested file it picks the archive that holds the most recent version with mtime ≤ the
  given date.
- **Renames.** If a file was renamed between backups its mtime is unchanged. `-w` may
  therefore return the renamed copy even when requesting a date before the rename occurred.
  Use PITR (`manager --when`) when you need archive-date-accurate recovery.
- This is a direct `dar_manager` call, not a dar-backup CLI feature. It bypasses
  dar-backup's target safety checks, so choose your `-R` target carefully.

---

## Default location for restores

dar-backup will use the TEST_RESTORE_DIR location as the Root for restores, if the --restore-dir option has not been supplied.

See example below to see where files are restored to.

## --restore-dir option

When the --restore-dir option is used for restoring, a directory must be supplied.

The directory supplied functions as the Root of the restore operation.

**Example**:

A backup has been taken using this backup definition:

```text
-R /
-g home/user/Documents
```

When restoring and using `/tmp` for --restore-dir, the restored files can be found in `/tmp/home/user/Documents`

## Restore a single file

```bash
. <the virtual env>/bin/activate
dar-backup --restore <archive_name> --selection="-g path/to/file"
deactivate
```

## Restore a directory

```bash
. <the virtual env>/bin/activate
dar-backup --restore <archive_name> --selection="-g path/to/directory"
deactivate
```

## Restore .NEF from a specific date

The backed up directory contains \*.NEF and \*.xmp files.

Filtering:

- Include files with "2024-06-16" in file name
- Exclude files with file names ending in ".xmp"
- Files must be in directory "home/user/tmp/LUT-play", compared to the file root (`-R`option) in the backup.

```bash
. <the virtual env>/bin/activate
dar-backup --restore <archive_name>  --selection="-I '*2024-06-16*' -X '*.xmp' -g home/user/tmp/LUT-play"
deactivate
```
