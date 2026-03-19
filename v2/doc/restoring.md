# Restoring

Back to [README](../../README.md)

## Point-in-Time Recovery (PITR)

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
