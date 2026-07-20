# Restoring

Back to [README](../../README.md)

## Point-in-Time Recovery (PITR)

### Real-world validation

PITR was validated against a live media archive in March 2026:

- **Archive:** a 904 GB FULL backup (85 slices × 10 GB) of a personal media collection
  spanning 2018–2026, stored on a NAS over a network mount.
- **Request:** restore `--when "2025-12-31 23:59:59"` to an isolated target directory.
- **Result:** 337 GB extracted in ~57 minutes; year directories 2018–2025 present,
  2026 directory absent — the date boundary held exactly as specified.

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

Restore multiple paths in one invocation — pass them space-separated after `--restore-path`:

```bash
. <the virtual env>/bin/activate
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path path/to/data media/billeder media/film \
  --when "2025-12-31 23:59:59" \
  --target /tmp/restore_pitr \
  --log-stdout --verbose
deactivate
```

Each path is processed independently, and both kinds follow the same selection rule —
**archive creation date at or before `--when`**. Directories apply the full archive
chain (FULL → DIFF → INCR); files are restored from the newest archive at or before
`--when` that **saved** the file's data (a DIFF that lists an unchanged file as merely
"present" is never selected). File mtimes never drive the selection — if you want a
file version by its *modification time* instead, see
[Restore a file by its mtime](#restore-a-file-by-its-mtime-file-version-restore).

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

- `--restore-path` must be a relative path as stored in the catalog (no leading slash). An
  absolute path or a `..` component is rejected before any restore is attempted.
- `--target` is checked for symlinks: if any path component under `--target` matching a
  requested restore path is a symlink (including a dangling one), the restore is refused
  rather than potentially writing outside the target. Use a clean/empty `--target`.
- If a restore path is a **directory** and its name has no file extension, add a trailing `/` to make the intent explicit (e.g., `photos/2026/01/`). This avoids ambiguity with file paths that also lack extensions.
  - Example (directory name has no extension):
    - `manager --backup-def <definition> --restore-path "Automatic Upload/Per - 2026/01/" --when "now" --target /tmp/restore_pitr`
- `--target` is required to avoid accidental restores into the current working directory.
- Protected targets are blocked (e.g., `/etc`, `/usr`, `/bin`, `/var`, `/root`, `/boot`, `/lib`, `/proc`, `/sys`, `/dev`).
- `--pitr-report` does a **dry-run** chain selection and validates every selected DAR slice set. It requires a contiguous sequence beginning at slice 1 and asks DAR to confirm that the highest available slice is the archive's real final slice. If an archive is missing or incomplete, the report exits non-zero.
- `--pitr-report-first` runs the same chain and slice validation before a restore and aborts if any selected archive is missing or incomplete (useful as a safety preflight).
- PITR slice validation is deliberately lighter than a full archive-integrity scan: it proves that all slices are present, but it does not checksum every archived byte. Use `dar -t <archive-base> -N -Q` when a full integrity test is required.
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
  - Before restoring a directory, PITR validates every archive in the selected chain. A missing interior slice or missing final slice makes the restore **fail before the first archive in that chain is applied**.
  - Single-file restores perform the same validation on their selected archive.
  - Slice filenames are checked again around extraction so a slice disappearing during the operation cannot produce a manager success exit code. If an I/O failure happens after extraction starts, treat the target as incomplete and retry into a clean target.
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
  - Rebuilding a catalog does **not** repair an incomplete multi-slice archive. Restore the missing slices or use PAR2 repair first.
  - If the damaged archive is intentionally abandoned, rebuild the catalog without that archive and retry PITR, understanding that its restore points and dependent chains may no longer be available.
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

### When the selected archive is damaged (fail-fast, no fallback)

PITR file restores try **only the newest archive at or before `--when` that saved
the file's data**. If `dar` fails to extract it — typically a corrupt or truncated slice —
the restore **fails with exit code 1**. dar-backup deliberately does *not* fall back
to an older version: that would deliver stale data behind a success exit code, with
nothing but a log line to tell you the restore is not what you asked for.

The failure is logged at ERROR level and includes dar's stderr and the older
versions recorded in the catalog:

```text
ERROR - dar restore failed for 'data/report.txt' from '/backups/example_DIFF_2026-01-15': CRC error: data corruption
ERROR - Not falling back to an older version of 'data/report.txt'. Older versions in the catalog: #1@2026-01-10 10:00:00 (example_FULL_2026-01-10). If the slice is damaged, try par2 repair first (see doc/par2.md), then rerun. To restore an older version instead, rerun with --when at that version's timestamp, into a clean target.
```

Recovery steps, in order of preference:

1. **Repair the damaged slice** — this recovers the version you actually asked for.
   If you generate PAR2 redundancy files (the default), verify and repair the
   failing slice, then rerun the *same* restore command:

   ```bash
   par2 verify <archive>.<slice number>.dar.par2
   par2 repair <archive>.<slice number>.dar.par2
   ```

   See [par2.md](par2.md) for both PAR2 storage layouts and full instructions.

2. **If the slice cannot be repaired**, restore an older version — explicitly:

   1. Pick an older version from the ERROR message above: it lists each candidate
      as `#<catalog>@<archive date> (<archive name>)`. (To see which archives
      recorded the file at all, `manager --find-file path/to/file.txt -d
      <definition>` lists them — note its timestamps are recorded file mtimes,
      which do not drive PITR selection.)
   2. Rerun the restore with `--when` set at that older version's **archive
      date**. It must be **before the damaged archive's date** — a `--when` that
      is merely earlier than your original one can still select the damaged
      archive again.
   3. Use a **clean/empty `--target`**: a failed `dar` run may have left partial
      files in the previous target, and PITR aborts rather than overwrite
      existing paths.

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

## Inspecting a DIFF or INCR archive directly

### DIFF vs INCR — what each archive contains

- **DIFF** — always taken against the FULL. Every DIFF contains *all* changes since
  the last FULL, regardless of how many DIFFs exist. Multiple DIFFs are therefore
  overlapping (space is traded for simplicity and redundancy — more copies means more
  chances of a successful restore in the future).
- **INCR** — always taken against the latest DIFF. If no DIFF exists, no INCR backups
  are taken. Each INCR contains only the changes since that DIFF, making them
  space-efficient. Restoring requires the full chain (FULL → DIFF → INCR) to
  reconstruct the filesystem.

### Restoring a single archive to a temporary directory

Sometimes you just want to peek at what a particular archive contains — for example
to fish out a file that was modified that day — without restoring the entire chain
first.

Restoring a DIFF or INCR archive directly to an empty directory fails by default
because the archive contains **deletion records** (files removed since the reference
backup). When dar tries to delete those files from the empty restore target they do
not exist, causing a non-zero exit code.

The `--no-deleted` flag tells dar to skip deletion records entirely, so only the
files that were **saved** in that archive are extracted.

**INCR example** — only files new or changed since the previous backup:

```bash
. <the virtual env>/bin/activate
dar-backup --restore my-backup_INCR_2026-06-01 \
  --restore-dir /tmp/incr-look \
  --no-deleted \
  --log-stdout --verbose
deactivate
```

**DIFF example** — all files changed since the last FULL:

```bash
. <the virtual env>/bin/activate
dar-backup --restore my-backup_DIFF_2026-05-27 \
  --restore-dir /tmp/diff-look \
  --no-deleted \
  --log-stdout --verbose
deactivate
```

Files that were unchanged since the reference backup will not be present in the
restore target — they were not saved in this archive. This is expected and correct
for a single-archive restore.

> **Note:** `--no-deleted` is also available on `manager --restore-path` for PITR
> restores, though it is rarely needed there since PITR restores an archive chain to
> a fresh target in the correct order.

---

## Birth time (btime) and FSA restoration

dar can optionally restore **Filesystem Specific Attributes (FSA)**, which on Linux
includes:

- **btime** — the file's birth/creation time
- **Linux inode flags** (set via `chattr`, read via `lsattr`):
  - `i` — immutable: file cannot be modified, deleted, renamed, or hard-linked
  - `a` — append-only: file can only be opened for appending, not overwriting
  - `s` — secure deletion: blocks are zeroed on delete
  - `u` — undeletable: content saved on delete to allow recovery
  - `A` — no atime updates
  - `S` — synchronous writes
  - `j` — data journaling (ext3/ext4)

### The btrfs btime problem

btrfs can internally store a btime whose nanosecond component is ≥ 1,000,000,000
(POSIX allows 0–999,999,999 only). dar faithfully records that value during backup.
When restoring, dar calls `utimensat` to set the btime — the kernel rejects the
out-of-range value and the restore fails with:

```text
cannot set birth time of file, value too high for the system integer type
```

This is commonly triggered by browser profile SQLite files under snap confinement
(e.g. `snap/firefox/common/.mozilla/firefox/.../idb/*.sqlite`).

### Fix: uncomment `--fsa-scope none` in `.darrc`

The shipped `.darrc` contains a commented-out `--fsa-scope none` in the
`restore-options` section. Uncommenting it tells dar to skip all FSA restoration:

- Birth times are **not** restored (the restored file gets the current time as btime)
- Linux inode flags are **not** restored — this includes security-relevant flags:
  - `i` — immutable (cannot be modified, deleted, renamed, or hard-linked)
  - `a` — append-only

File content, ownership (when `--preserve-ownership` is used), permissions, and
standard timestamps (mtime, atime) are fully restored — FSA is separate from these.

If you rely on inode flags being restored (e.g. you use `chattr +i` on files in your
backup set), do **not** enable `--fsa-scope none`. For most home and desktop setups
the trade-off is acceptable: btime is rarely used by applications, and inode flags
on regular user files are uncommon.

---

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
