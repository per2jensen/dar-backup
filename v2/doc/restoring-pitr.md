# Point-in-Time Recovery

Back to the [restore operator guide](restoring.md).

## What PITR promises

dar-backup selects archives by **archive creation date**, not by file mtime.

> **PITR contract:** restore the state of the filesystem as it was captured by
> the most recent backup on or before the requested date.

For example, `--when "2026-03-01 12:00"` selects the newest applicable archive
whose backup date is on or before that timestamp, regardless of the mtimes of
individual files.

This matters for renames. Renaming a file normally keeps its old mtime, so an
mtime-based filter can incorrectly include a name that did not exist at the
requested point. PITR instead anchors the state to the backup that captured the
rename. See
[PITR: archive creation date vs. file mtime](pitr-archive-date-vs-file-mtime.md)
for the design analysis and same-day archive limitation.

If you intentionally want a file version selected by its mtime, use the
[manual file-version procedure](restoring-advanced.md#restore-a-file-by-its-mtime).

## Path and archive selection

`--restore-path` values must be relative paths exactly as stored in the
catalog. Leading `/`, empty values, and `..` components are rejected.

Each requested path is evaluated independently:

- A directory is reconstructed by applying the selected FULL → DIFF → INCR
  chain in order.
- For a file, the newest eligible catalog state is authoritative.
  - `saved` means that archive supplies the bytes.
  - `present` means the bytes come from the nearest earlier `saved` state.
  - `removed` means the path was absent at that restore point; PITR exits
    non-zero rather than resurrecting stale data.
- `--restore-path .` selects the archive root and therefore requires a
  completely empty target.

Recover a deleted or renamed-away path by choosing a `--when` before the
archive that recorded its removal.

If a directory name has no extension, add a trailing `/` to make the intent
explicit:

```bash
manager --backup-def <definition> \
  --restore-path "photos/2026/01/" \
  --when "now" \
  --target /tmp/restore-pitr
```

The complete quick-start commands are in the
[restore operator guide](restoring.md#point-in-time-recovery-quick-start).

## Date, time, and timezone behavior

`--when` accepts natural-language expressions through `dateparser`, including:

- `"now"`
- `"2 weeks ago"`
- `"2025-10-05 14:30"`
- `"yesterday 23:00"`

A value without a UTC offset is interpreted as local wall-clock time.

A timezone-aware value such as `2025-12-31T23:00:00Z` or
`2026-07-01T12:00:00+05:45` is converted to the system's local archive
calendar using the timezone rules in effect at the requested instant. This
includes historical DST rules, southern-hemisphere DST, non-hour offsets, and
30-minute DST changes.

Archive filenames currently carry the calendar date but not the backup's time
of day. A FULL and DIFF created on the same calendar date cannot be separated
by a `--when` between those two runs. Production schedules normally place them
on different dates. See
[the documented limitation](pitr-archive-date-vs-file-mtime.md#known-limitation-same-day-full-and-diff).

## Chain selection and validation

PITR uses the catalog to select archives, then invokes DAR directly:

1. The newest eligible FULL.
2. The newest eligible DIFF after that FULL.
3. The newest eligible INCR after that DIFF.

Restoring directly avoids interactive `dar_manager` extraction behavior and
correctly reconstructs directories whose mtimes changed as entries were added
or removed.

Before a directory restore begins, PITR validates every archive in the
selected chain:

- Slices must form a contiguous sequence beginning at slice 1.
- DAR confirms that the highest available slice is the archive's real final
  slice.
- A missing archive, interior slice, or final slice aborts before the first
  archive is applied.
- Single-file restores validate their selected archive in the same way.
- Slice filenames are checked again around extraction. If a slice disappears
  after extraction starts, the restore fails and the target must be treated as
  incomplete.

`--pitr-report` performs chain and slice validation without restoring.
`--pitr-report-first` performs the same preflight immediately before a restore.

This is deliberately lighter than a checksum of every archived byte. Use:

```bash
dar -t <archive-base> -N -Q
```

when a full archive-integrity test is required.

## Missing archives and catalog paths

The catalog stores absolute archive paths. If archives or mountpoints move,
rewrite the old prefix:

Dry run:

```bash
manager --relocate-archive-path /old/path /new/path \
  --relocate-archive-path-dry-run \
  --backup-def <definition>
```

Apply:

```bash
manager --relocate-archive-path /old/path /new/path \
  --backup-def <definition>
```

A symlink from the old archive location to the new location can be used as a
temporary alternative.

Rebuilding a catalog does not repair incomplete multi-slice archives. Restore
the missing slices or use PAR2 first. If an archive is intentionally
abandoned, rebuild without it, understanding that its restore points and
dependent chains may no longer be available:

```bash
manager --create-db --config-file <dar-backup.conf>
manager --add-dir <backup-dir> \
  --backup-def <definition> \
  --config-file <dar-backup.conf>
```

Add one archive with:

```bash
manager --add-specific-archive <path/to/archive> \
  --config-file <dar-backup.conf>
```

If configured, missing-archive failures also produce a short Discord notice.

## When the selected archive is damaged

PITR tries only the correct archive version for the requested restore point.
If DAR cannot extract it because a slice is corrupt or truncated, PITR exits
non-zero. It deliberately does not fall back to an older version and silently
return stale data.

The error identifies the failing archive and lists older versions recorded in
the catalog. Recovery order:

1. Repair the damaged slice so the requested version remains recoverable:

   ```bash
   par2 verify <archive>.<slice-number>.dar.par2
   par2 repair <archive>.<slice-number>.dar.par2
   ```

   See [PAR2 redundancy](par2.md) for both supported storage layouts.

2. Rerun the same restore into a new clean target.

3. If repair is impossible, explicitly select an older restore point:
   - Choose an older archive date from the error output.
   - Set `--when` before the damaged archive's date.
   - Restore into a new clean target.

A merely earlier time may still select the damaged archive. The requested time
must cross the archive-date boundary shown in the error.

## Directory-mtime example

Consider:

1. A FULL at 10:00 contains `data/photos/`.
2. Files are added at 11:00, changing the directory mtime.
3. A DIFF runs at 11:05.
4. PITR is requested for 10:30.

An mtime-based directory query may conclude the directory did not yet exist
because its current mtime is after 10:30. PITR instead excludes the later DIFF
and applies the archive chain eligible at 10:30, restoring the captured tree.

## Real-world validation

PITR was validated against a live media archive in March 2026:

- A 904 GB FULL backup in 85 slices on a network-mounted NAS.
- A request for `--when "2025-12-31 23:59:59"`.
- 337 GB restored in approximately 57 minutes.
- Directories for 2018–2025 were present and the 2026 directory was absent.

The requested archive-date boundary held as specified.
