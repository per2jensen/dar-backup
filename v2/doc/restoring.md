# Restoring

Back to [README](../../README.md)

This is the operator entry point for restores. Use a dedicated restore target,
check the command before running it, and verify the restored data before using
it.

## Choose the restore method

| What you need | Use |
| --- | --- |
| Filesystem state captured by the latest backup on or before a point in time | PITR with `manager --restore-path` and `--when` |
| Everything, or selected entries, from one named archive | Direct archive restore with `dar-backup --restore` |
| A file version selected by its recorded modification time | Manual `dar_manager -w` |
| Low-level DAR inspection, FSA handling, or complex selection expressions | Advanced restore procedures |

PITR selects by **archive creation date**, not file mtime. See
[PITR restore details](restoring-pitr.md) for its complete behavior, archive
chain selection, timezones, and damaged-archive recovery.

Manual and specialized procedures are documented in
[Advanced restore procedures](restoring-advanced.md). Commands that invoke
`dar` or `dar_manager` directly do not receive dar-backup's target-safety
checks.

## Restore-target safety

dar-backup fails closed when a target does not satisfy the policy for the
requested operation:

| Restore operation | Existing-data policy | Protected directories |
| --- | --- | --- |
| PITR of specific paths | Requested paths must not already exist | Rejected |
| PITR archive root (`--restore-path .`) | Entire target must be empty | Rejected |
| Direct archive restore | Entire target must be empty | Rejected |
| Manual `dar` or `dar_manager` command | No dar-backup protection | No dar-backup protection |

Important details:

- Protected destinations include `/`, `/etc`, `/usr`, `/bin`, `/sbin`,
  `/var`, `/root`, `/boot`, `/lib`, `/proc`, `/sys`, and `/dev`, including
  paths below them. `/tmp`, `/var/tmp`, and `/home` are permitted restore
  locations.
- Target paths are resolved before the protected-directory check. A target
  symlink pointing to `/root`, `/sbin`, or another protected destination is
  rejected.
- For selected-path PITR, existing symlinks in the path below the target are
  rejected, including dangling symlinks. This prevents a restore from being
  redirected outside the target.
- The target is locked cooperatively while it is checked and while DAR runs.
  A concurrent dar-backup restore to the same target is rejected.
- A failed or interrupted extraction may leave a partial target. Do not reuse
  it; retry into a new clean target.

No CLI option currently permits overwriting existing data or bypassing
protected-directory checks.

## Point-in-Time Recovery quick start

Activate the virtual environment and restore a relative catalog path:

```bash
. <the virtual env>/bin/activate
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path path/to/file.txt \
  --when "2026-01-29 15:00:39" \
  --target /tmp/restore-pitr \
  --log-stdout --verbose
deactivate
```

Restore a directory by making the directory intent explicit with a trailing
slash:

```bash
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path path/to/directory/ \
  --when "2026-01-29 15:00:39" \
  --target /tmp/restore-pitr \
  --log-stdout --verbose
```

Restore multiple paths by passing them after one `--restore-path`:

```bash
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path path/to/data media/photos media/film \
  --when "2025-12-31 23:59:59" \
  --target /tmp/restore-pitr \
  --log-stdout --verbose
```

Select the complete archive tree with `.`. Because this can write anywhere
below the destination, the target must be completely empty:

```bash
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path . \
  --when "2025-12-31 23:59:59" \
  --target /tmp/restore-pitr-empty \
  --log-stdout --verbose
```

Preview and validate the selected archive chain without extracting:

```bash
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path path/to/directory/ \
  --when "2026-01-29 15:00:39" \
  --pitr-report \
  --log-stdout --verbose
```

Add `--pitr-report-first` to a restore command to run that preflight before
extraction. Continue with [PITR restore details](restoring-pitr.md) before a
disaster-recovery operation or when restoring across a FULL → DIFF → INCR
chain.

## Direct archive restore quick start

Restore one named archive into an explicitly chosen empty directory:

```bash
. <the virtual env>/bin/activate
dar-backup --restore <archive-name> \
  --restore-dir /tmp/archive-restore-empty \
  --log-stdout --verbose
deactivate
```

When `--restore-dir` is omitted, dar-backup uses the configured
`TEST_RESTORE_DIR` and cleans it before the direct restore. An explicitly
supplied directory is never cleaned automatically and must already be empty.

If the archive was created with:

```text
-R /
-g home/user/Documents
```

then restoring with `--restore-dir /tmp/archive-restore-empty` places the files
under `/tmp/archive-restore-empty/home/user/Documents`.

Restore one file or directory from the archive:

```bash
dar-backup --restore <archive-name> \
  --restore-dir /tmp/archive-restore-empty \
  --selection="-g path/to/file" \
  --log-stdout --verbose
```

```bash
dar-backup --restore <archive-name> \
  --restore-dir /tmp/archive-restore-empty \
  --selection="-g path/to/directory" \
  --log-stdout --verbose
```

`--selection` accepts DAR selection expressions, but it cannot contain options
that redirect the target, load batch options, or execute commands:
`-R`/`--fs-root`, `-B`/`--batch`, `-E`/`--execute`, and
`-F`/`--ref-execute` are rejected.

To inspect only the saved content of a DIFF or INCR archive, see
[Inspecting a DIFF or INCR archive](restoring-advanced.md#inspecting-a-diff-or-incr-archive).

## After the command

Treat a non-zero exit status as a failed restore. For a successful command:

1. Inspect the restored tree and confirm the expected paths are present.
2. Compare critical files with known checksums or another trusted source.
3. Preserve the original archive and catalog until verification is complete.
4. Move data into its final location only after verification.

For archive damage, catalog relocation, historical timezones, deletion states,
and PITR chain behavior, continue with
[PITR restore details](restoring-pitr.md).
