# PITR: why dar-backup selects by archive creation date

## The contract

dar-backup's PITR promise is:

> Restore the state of the filesystem as it was captured by the most recent backup on or
> before the requested date.

The selection criterion is always: **archive creation date ≤ `--when` date**.

This is anchored to *when the backup ran*, not to any timestamp recorded inside the
archive.

---

## Why this matters

Consider a file that was renamed between two backups. The rename does not change the
file's mtime. A selection mechanism that filters by mtime would include the renamed file
in a restore to a point before the rename happened — delivering content from the wrong
backup.

dar-backup avoids this by anchoring all selection to archive creation date. The rename
happened *after* the FULL backup was created, so the DIFF that captured the rename has a
creation date *after* the FULL. A PITR to the FULL date excludes the DIFF entirely.

The failure case is exercised by the test
`test_pitr_integration_rename_mtime_torture` in `v2/tests/test_pitr_integration.py`.

---

## What dar-backup uses from dar

dar-backup calls `dar_manager --list` to enumerate archives and parse their creation
dates, and `dar_manager -f path` to enumerate which archives contain a given path.
Archive selection is then done entirely in dar-backup based on creation date.

dar-backup does **not** use `dar_manager -w` (mtime-based selection) for PITR.

---

## `dar_manager -w` is not wrong

For an interactive user who wants *"the version of this file whose mtime was at or before
DATE"*, `dar_manager -w` is exactly right. That is a different question from
dar-backup's PITR contract.

See [restoring.md](restoring.md) for how to use `dar_manager -w` directly when that is
what you need.
