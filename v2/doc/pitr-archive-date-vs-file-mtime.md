# PITR: archive creation date vs. file mtime

## Quick answer for stressed operators

**dar-backup PITR works correctly as long as your FULL and DIFF backups were taken on
different calendar dates** — which is the normal production schedule.

If you ran a FULL and a DIFF on the *same* calendar date (unusual), and you are trying to
restore to a point *between* those two backups on that day, PITR cannot distinguish them
and will include the DIFF. See [Known limitation](#known-limitation-same-day-full-and-diff)
below.

For every other scenario: pass `--when` with the date/time you want to roll back to and
dar-backup will select the correct archive chain automatically.

---

## The PITR contract

dar-backup's PITR promise is:

> Restore the state of the filesystem **as it was captured by the most recent backup on
> or before the requested date**.

The selection criterion is always: **archive creation date ≤ `--when` date**.

This is anchored to *when the backup ran*, not to when individual files inside it were
last modified.

---

## Why archive creation date — not file mtime

`dar_manager` stores the mtime of every file at the time it was backed up. An alternative
PITR design would use those stored mtimes to decide which archive version of a file to
restore. dar-backup deliberately does not do this, for a good reason.

**The rename problem:**

Consider this sequence:

1. FULL backup runs on Monday. File `report.txt` is saved.
2. On Tuesday, `report.txt` is renamed to `final-report.txt`. The file content and mtime
   are unchanged — a rename does not update mtime.
3. DIFF backup runs on Wednesday. It captures the rename: `report.txt` deleted,
   `final-report.txt` saved (same mtime as Monday's file).
4. You request PITR to Monday 23:00 — a point before the rename.

With mtime-based selection, the filter sees `final-report.txt` with an mtime from Monday,
concludes it was present before the requested date, and restores it. You get a file that
did not exist until Wednesday.

With archive-creation-date selection, the Wednesday DIFF has a creation date after the
Monday request. The DIFF is excluded entirely. You get the Monday FULL state exactly:
`report.txt` present, `final-report.txt` absent. Correct.

**The same rule applies to deletions, directory restructuring, and any change captured in
a DIFF that you are trying to exclude from a PITR restore.**

The failure case is exercised by the integration test
`test_pitr_integration_rename_mtime_torture` in `v2/tests/test_pitr_integration.py`.

---

## What dar-backup uses from dar_manager

dar-backup calls `dar_manager --list` to enumerate archives in the catalog. The creation
date of each archive is parsed from its filename (e.g. `homedir_FULL_2026-06-01` gives
`2026-06-01`). Archive chain selection is then done entirely in dar-backup based on those
dates.

dar-backup does **not** use `dar_manager -w` (mtime-based selection) for PITR. In
addition to the rename correctness problem above, `dar_manager -w` has a DST parsing bug
in versions before 2.7.21.RC1 that causes it to silently exclude files during standard-time
months in any timezone that observes DST. See
[dar_manager_w_dst_bug_report.md](dar_manager_w_dst_bug_report.md).

---

## `dar_manager -w` is not wrong — it answers a different question

For an interactive user who wants *"give me the version of this specific file whose
content was last modified at or before DATE"*, `dar_manager -w` is exactly right. That
is a different question from dar-backup's PITR contract.

See [restoring.md](restoring.md) for how to use `dar_manager -w` directly when that is
what you need.

---

## Known limitation: same-day FULL and DIFF

Archive filenames carry only the calendar date, not the time of day. When
`_select_archive_chain` compares archives by creation date, a FULL and a DIFF both named
`…_2026-06-11` are indistinguishable — both resolve to `2026-06-11 00:00:00`. The DIFF
is always included in the chain for any `--when` timestamp on that day.

**In practice this does not matter** because FULL and DIFF are virtually never taken on
the same calendar date in a normal backup schedule:

- A FULL backup is taken periodically (weekly or monthly). It is added to the catalog at
  that time.
- DIFF backups are taken against that existing FULL on subsequent days. Each DIFF is added
  to the catalog on the day it runs.

For a DIFF to share a calendar date with its parent FULL, someone would have to run a
FULL backup and then immediately run a DIFF against it on the same day — an unusual
pattern.

**If you are in this situation:** the PITR restore will include the DIFF. To get the
FULL-only state you have two options:

1. Restore directly from the FULL archive using `dar-backup --restore <FULL_archive_name>`
   with a path selection (`--selection "-g path/to/restore"`).
2. Remove the DIFF archive from the catalog temporarily, run PITR, then re-add it.

**For test authors:** an automated test that creates both a FULL and a DIFF in the same
session and then asserts between-snapshot PITR behaviour will always fail for this reason.
The between-snapshot scenario is only meaningful — and only works — when FULL and DIFF
are on different calendar dates.
