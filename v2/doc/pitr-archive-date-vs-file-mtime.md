# PITR implementation: archive creation date vs. file mtime

**Audience:** Denis Corbin (dar author) and dar-backup contributors.

---

## Background

dar-backup supports Point-in-Time Recovery (PITR): given a user-supplied `--when` timestamp, restore
each requested path from the most recent backup that existed at or before that point.

We investigated replacing our custom selection logic with `dar_manager -w DATE -r paths`
(the native dar_manager PITR mechanism) after the DST off-by-one-hour bug was fixed in
dar 2.7.21RC1. This document records why we chose not to.

---

## Two approaches to PITR

### Approach A: archive creation date (what dar-backup does)

The implementation lives in `_restore_with_dar()` in `v2/src/dar_backup/manager.py`.

**Step 1 — build an archive map.**

`dar_manager --list` is called once per restore operation. Its output is parsed into a
map of catalog number → archive path and a list of `(catalog_no, creation_datetime, type)`
triples. The creation timestamp is extracted from the archive basename, e.g.
`example_FULL_2026-03-21_065621_01` → `2026-03-21 06:56:21`, type `FULL`.

**Step 2 — for each requested path, determine whether it is a file or a directory.**

A filesystem check (`os.path.isdir`) is tried first. If inconclusive, `dar -l` on the
most recent FULL archive is inspected.

**Step 3a — file path restore.**

`dar_manager -f path` returns the list of archive numbers that contain the path and the
mtime recorded there:

```text
1  Fri Mar 21 06:56:21 2026  saved
2  Fri Mar 21 06:56:31 2026  saved
```

`_restore_with_dar` parses this list, keeps only entries whose **archive creation date**
(looked up via the map from step 1) is ≤ the PITR date, then picks the one with the
most recent creation date. It then calls:

```bash
dar -x <archive> -g <path> -R <target> -wa --noconf -Q
```

**Step 3b — directory path restore.**

For directories, `dar_manager -f path` is not useful (it returns entries for the directory
node, not its contents). Instead `_restore_with_dar` builds the full archive chain: the
most recent FULL whose creation date ≤ PITR date, followed by any DIFF archives built on
that FULL whose creation dates are also ≤ PITR date, followed by any INCR archives built
on the most recent such DIFF. Each archive in the chain is applied in order:

```bash
dar -x <FULL>  -g <dir> -R <target> -wa --noconf -Q
dar -x <DIFF>  -g <dir> -R <target> -wa --noconf -Q   # if ≤ PITR date
dar -x <INCR>  -g <dir> -R <target> -wa --noconf -Q   # if ≤ PITR date
```

This reconstructs the directory tree incrementally, exactly as dar's own restore chain
does — but gated strictly on archive creation date, not file mtime.

**Selection criterion throughout: `archive_creation_date ≤ pitr_date`.**

### Approach B: file mtime (dar_manager -w)

`dar_manager -w DATE -r paths` selects, for each path, the archive that recorded
the path with the most recent **mtime ≤ DATE**.

Selection criterion: `file_mtime_recorded_in_archive ≤ pitr_date`.

---

## Why approach B gives wrong results for a rename scenario

POSIX `rename(2)` does **not** update the mtime of the renamed entry. The mtime of a
file or directory records the last time its *contents* changed, not when it was moved.

Consider this backup sequence:

```text
T0  FULL backup created.
    At T0, only directory "l3" exists.
    l3.mtime = T_old  (some time before T0)

T1  User renames "l3" → "l3r" (outside any backup).
    l3r.mtime = T_old  (unchanged by rename — POSIX guarantee)

T2  DIFF backup created.
    "l3r" appears in the DIFF archive for the first time.
    "l3" is absent from DIFF (it no longer exists).
    l3r mtime recorded in archive = T_old
```

Now the user requests a PITR restore to date **T0** (the FULL backup):

| Approach | Reasoning | Decision |
| --- | --- | --- |
| A (archive date) | DIFF created at T2, T2 > T0 → exclude DIFF. | Correct: `l3r` not restored, since it did not exist at T0. |
| B (file mtime)   | l3r.mtime = T_old ≤ T0 → include DIFF. | **Wrong**: `l3r` is restored even though it did not exist at T0. |

With approach B the user receives content from the DIFF archive in what should be a
FULL-date restore. This violates the semantic contract of PITR.

---

## Validation

The failure case above is exercised by the test
`test_pitr_integration_rename_mtime_torture` in `v2/tests/test_pitr_integration.py`.
The test:

1. Creates a FULL backup containing directory `l3`.
2. Renames `l3` → `l3r` without touching its contents (mtime unchanged).
3. Creates a DIFF backup containing `l3r`.
4. Requests a PITR restore to the FULL backup date.
5. Asserts that `l3r` is **not** present in the restored tree.

Approach A (archive date) passes. Approach B (file mtime / `dar_manager -w`) fails.

---

## dar_manager -w is not wrong

For an interactive user who thinks in terms of "restore the version of this file
that had mtime ≤ DATE", `dar_manager -w` is exactly right. The semantics are correct
and well-defined — they just differ from what dar-backup's PITR feature promises.

dar-backup's PITR contract is: *restore the state of the filesystem as it was captured
by the most recent backup on or before the requested date*. That is an archive-creation-
date question, not a file-mtime question.

---

## Summary

| | Archive creation date | File mtime |
| --- | --- | --- |
| dar-backup PITR | **correct** | wrong for renames |
| Interactive `dar_manager -w` use | not natively supported | correct for its stated semantics |

dar-backup therefore implements its own archive-date selection on top of
`dar_manager --list` and `dar_manager -f`, rather than delegating to `dar_manager -w`.
