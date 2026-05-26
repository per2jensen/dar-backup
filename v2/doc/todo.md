# TODO

## Verifying

- log file verifications in the metrics db, perhaps for the 10 first restores.
  
  ```sql  
    CREATE TABLE IF NOT EXISTS restore_test_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL,          -- FK to backup_runs.run_id
    backup_definition TEXT NOT NULL,
    archive_name    TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    file_size_bytes INTEGER,
    result          TEXT NOT NULL CHECK (result IN ('PASS', 'FAIL', 'SKIP')),
    fail_reason     TEXT,                   -- NULL on PASS, message on FAIL/SKIP
    tested_at       TEXT NOT NULL
  );
    CREATE INDEX IF NOT EXISTS idx_samples_run_id
       ON restore_test_samples (run_id);
  ```

## Ownership restoration on real restores

The darrc ships with `--comparison-field=ignore-owner` in the `restore-options`
section so non-root users can restore without permission errors. As a side effect,
uid/gid is never restored even when running as root.

For a **real production restore** (not the restore test) a root user would typically
want original ownership preserved. `dar-backup --restore` and `manager` PITR should
gain a way to override this.

Before implementing, verify dar's option precedence: does passing
`--comparison-field=owner` on the command line after `-B darrc restore-options`
actually override the darrc setting, or does dar merge/reject it? A quick manual
`dar` test is needed first.

Design options to evaluate:

- CLI flag `--preserve-ownership` on `dar-backup` and `manager`
- Config setting `RESTORE_OWNERSHIP = yes` (default `no`)
- Automatic override when `os.getuid() == 0`

If the override is added, `compare_metadata()` in `util.py` must also be updated
to conditionally check uid/gid when ownership restoration is active.




## Testing

- **Low-resource test VM**: set up a Multipass VM (2 CPU, 4 GB RAM) to mirror CI conditions locally. The CI runner's tighter memory budget surfaces resource-sensitive bugs (e.g. stale log-file handles, filesystem cleanup timing) that a 64 GB workstation never triggers.
