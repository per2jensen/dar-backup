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

## ~~Ownership restoration on real restores~~ DONE (v2-1.1.6)

~~The darrc ships with `--comparison-field=ignore-owner` in the `restore-options`
section so non-root users can restore without permission errors. As a side effect,
uid/gid is never restored even when running as root.~~

Implemented in v2-1.1.6:

- `RESTORE_OWNERSHIP = no` config setting in `[MISC]` (default `no`, backward-compatible)
- `--preserve-ownership` CLI flag (forces uid/gid restore for one run, root only)
- `--ignore-ownership` CLI flag (forces ignore-owner, overrides config)
- Both flags are mutually exclusive via argparse group
- Root warning when running as root with ownership disabled
- `compare_metadata()` updated to optionally check uid/gid (`check_ownership=` param)
- `--comparison-field=ignore-owner` injected programmatically; removed from darrc
- Covered by integration tests (`test_dar_ownership_precedence.py`) and unit tests




## Testing

- **Low-resource test VM**: set up a Multipass VM (2 CPU, 4 GB RAM) to mirror CI conditions locally. The CI runner's tighter memory budget surfaces resource-sensitive bugs (e.g. stale log-file handles, filesystem cleanup timing) that a 64 GB workstation never triggers.
