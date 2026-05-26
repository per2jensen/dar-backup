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




## Testing

- **Low-resource test VM**: set up a Multipass VM (2 CPU, 4 GB RAM) to mirror CI conditions locally. The CI runner's tighter memory budget surfaces resource-sensitive bugs (e.g. stale log-file handles, filesystem cleanup timing) that a 64 GB workstation never triggers.
