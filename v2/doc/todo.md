# TODO

## ~~Verifying~~ DONE (v2-1.1.6)

~~log file verifications in the metrics db, perhaps for the 10 first restores.~~

Implemented in v2-1.1.6 — `verify()` records every restore-test result into a
`restore_test_samples` SQLite table (linked to `backup_runs` via `run_id`), with a
`restore_test_fail_reasons` lookup table for stable failure codes. See
`util.py:write_restore_test_samples()` and the Changelog for details.

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




## Concurrent backup — TOCTOU race (proper fix pending)

`test_concurrent_same_definition_does_not_corrupt_catalog` is marked `xfail` because two
simultaneous `dar-backup --full-backup` processes for the same definition can race past the
`os.path.exists(backup_file + '.1.dar')` guard and both invoke dar. When the slower process's
dar fails (because the archive already exists), it returns rc=1 instead of the expected rc=2,
causing the test assertion to trip.

**Proper fix**: wrap the check→dar→catalog sequence in a per-definition advisory file lock
(`fcntl.flock`) on a lock file such as `{backup_dir}/{definition}.lock`. The lock must be held
from just before the `os.path.exists` check until after `manager --add-specific-archive`
completes. This ensures only one process at a time can create and register an archive for a
given definition, so the losing process always exits at the check with rc=2 rather than
crashing inside dar.

Risk to be verified: ensure the lock file does not interfere with scheduled cron runs or
systemd timer units that legitimately overlap across definitions.

## Testing

- **Low-resource test VM**: set up a Multipass VM (2 CPU, 4 GB RAM) to mirror CI conditions locally. The CI runner's tighter memory budget surfaces resource-sensitive bugs (e.g. stale log-file handles, filesystem cleanup timing) that a 64 GB workstation never triggers.
