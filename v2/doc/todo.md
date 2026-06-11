# TODO

## Ruff finding

There are a lot more UP violations than the initial truncated output showed — mostly the typing modernization rules (List→list, Optional→X|None, etc.).

That's a large-scale type-hint refactor.

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
