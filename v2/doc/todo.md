# TODO

## Ruff finding

There are a lot more UP violations than the initial truncated output showed — mostly the typing modernization rules (List→list, Optional→X|None, etc.).

That's a large-scale type-hint refactor.

`BLE`, `TRY`, `DTZ`, and `S` (flake8-bandit security) rule categories were enabled and fully audited (see `v2-1.1.10` Changelog entry). A few sub-rules were deliberately deferred alongside the `UP` rules above, for the same reason — high mechanical effort/review churn relative to correctness value:

- **`G004`** (f-string logging calls, ~160 sites across every file): converting these to lazy `%s`-style args is mechanical but risky (mismatched `%s` counts, lost format specs like `{x:,}`) and mostly a micro-optimization. Not yet enabled.
- **`TRY003`/`TRY300`/`TRY301`**: pure control-flow-shape style preferences (message-outside-exception-class, try/else restructuring, raise-location) with no correctness value. Not yet enabled.
- **`DTZ007`/`DTZ901`**: archive-filename date parsing is deliberately naive (date-only granularity, no time-of-day — see `doc/pitr-archive-date-vs-file-mtime.md`); forcing tz-awareness here risks naive/aware comparison `TypeError`s for no correctness gain. Explicitly ignored in `pyproject.toml`, not deferred for later.

## Testing

- **Low-resource test VM**: set up a Multipass VM (2 CPU, 4 GB RAM) to mirror CI conditions locally. The CI runner's tighter memory budget surfaces resource-sensitive bugs (e.g. stale log-file handles, filesystem cleanup timing) that a 64 GB workstation never triggers.

- **FUSE/NFS coverage in `large_scale_test.sh`**: the large-scale torture test only ever runs against a regular local filesystem. It says nothing about the FUSE-mounted (pCloud, rclone, sshfs) and NFS environments the README calls out as first-class use cases — exactly the environments most likely to produce the I/O errors (dar exit code 5) already documented in `troubleshooting.md`. Worth adding a variant (or a `--source-fuse`/`--source-nfs`-style option) that points the backup definition's `-R`/`-g` at a real FUSE or NFS mount instead of local disk, so the torture test actually exercises the failure-prone path, not just the easy one.
  - Known real-world case motivating this: pCloud's FUSE client currently has 4 files that dar flags as not backed up correctly, confirmed intact via the pCloud web interface — a client-side cache bug, not a dar/dar-backup bug (see `troubleshooting.md`'s "FUSE-mounted filesystems" section). Clearing the pCloud cache fixes the current set but a few *different* files then show the same symptom on the next backup — a recurring, moving-target pattern worth keeping an eye on if this ever gets automated detection.
