<!-- markdownlint-disable MD024 -->
# dar-backup Changelog

High-level release summary. For detailed per-release notes see [v2/Changelog.md](v2/Changelog.md).

## v2-1.1.3 - not released

- More robust PITR edge-case handling for file vs directory inodes.
- PITR integration tests extended to cover multi-slice archives, symlinks (relative, dangling, hard links), and special-character filenames; `dar_manager -w` file-version-restore documented.
- Dashboard trend charts redesigned: indigo stepped FULL carry-forward line + cyan DIFF/INCR sum scatter per period; `import-archive-metrics.py` script seeds the metrics DB from existing archives.

## v2-1.1.2 - 2026-03-15

- **SQLite metrics database** records every backup run with structured data; browse with `datasette`.
- **Dashboard** command (`dar-backup-dashboard`) launches `datasette` and opens an HTML overview in the browser.
- **Security fix:** path traversal in `generate_clone_dashboard.py` closed (symlink and `..` bypasses blocked).
- `manager --add-dir` and `manager --create-db` bug fixes for definition filtering and corrupt-database recovery.
- Preflight detects stale/unavailable backup storage earlier with write probes.

## v2-1.1.1 - 2026-02-14

- **Breaking:** Backup definition names are now validated (letters, numbers, spaces, hyphens). Use `--allow-unsafe-definition-names` to opt out.
- Improved Discord notifications, logging, and safe-deletion during cleanup.
- Configurable command timeout via `DAR_BACKUP_COMMAND_TIMEOUT_SECS`.

## v2-1.1.0 - 2026-02-05

- **Point-in-Time Recovery (PITR):** restore paths as of a specific time via `manager --restore-path --when --target`.
- PITR dry-run chain report (`--pitr-report`), fallback restore with Discord notifications, and preflight flag (`--pitr-report-first`).
- Archive path relocation inside catalog databases (`--relocate-archive-path`).
- Catalog rebuild now adds archives in correct FULL/DIFF/INCR order.

## v2-1.0.2 - 2026-01-25

- Streaming restore-test sampling (reservoir sampling) and streaming list output to reduce memory use.
- Configurable command output capture cap (`COMMAND_CAPTURE_MAX_BYTES`).
- Trace logger for always-on DEBUG logging with stacktraces (10 MB + 1 rollover).
- Cleanup reports PREREQ/POSTREQ failures and sends Discord notifications.
- **Security:** XML parsing now strips DTD to prevent XXE. Python 3.11 required.

## v2-1.0.1 - 2026-01-09

- Cleanup `--dry-run` preview and comma-separated archive lists.
- Discord webhook notifications with config-over-env precedence.
- Automatic preflight checks (directories, write access, binary availability).
- PAR2 enhancements: separate PAR2_DIR, per-archive parity, per-backup overrides.
- Restore-test file sampling filters (prefix/suffix/regex exclusions).
- Exit code 2 for warnings (verification failures, existing-backup skips).

## v2-1.0.0 - 2025-10-09

- Version 2 **1.0.0** declared stable.

## Pre-1.0 (beta/alpha)

Development history from v2-alpha-0.6.0 (2025-01-05) through v2-beta-0.8.4 (2025-08-23).
Key milestones:

- **0.8.x** — Security hardening (CommandRunner sanitization), nailing DIFF/INCR restore semantics.
- **0.7.x** — Build system refactor (`pyproject.toml`), Snyk enrollment, shell autocompletion, installer, `.deb` packaging (draft), clone stats dashboard.
- **0.6.x** — Core backup/restore/verify pipeline, `dar_manager` catalog integration, PAR2 parity, environment variable support, `cleanup` confirmation prompts, logging improvements, PyPI packaging.

See [v2/Changelog.md](v2/Changelog.md) for the full pre-1.0 history.

<!-- markdownlint-enable MD024 -->
