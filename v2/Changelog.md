<!-- markdownlint-disable MD024 -->
# dar-backup Detailed Changelog

For a high-level summary see [CHANGELOG.md](../CHANGELOG.md) in the repo root.

## v2-1.1.4 - not released

### Added

- **Locale guard in `dar_backup_systemd.py`**: `check_locale()` warns at unit-generation time if `LANG` is not `en_US.UTF-8`; all generated service units now include `Environment=LANG=en_US.UTF-8` so `dar` always runs with the correct locale regardless of the calling shell.
- **Locale guard in `dar_backup.py`**: `_locale_ok()` helper and a startup warning to `stderr` when `LANG` is not `en_US.UTF-8`; `generic_backup()` skips `parse_dar_stats()` and returns an empty stats dict when the locale is wrong, preventing silently corrupt inode metadata.

### Added (tests)

- **Locale tests in `test_systemd_unit_generation.py`** (4 tests): positive — no warning when `LANG=en_US.UTF-8`, `Environment=LANG=en_US.UTF-8` present in both service and cleanup service units; negative — `check_locale()` prints a `WARNING` for a wrong locale.
- **Locale tests in `test_dar_backup_startup.py`** (5 tests): positive — `_locale_ok()` returns `True` and `parse_dar_stats` is called when locale is correct; negative — `_locale_ok()` returns `False`, `main()` emits a locale warning to `stderr`, and `generic_backup()` skips `parse_dar_stats` when locale is wrong.

### Changed

- **`release.sh`** auto-stamps the release date in both changelogs (`CHANGELOG.md`, `v2/Changelog.md`) and updates the `README.md` current-version reference as part of the post-test commit — eliminating two manual pre-release steps that were easy to forget.

## v2-1.1.3 - 2026-03-22

### Added

- PITR integration test `test_pitr_multislice_archive`: verifies PITR restore works correctly across multi-slice archives (`.1.dar`, `.2.dar`, …); proves that content in later slices is actually reached by checking restored file content rather than dar exit code (dar returns 0 on partial/graceful restores).
- PITR integration test `test_pitr_symlinks_and_hardlinks`: verifies that relative symlinks, dangling symlinks, and hard-link pairs are all preserved correctly after PITR restore (symlink targets checked with `os.readlink`; hard links verified via inode equality `os.stat().st_ino`).
- PITR integration test `test_pitr_special_char_filenames`: verifies PITR restore of files whose names contain spaces, Danish characters (æøå / ÆØÅ), colons, hashes, currency symbols, parentheses, `+`, `!`, and brackets; `&` excluded as a known `sanitize_cmd()` limitation (subprocess safety guard rejects `&` even without `shell=True`).
- New doc `v2/doc/pitr-archive-date-vs-file-mtime.md`: explains why dar-backup implements its own archive-creation-date PITR selection instead of delegating to `dar_manager -w`, with a concrete rename/mtime counter-example and a reference to the torture test that validates the design choice.
- New doc section in `v2/doc/restoring.md` — **"Restore a file by its mtime (file-version restore)"**: step-by-step guide for `dar_manager -w` direct use (find `.db`, run `-f` to list versions, restore with `-w -r -e`), date format `YYYY/MM/DD-HH:MM:SS`, caveats (deletions not handled per Denis's own man page; rename/mtime trap; bypasses dar-backup target safety checks). Requires dar ≥ 2.7.21 (DST `tm_isdst=1` bug fixed in `line_tools_convert_date()`).
- **PITR contract** prominently stated at the top of the PITR section in `v2/doc/restoring.md`: selection is by archive creation date, not file mtime; cross-referenced to the new design-decision doc.

### Changed

- Checks for edge cases in PITR expanded
  - Logic determining if an inode is file or dir much more robust
- **`release.sh`** auto-stamps the release date in both changelogs (`CHANGELOG.md`, `v2/Changelog.md`) and updates the `README.md` current-version reference as part of the post-test commit — eliminating two manual pre-release steps that were easy to forget.

### Added (tests)

- **`TestParseDarStats` / `TestWriteMetricsRowGraceful`** (8 unit tests in `test_util.py`): prove that `parse_dar_stats()` always returns a complete dict with `None` for every unmatched field (empty output, garbage output, partial block), and that `write_metrics_row()` stores the row successfully with NULL inode columns when dar < 2.7.21 produces no stats — and silently absorbs DB write errors without propagating them to the backup run.
- **`v2/tests/test_import_archive_metrics.py`**: 51 new unit tests covering all testable functions in `import-archive-metrics.py` — archive filename scanning (current and legacy formats, definition filter, chronological sort), slice size summation, dar stat regex parsing, `dar -l` subprocess handling (not found / timeout / OSError / non-UTF-8 bytes), idempotency checks, DB insert, byte formatting, schema creation, and the `main()` end-to-end path including dry-run, definition filter, missing slices, and multi-archive imports.
- **`v2/tests/test_dashboard_html.py`**: 24 new static-analysis unit tests for `dashboard.html` using Python's `html.parser` (no browser dependency).  Covers: Chart.js CDN script tag has `onerror="window._chartjsFailed=true"`; required DOM element IDs (`trend-panels`, `trends-section-label`) exist; JS failure guard checks both `_chartjsFailed` and `typeof Chart === 'undefined'`; degradation path hides the section label and inserts a user-readable CDN warning; three granularity buttons present with correct `data-gran` attributes and monthly set as the default active; key JS functions (`buildTrendPanels`, `periodKey`, `worstStatus`, `fmtBytes`) are defined; two-dataset chart design markers present (`stepped`, FULL and DIFF/INCR references).

### Added (dashboard & metrics)

- **Two-dataset trend charts** in the dashboard: an indigo stepped line carries the most recent FULL archive size forward between FULL runs; cyan scatter dots show the combined size of all DIFF/INCR runs per period.  This makes it easy to see true data-set growth (FULL line) alongside incremental activity (cyan dots) at a glance.
- Trend panel layout changed to single-column so each chart has full content width.
- Hover tooltip shows both datasets in one popup: FULL size (with `carried fwd` label when no FULL ran in that period), DIFF/INCR combined size + run count, overall worst status, and total run breakdown.
- **`v2/scripts/import-archive-metrics.py`**: standalone idempotent script that seeds the metrics DB from existing `.dar` archives on disk without re-running any backups.  Parses definition, type, and date from the archive filename; sums slice sizes; attempts `dar -l` for inode stats (NULL on failure); supports `--backup-definition` filter for shared archive directories; `--dry-run` previews what would be imported.  Non-UTF-8 filenames in archives (e.g. media collections) handled with `errors='replace'` so the inode-summary block is always parsed cleanly.
- **`v2/doc/dashboard-and-metrics.md`** updated with: two-dataset chart interpretation guide, annotated tooltip examples, screenshot of the trend panels, and full `import-archive-metrics.py` usage documentation including what fields are recovered vs left NULL.

## v2-1.1.2 - 2026-03-15

### Added

- **SQLite metrics database** (`dar-backup-metrics.db`): every backup run now writes a structured row to a SQLite database, capturing identity (definition name, backup type, archive name, version) and capturing `dar's` status messages after a backup.
- Metrics documented, `datasette` suggested as an easy to use metrics db browser.
- **Dashboard** command (`dar-backup-dashboard`) added that fires up `datasette` and then opens a html file in the standard browser
  - [Example dashboard](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/dar-backup-dashboard.png)
  - [Documentation](https://github.com/per2jensen/dar-backup?tab=readme-ov-file#dashboard)

### Fixed

- **Security:** Path traversal vulnerability in `generate_clone_dashboard.py` — the `--downloads-file` CLI argument is now resolved to its canonical path and validated against a blocklist of OS system directories before opening. Symlink-based bypasses (e.g. a link in `/tmp` pointing to `/etc/passwd`) and `..`-component traversals are both caught.
- `manager --add-dir` ignored `-d <backup-def>`, processing all definitions instead of the specified one.
- `manager --create-db` silently skipped corrupted databases; it now runs `dar_manager --check`, backs up the corrupt file as `<name>.db.corrupted.<timestamp>`, and recreates it.
- Fall-through bug in `create_db()`: after renaming a corrupt db, `process` was unset causing an `UnboundLocalError`.

### Changed

- Preflight now detects stale/unavailable backup storage with real write probes, logs startup failures earlier, and falls back to temporary/stderr logging instead of aborting when the configured logfile path is unusable.

## v2-1.1.1 - 2026-02-14

### Changed

- **Heads up:** Backup definition names are now validated. Allowed characters: letters, numbers, spaces, and hyphens. Underscores are rejected by default. Use `--allow-unsafe-definition-names` to skip this validation if you need legacy names.
- Discord reporting improved
- Error "code 2" during backup documented with example
- PITR integration tests now enforce a minimum time spacing between versions to avoid flaky restores on fast systems/CI.
- Restore-test directory cleanup now only runs when an operation will actually write there (backup verification or default restore); `--list-contents` no longer clears it.
- [BUGFIX] Lacking notice in dar-backup.log about missing FULL or DIFF added.
- Logging improvements for command failures: CommandRunner now logs start failures and non-zero exits with pid/returncode, `par2 verify` failures emit errors, and unexpected list-contents errors are logged.
- Cleanup now uses safe deletion for archive slices and warns when unsafe deletions are skipped.
- [BUGFIX] Manager stderr logging on remove-specific-archive failures now reports the correct stderr field.
- Set env var `DAR_BACKUP_COMMAND_TIMEOUT_SECS` to override the config var `COMMAND_TIMEOUT_SECS`

## v2-1.1.0 - 2026-02-05

### Added

- Point-in-Time Recovery (PITR): restore paths as of a specific time via `manager --restore-path --when --target`, with safety checks, logging, and fallback restore when catalogs can't resolve a dated restore.  `--restore-path` accepts multiple space-separated paths in one invocation.
- PITR integration torture tests for rename/mtime traps and catalog rebuild after DB loss.
- PITR dry-run chain report (`manager --pitr-report`) to preview archive selection and detect missing archives.
- PITR fallback now reports missing archive slices and can notify via Discord when configured.
- CommandRunner debug diagnostics now include process PID and elapsed time for each executed command.
- Manager command to relocate archive paths inside catalog databases (`--relocate-archive-path`, with dry-run).
- PITR restore logging now includes the exact archive chain (FULL/DIFF/INCR + timestamps + basenames).
- Tests covering PITR direct-restore flow and relocate-archive-path CLI safeguards.
- PITR preflight flag `--pitr-report-first` to run a chain report before restore and fail fast on missing archives.

### Changed

- The release.sh script is more strict and runs the full pytest suite and commits test reports to doc/test-report
- Github `pytest` workflow uploads test reports in .json and .txt formats
- [Snyk] An XML parsing function now strips DTD to avoid a class of XXE vulnerabilities
- PITR fallback now restores via the latest FULL → DIFF → INCR chain and fails fast when required archives are missing.
- PITR restore now requires `--target` and blocks unsafe restore targets by default.
- Filtered `.darrc` temp files are created in a writable location and cleaned up reliably after runs.
- PITR fallback now validates chain completeness instead of skipping missing archives.
- `COMMAND_TIMEOUT_SECS = -1` disables timeouts for long-running operations.
- Catalog rebuild (`manager --add-dir`) now adds archives in FULL → DIFF → INCR order for the same date to avoid dar_manager prompts.
- PITR restores now always use direct `dar` chain application (skipping `dar_manager -w` restores) to avoid interactive prompts on non-monotonic mtimes.

## v2-1.0.2 - 2026-01-25

### Added

- Streaming restore-test sampling using reservoir sampling to avoid holding full file lists in memory.
- Configurable command output capture cap (`COMMAND_CAPTURE_MAX_BYTES`, default 100 KB) to limit in-memory stdout/stderr while still logging full output.
- Streaming list output for `dar-backup --list-contents` and `manager --list-archive-contents` to avoid large in-memory buffers.
- Test coverage additions for config parsing, util helpers, restore-test sampling edge cases, par2 slice helpers, and get_backed_up_files error paths.
- Cleanup now reports PREREQ/POSTREQ failures cleanly and sends Discord failure notifications when configured.
- New trace logger that always logs at DEBUG and captures stacktraces if they happen. Default max size is 10 MB + 1 rollover file.

### Changed

- BUGFIX: Ensure existing files are removed before restore verification to prevent false positives.
- Clears out restore-test directory on program start to ensure a clean slate.
- Restore-test selection now streams DAR XML listings and samples candidates without loading all entries into RAM.
- `get_backed_up_files` uses incremental XML parsing to reduce memory use for large archives.
- Restore verification now logs a warning and continues when a source or restored file is missing during comparison.
- CommandRunner supports per-command capture cap overrides (disable cap with `capture_output_limit_bytes=-1`).
- Cleanup now rejects unsafe archive names when `--cleanup-specific-archives` is used to prevent accidental deletions.
- Removed deprecated PAR2 layout/mode settings and simplified PAR2 cleanup to delete all matching .par2 artifacts.
- [Snyk] Python 3.11 required in pyproject.toml.
- Config parsing errors now emit concise messages (no stack trace) and trigger Discord failure notifications in CLI tools.

## v2-1.0.1 - 2026-01-09

### Added

- Cleanup `--dry-run` to preview archive, PAR2, and catalog deletions.
- Completion: `cleanup` supports comma-separated archive lists with whitespace normalization.
- Completion: `cleanup` now offers archive-only suggestions after `--cleanup-specific-archives`.
- Optional Discord webhook notifications: `send_discord_message` helper with config-over-env precedence (`DAR_BACKUP_DISCORD_WEBHOOK_URL`), JSON payload, timeout, and detailed error logging.
- Backup runs now emit a per-backup-definition status message (`YYYY-MM-DD_HH:MM - dar-backup, <backup definition>: SUCCESS|FAILURE`).
- dar-backup `--list-definitions` option to list backup definitions from `BACKUP.D_DIR`.
- Automatic preflight checks now run before every invocation (or standalone via `--preflight-check`) to verify required directories, write access, and availability of `dar`/`par2` binaries.
- PAR2 enhancements: optional PAR2_DIR storage, per-archive parity mode, per-backup overrides, and parity manifests to support verify/repair against archives in a different directory.
- Restore test filters: optional case-insensitive prefix/suffix/regex exclusions for restore-test file sampling.
- Env var `DAR_BACKUP_CONFIG_FILE` now supported.

### Changed

- Completion: `dar-backup -l -d <def>` and `cleanup --cleanup-specific-archives -d <def>` now narrow archive suggestions by definition and prefix.
- Skip Discord notifications for the demo/example backup definition to avoid spam during sample runs.
- Discord backup status now includes WARNING when a backup is skipped because it already exists.
- Verification failures and existing-backup skips now emit exit code 2 (warning), while errors continue to emit exit code 1.
- Cleanup deletion hardening (Snyk): validate archive names and enforce safe, base-dir-bound file deletions.
- Removed the rich progress bar wrapper from backup/verify runs to simplify core execution.
- CommandRunner now restores terminal attributes after subprocesses and runs with stdin set to `/dev/null` by default to avoid terminal echo issues.

## v2-1.0.0 - 2025-10-09

[v2-1.0.0 on Github](https://github.com/per2jensen/dar-backup/tree/v2-1.0.0/v2)

- Version 2 **1.0.0** declared stable.
- Expanded test suite and Codecov integration.

---

## Pre-1.0 Development History

### v2-beta-0.8.4 - 2025-08-23

- Option `-D` only added when restoring FULL backups to avoid incorrectly deleting files during DIFF restores.

### v2-beta-0.8.3 - 2025-08-23

- Restore now deletes files marked as "removed" in DIFF and INCR catalogs, ensuring FULL + DIFF + INCR restore matches source directories.
- Options `-wa` and `-/ Oo` added to the restore command.

### v2-beta-0.8.2 - 2025-07-17

- **Security hardening:** CommandRunner performs strict command-line sanitization — disallows dangerous characters (`;`, `&`, `|`) in arguments to prevent injection.
- Documentation on filename restrictions and safe workarounds added.

### v2-beta-0.8.1 - 2025-07-16

- FIX: CommandRunner now logs errors and fills more data into the returned CommandResult.

### v2-beta-0.8.0 - 2025-06-13

- Clone dashboard generator produces a cleaner, more robust dashboard.
- Directory traversal fix: `clean_log.py` now only accepts files in the configured log directory.

### v2-beta-0.7.2 - 2025-06-07

- Build system refactored — all dependencies now in `pyproject.toml`, separated into dev, packaging, and delivery phases.
- `build.sh` used for both Github CI and local dev environment setup.
- Two new optional params to control log file rotation.
- Enrolled in [Snyk code checker](https://snyk.io/code-checker/) — identified vulnerable package versions and started input sanitation.

### v2-beta-0.7.1 - 2025-05-22

- Quick Guide with reworked `demo` program.
- Installer to setup directories and catalog databases from config file.
- `.deb` package for Ubuntu (draft quality — testing only).
- SPDX license headers added.
- Clone stats capture action with dashboard PNG generation and milestone badges.
- Shell autocompletion improvements.
- `--verbose` now controls startup banner display.

### v2-beta-0.6.20.1 - 2025-05-04

- FIX: bash/zsh completers now support `MANAGER_DB_DIR` config.
- `cleanup` and `manager` completers sort archives by definition and date.

### v2-beta-0.6.20 - 2025-05-03

- `show_version()` moved to util with tests for all three commands.
- Improved ConfigSettings class to handle optional configuration keys.
- Optional config parameter `MANAGER_DB_DIR` for storing catalog databases on a separate disk.

### v2-beta-0.6.19 - 2025-04-21

- Bash and zsh autocompletion for CLI.
- `manager --add-specific-archive` warns if adding a catalog breaks chronology, with timeout-guarded user prompt.
- More robust decoding in `command_runner.run()`.

### v2-beta-0.6.18 - 2025-04-05

- Package signing setup using key `dar-backup@pm.me` (OpenPGP.org key server, PyPI signing subkey).
- README.md and Changelog.md included in wheel package.
- New options: `--readme`, `--readme-pretty`, `--changelog`, `--changelog-pretty`.
- Systemd user unit generation and optional installation.
- Progress bar via `rich` showing current directory being backed up.
- Pytest coverage computed and displayed on Github.

### v2-beta-0.6.17 - 2025-03-29

- Prereq/postreq logging moved to debug level; many `.info()` calls changed to `debug()` for cleaner logs.
- Code reorganization: `util.run_command()` replaced with `CommandRunner` class.
- FIX: config_setting init error found by test case.

### v2-beta-0.6.16 - 2025-03-22

- Filtered `.darrc` file from `--suppress-dar-msg` now removed at exit.
- `cleanup` requires confirmation to delete a FULL archive via `--cleanup-specific-archives`.
- Module `inputimeout` introduced for timed user prompts.
- Cleaner default log output; use `--verbose` or `--log-level debug` for more detail.

### v2-beta-0.6.15 - 2025-03-16

- Restore test details logged only with `--verbose`.
- `--log-stdout` no longer shows subprocess output.
- Error exit code 1 if manager fails to add an archive to its database.

### v2-beta-0.6.14 - 2025-03-02

- DAR XML catalog parsing fixed (recursive → iterative). Test case added.
- Error handling improved; `--verbose` prints terse error list on exit.
- Manager no longer passes `-ai` when adding catalogs.

### v2-beta-0.6.13 - 2025-02-25

- `--suppress-dar-msg` option added.
- Separate log file for command outputs to keep `dar-backup.log` readable.
- FIX: leftover `print()` removed from `run_command()`.

### v2-beta-0.6.12 - 2025-02-23

- Environment variable support in paths (command line and config files).
- Proper handling of missing config file (exit code 127).
- Demo installer for config and backup definition setup.

### v2-beta-0.6.11 - 2025-02-23

- `run_command()` handles missing commands gracefully.
- XML parsing refactored from recursive to iterative.
- Input verification for config file existence.

### v2-beta-0.6.10 - 2025-02-22

- Unit test verifying compressed file formats are not double-compressed.

### v2-beta-0.6.9 - 2025-02-21

- `clean-log` script added to strip verbose `dar` output from log files.
- Initial pytest test cases.

### v2-beta-0.6.8 - 2025-02-13

- Transitioned from alpha to beta status.
- `manager --list-archive-contents` added.

### v2-alpha-0.6.7 - 2025-02-11

- Cleanups now remove catalogs from catalog databases.

### v2-alpha-0.6.6 - 2025-02-02

- Archive catalogs added to databases after backup.

### v2-alpha-0.6.5 - 2025-01-24

- Changelog.md added. LICENSE included in wheel. PyPI changelog link.

### v2-alpha-0.6.4 - 2025-01-23

- Stdout/stderr from subprocesses streamed to logfile in real time.
- `.darrc`: `-vd` and `-vf` options enabled for directory-level `dar` output.
- Manager commands added: `--remove-specific-archive`, `--list-catalog`, `--add-dir`.
- PAR2 slices processed by increasing slice number.

### v2-alpha-0.6.2 - 2025-01-12

- Backup functions refactored. PAR2 slice ordering. `--verbose` option for par2 info.

### v2-alpha-0.6.1 - 2025-01-05

- FIX: timeout on `run_command()` — long timeout for heavy operations, default 30 seconds.

### v2-alpha-0.6.0 - 2025-01-05

- Pytest session logger. Prereq failure now causes `dar-backup` to fail.
- FIX: `run_command()` handles large stdout correctly.
- `--restore-dir` documented.

<!-- markdownlint-enable MD024 -->
