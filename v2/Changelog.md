<!-- markdownlint-disable MD024 -->
# dar-backup Detailed Changelog

For a high-level summary see [CHANGELOG.md](../CHANGELOG.md) in the repo root.

## v2-1.1.10 - not released

### Fixed

- **Concurrent PITR restores to the same target directory could silently corrupt output** (`manager.py`) — the pre-existence check (does the target already contain files to restore?) and the actual dar invocation were not atomic.  If two `restore_at()` calls targeted the same directory simultaneously, both could pass the check before either ran dar, and dar with `-wa` would then interleave writes from both processes — producing corrupted output with no error logged.  Fixed by acquiring an exclusive non-blocking `fcntl.flock()` on the target directory immediately after `makedirs` and holding it through the end of `_restore_with_dar()`.  The lock is released unconditionally in a `finally` block.  If the lock is already held, the second caller logs a clear error ("Restore target '…' is locked by a concurrent PITR restore — aborting to prevent silent data corruption") and returns 1 without proceeding.  This is a cooperative lock: it prevents concurrent dar-backup PITR processes from racing; it does not block unrelated processes that write to the directory without acquiring the lock.  Two new unit tests cover: (1) a simulated concurrent holder causes the second call to return 1 and never invoke dar; (2) the lock is confirmed released after a successful restore.

- **PITR restore safety check could be bypassed via a symlink, allowing restore into protected system directories** (`manager.py`) — `_restore_target_unsafe_reason()` used `os.path.abspath()` to resolve the target path, which expands `.` and `..` but does **not** follow symlinks.  A symlink at e.g. `/home/user/link` pointing to `/etc` appeared to be under `/home/` and was allowed; dar would then restore files directly into `/etc`.  Fixed by replacing `abspath()` + `normpath()` with a single `os.path.realpath()` call, which follows the full symlink chain to the canonical path before the allow/protect check runs.  This is consistent with how the rest of `manager.py` resolves paths (lines 63, 961, 1178).  Two new tests cover the bypass case (symlink into `/etc` is now blocked) and confirm that symlinks to genuinely safe locations are not false-positived.

- **PREREQ/POSTREQ timeout could hang the process indefinitely when a script spawned background children** (`util.py`) — `subprocess.Popen` was called without `start_new_session=True`, so background children spawned by a script (e.g. `cmd &`) inherited the stdout/stderr pipe file descriptors from the shell.  After the shell exited (or was killed on timeout), those children kept the pipes open, causing the reader-thread `join()` calls to block indefinitely.  Fixed by adding `start_new_session=True` so the shell and all its descendants form a new process group; the process group ID is now captured immediately after `Popen` (before `wait()` reaps the shell PID), and `os.killpg()` is called both on timeout and after normal exit to reap any lingering background children before joining threads.  Thread joins now have a 5-second safety timeout.  Two new unit tests cover the background-child no-hang case and the timeout-raises-promptly case.

- **PAR2 generation gave no diagnostic when it failed mid-run** (`dar_backup.py`) — if `par2 create` failed on slice N of M, the exception propagated silently with only a per-slice error log.  Operators had no summary of how many slices had been protected before the failure.  Each slice's par2 set is self-contained (slice 1's par2 can repair slice 1 independently of whether slice 2 has par2), so the par2 files already written for completed slices are retained — partial coverage is better than none.  The fix wraps the per-slice loop in `try/except`: on failure, if at least one slice completed, a `WARNING` is logged stating exactly how many slices have par2 coverage (e.g. "PAR2 generation failed after 3/10 slice(s) … par2 files for the first 3 slice(s) remain on disk and provide partial recovery coverage").  If the very first slice fails (zero coverage), no coverage warning is emitted.  Two new tests verify: (1) par2 files for completed slices are kept on disk and the coverage warning is logged, (2) no spurious coverage warning appears when zero slices completed.

- **`install_autocompletion()` left the RC file handle unclosed after appending** (`installer.py`) — `rc_file.open("a").write(...)` returned a file object that was written to and immediately discarded without calling `close()`.  CPython closes unclosed handles via reference counting when the object is garbage collected, but this is not guaranteed in alternative Python implementations and is inconsistent with the `with`-statement pattern used everywhere else in the codebase.  Fixed by wrapping the append in a `with rc_file.open("a") as fh:` block.  One new unit test instruments the real file handle's `close()` method to verify it is called explicitly by the `with` statement rather than by the GC.

- **`DoctypeStripper` had no context-manager support — file handle leaked on parse error** (`dar_backup.py`) — `DoctypeStripper` opens a file handle in `__init__` but had no `close()`, `__enter__`, or `__exit__`.  It was passed directly to `ET.iterparse()` without a `with` statement.  If the parser raised mid-parse (malformed XML, I/O error, XXE `ParseError`), the `DoctypeStripper` instance became orphaned and `self.f` was left open until the GC ran — nondeterministic in CPython and not guaranteed in other implementations.  For a long-running backup process verifying many archives this could accumulate open file descriptors until the OS limit was hit.  Fixed by adding `close()`, `__enter__`, and `__exit__` to `DoctypeStripper` and wrapping the `ET.iterparse()` call in `iter_files_with_paths_from_xml()` with a `with` statement.  Using `with` inside a generator correctly handles all three cases: normal exhaustion (exits the block), parse error (exception propagates through `__exit__`), and abandoned iteration (`GeneratorExit` is thrown into the generator at the `yield` point and propagates through the `with` block).  Three new unit tests cover: normal-exit close, exception-exit close, and close-on-ParseError via `iter_files_with_paths_from_xml()`.

- **`_size_in_verification_range()` duplicated the dar unit table from `_parse_size_bytes()`, creating a divergence risk** (`dar_backup.py`) — both functions maintained an identical `dict` mapping dar size units (`o`, `kio`, `Mio`, `Gio`, `Tio`) to byte multipliers.  If a new unit were added to the module-level `_DAR_SIZE_UNITS` table (e.g. `Pio` for pebibytes), `_parse_size_bytes()` would handle it correctly but `_size_in_verification_range()` would silently reject those files, causing them to be dropped from the restore-test sample pool with no error.  Fixed by removing the local dict and delegating entirely to `_parse_size_bytes()`: a `None` return maps to `False`, and the range check runs on the returned byte count.  Five new unit tests cover in-range, below-range, above-range, unparseable input, and the unknown-unit delegation case that directly guards against future divergence.

- **Subprocess spawn failures in `generic_backup()` and `verify()` were silently discarded on systemd** (`dar_backup.py`) — both functions had a bare `print(f"[!] Backup failed: {e}")` in the `except` block that catches `runner.run()` raising (e.g. the process could not be spawned).  On a systemd service stdout is not captured, so this message produced no log file entry and no journal record — the only observable signal was the exception propagating up.  Additionally, the message in `verify()` said "Backup failed" even though the failing operation was the archive integrity test, making triage harder.  Fixed by replacing both `print()` calls with `logger.error()` carrying the correct operation name: `generic_backup()` now logs "Backup command could not be run for …" and `verify()` logs "Verification command could not be run for …".  Two new component tests assert `logger.error` is called with the correct operation name when `runner.run()` raises.

- **Missing archive slice or par2 file after successful backup caused a false FAIL** (`dar_backup.py`) — after dar completed, `_list_dar_slices()` enumerated `.dar` slices and then `os.path.getsize()` was called on each; similarly, after par2 generation, `glob.glob()` enumerated `.par2` files and `os.path.getsize()` was called on each.  In both cases an unhandled `OSError` (e.g. a file that disappeared between the enumeration and the stat call) propagated to the outer `except Exception` and marked the entire backup as `FAILED`.  The two cases have different semantics and are fixed differently: (1) a missing `.dar` slice means the archive is genuinely incomplete — the `OSError` is now caught, an `ERROR` is logged clearly naming the missing slice (so blame does not fall on the dar phase, which already exited with code 0), and then re-raised so the backup is still recorded as `FAILURE`; (2) a missing `.par2` file after successful generation is a degraded but not data-loss state — par2 files are now measured individually so that the partial sum of available files is still recorded (e.g. 9 out of 10 files present still yields a meaningful metric), each missing file is logged as a `WARNING` naming the specific file, and the backup completes as `SUCCESS`.  Three new component tests cover: the dar-slice missing case, the all-par2-files-missing case (`par2_size_bytes = NULL`), and the partial-par2 case (partial sum stored, missing file named in warning).  Monkeypatched `os.path.getsize` used per project convention for OS-level TOCTOU failures.

- **Stale restore file in the verify phase caused a false FAIL** (`dar_backup.py`) — when a file already existed at the restore target path, `os.remove()` was called before the dar restore.  If `os.remove()` raised `OSError` (e.g. read-only mount, wrong ownership), the exception was silently swallowed with a bare `except OSError: pass`.  The stale file remained on disk and the dar restore command did not include `-wa`, so dar refused to overwrite the existing file and returned non-zero — marking the sample as `FAIL` even though the archive was intact.  Fixed by logging the `OSError` as a `WARNING` (so operators can diagnose permission problems in the restore directory) and adding `-wa` to the dar restore command so the file is overwritten regardless of whether the prior removal succeeded.  This is now consistent with `restore_backup()` and `_restore_with_dar()`, which already passed `-wa`.  Two new tests cover the warning-is-logged path (monkeypatched `os.remove` per project convention for OS-level failures) and assert that `-wa` is present in the captured dar command.

## v2-1.1.9 - 2026-06-20

### Added

- **Instance lock prevents concurrent backup runs** (`dar_backup.py`) — a per-config `fcntl.flock`
  exclusive lock is acquired at startup for all backup operations (`--full`, `--differential`,
  `--incremental`) and released on exit.  The lock path is derived from the config file's absolute
  path with `/` and spaces replaced by `_`, placed under `/run/lock/` (tmpfs on systemd systems,
  auto-cleared on reboot) or `tempfile.gettempdir()` as fallback.  A second invocation that finds
  the lock held exits immediately with rc=1; the error is logged at ERROR level and recorded in the
  metrics DB as a `PREREQ / FAILURE` row so the dashboard shows the blocked run.  The lock is
  kernel-held and released automatically on process death (power cut, SIGKILL, crash) — no stale
  lock files.  DEBUG messages are written when the lock is acquired and released.

- **26 new PITR unit tests in `test_pitr_edge_cases.py`** — filled coverage gaps for helper functions:
  `_missing_chain_elements`, `_is_directory_path`, `_is_directory_in_archive`, `_format_chain_item`,
  `_describe_archive`, and additional edge cases for `_select_archive_chain` (notably when_dt between DIFF
  and INCR).  All tests follow real-filesystem conventions with `tmp_path` fixture and proper type
  hints.

### Changed

- **`get_backed_up_files()` — removed `_is_mock_object` test fork** (`dar_backup.py`) — the function
  previously used `subprocess.Popen` directly with a manual stderr thread, and contained a
  `_is_mock_object` branch so unit tests could intercept it via a mock runner.  Refactored to go
  through `runner.stream_command()` (the same path used by `list_contents()`), eliminating the test
  fork entirely.  Production and test code now execute the same path.

### Fixed

- **`write_metrics_row()` silently swallowed exceptions when logger was `None`** (`util.py`) — the
  exception handler called `get_logger()` and only logged if it returned a non-`None` value;
  because `util.logger` is `None` until `setup_logging()` is called, any SQLite failure during that
  window (wrong path, locked DB, disk full) was completely silent.  Fixed by falling back to
  `logging.getLogger(__name__)` so a warning is always emitted.

- **`backup_file` undefined in `finally` block could silently drop a metrics row** (`dar_backup.py`)
  — `backup_file` was assigned inside the `try` block; if an exception occurred before that
  assignment the `finally` block raised `NameError` on the `glob.glob(f"{backup_file}.*.dar")`
  call, preventing `write_metrics_row()` from being reached.  Fixed by initialising
  `backup_file = None` before the `try`, guarding the glob against `None`, and emitting a distinct
  error message (`"Archive path not constructed — exception raised before backup path was set up"`)
  instead of the misleading "No archive slices found" message.

- **PREREQ/FAILURE rows now show `"no archive produced"` in `archive_name`** (`dar_backup.py`)
  — lock-blocked and prereq-failed runs previously wrote `NULL` to `archive_name`, which displayed
  as an empty cell in the dashboard and could look like a data error.  The field is now set to the
  literal string `"no archive produced"` so the row is self-explanatory.

- **"Archive already exists" skip left `error_summary` NULL in the metrics row** (`dar_backup.py`)
  — when a backup was skipped because today's archive already existed, the WARNING metrics row
  written by the `finally` block had `error_summary = NULL`; the reason was only derived
  indirectly via `first_error` logic that could be confused by other results.  `error_summary` is
  now set explicitly to the skip message before `continue` so the field is always populated.

- **Startup banner printed for non-backup operations** (`dar_backup.py`) — the `##  dar-backup INCR  ##`
  banner and `START TIME`/`END TIME` markers were emitted unconditionally, so commands such as
  `-l` (list archives) or `--restore` appeared in the log as INCR backup runs.  The banner and
  timing markers are now only logged when an actual backup operation (`--full`, `--differential`,
  `--incremental`) is being performed.

- **`Operation:` field missing from startup settings** (`dar_backup.py`, `cleanup.py`, `manager.py`)
  — the startup settings block logged version, paths, and config but gave no indication of which
  operation was being run.  Each tool now appends an `Operation:` line (e.g. `list archives`,
  `INCR backup`, `cleanup`, `restore-path (PITR)`) as the second entry, always visible at INFO
  level regardless of `--verbose`.  Detection is wrapped in `try/except`; on any error a WARNING
  is logged and the value falls back to `"unknown"` so the operation itself is never affected.
  The now-redundant `Type of backup:` entries were removed from `dar_backup.py`.

- **`stream_command()` hung on `KeyboardInterrupt` when child spawned background processes**
  (`command_runner.py`) — when a signal arrived while `stream_command()` was reading stdout, the
  `finally: stderr_thread.join()` block would block indefinitely if the child process had launched
  background subprocesses (e.g. `sleep N &` in a shell script): those grandchildren inherited the
  stderr pipe file descriptor, so the pipe never closed and the reader thread never saw EOF.  In
  practice this meant a `SIGINT` or `SIGTERM` during the verify phase could not propagate to
  `perform_backup()`'s signal handler — the process would hang until systemd's stop timeout issued
  `SIGKILL`, with no "interrupted" message logged.  Fixed by:

  - Starting the child process with `start_new_session=True` so it leads its own process group,
    isolating it and all its descendants from the parent's group.
  - Replacing `process.kill()` with `os.killpg()` at both kill sites (timeout path and the new
    `finally` guard), ensuring all members of the child's process group — including background
    grandchildren — are killed, the stderr pipe is fully closed, and the reader thread exits cleanly.

## v2-1.1.8 - 2026-06-11

### Fixed

- **`cat_no_for_name()` wrong catalog match** (`manager.py`) — the regex used to locate an
  archive's catalog number interpolated the archive name directly without `re.escape()` and without
  anchoring, so `media_FULL_2026-01-01` could match a catalog-list line for
  `media2_FULL_2026-01-01`, causing `remove_specific_archive()` to delete the wrong entry.  Fixed
  by switching to a tab-split exact-field comparison against `parts[2]` (the column that
  `list_catalogs` already extracts as the archive name), which is unambiguous and immune to
  special-character issues.

- **`_restore_target_unsafe_reason()` allow-list gap** (`manager.py`) — `startswith(allow_prefixes)`
  accepted any path whose first characters matched a prefix tuple entry, so `/tmpfoo` and
  `/homestead` were silently allowed.  Fixed to use `prefix + os.sep` (matching the same pattern
  the protected-prefix check already used correctly).

- **`add_directory()` always exited 0** (`manager.py`) — the function returned `None` on both
  success and per-archive failure, so `sys.exit(add_directory(...))` always reported success to
  systemd and calling scripts.  Fixed by returning `1` if any archive failed to add, `0` otherwise.
  Also fixed a missing `{result}` interpolation in the final debug log line.

- **`setup_logging()` bad config path continued silently** (`dar_backup.py`) — if
  `logfile_location` did not end with `dar-backup.log`, the code printed an "exiting" message but
  then continued, silently aliasing the command-output log to the main log.  Added the missing
  `exit(1)`.

- **`filter_darrc_file()` used private `tempfile._get_candidate_names()`** (`dar_backup.py`) —
  replaced with the public `tempfile.mkstemp()`, which also avoids the previous TOCTOU race between
  generating a name and opening the file.

- **Duplicate `-c` flag in cleanup argument parser** (`cleanup.py`) — `argparse.add_argument` was
  called with `'-c', '--config-file', '-c'`; the duplicate was silently tolerated but is now
  removed.

- **Discarded `ArgumentParser` in `manager.main()`** (`manager.py`) — `argparse.ArgumentParser()`
  was constructed and immediately overwritten by `build_arg_parser()`.  The dead call is removed.

- **`datetime.utcnow()` deprecated** (`dar_backup.py`) — replaced with
  `datetime.now(timezone.utc)` (already imported) in `write_par2_manifest()`.

- **`List[(str,int)]` invalid type annotation** (`dar_backup.py`) — corrected to
  `List[Tuple[str, int]]`.

- **Dead `raw_config` block in `main()`** (`dar_backup.py`) — duplicate config-path resolution that
  was superseded by `get_config_file(args)` on the very next line; removed.

- a restore-test after a backup would previously result in a WARNING, it is now an ERROR
  
  - A test case now proves an ERROR is issued in the log and in the metrics DB.

- **`get_backed_up_files()` — temp file leaked on timeout** (`dar_backup.py`) —
  the `subprocess.TimeoutExpired` handler raised `BackupError` without removing the
  temporary XML file, because `TimeoutExpired` is caught before the `except Exception`
  block that contained the cleanup.  Fixed by adding the same `os.remove(temp_path)`
  guard to the `TimeoutExpired` handler.

- **`verify()` — missing source file recorded as SKIP but counted as failure** (`dar_backup.py`) —
  when a `FileNotFoundError` occurred (source file deleted between backup and verify), the sample
  was recorded as `result="SKIP"` in the metrics DB while `restore_test_passed` was set to `0`
  (failure).  The two signals contradicted each other: the sample said "skipped" but the run was
  marked failed.  Fixed by recording the sample as `result="FAIL"` and logging at `ERROR` level,
  consistent with the aggregate result — if the file is gone it cannot be verified or restored.

- **Signal propagation in generated systemd units** (`dar_backup_systemd.py`) — the generated
  `ExecStart` line ran the backup tool as a child of a bash subshell.  When systemd sent `SIGTERM`
  (e.g. on shutdown or `systemctl stop`), bash received the signal but did not forward it to the
  Python process, which could be left running until systemd sent `SIGKILL` after the stop timeout —
  risking stale dar lockfiles or half-written archives.  Fixed by prepending `exec` to the tool
  invocation so bash replaces itself with the Python process, making it the direct target of any
  signal from systemd.

- **Locale handling — any UTF-8 locale now accepted** (`dar_backup_systemd.py`, `dar_backup.py`) —
  previously the codebase enforced `LANG=en_US.UTF-8` system-wide: the generated systemd service
  units hard-coded `Environment=LANG=en_US.UTF-8` and `check_locale()` warned for any other locale
  including valid ones such as `de_DE.UTF-8`.  This was unnecessary because `CommandRunner` already
  pins `LC_ALL=C` for every `dar` subprocess, which guarantees English-formatted diagnostic output
  for `parse_dar_stats()` regardless of the caller's locale.  Changes:

  - Generated service units now set `Environment=LC_MESSAGES=C` instead of `LANG=en_US.UTF-8`.
    `LC_MESSAGES=C` keeps dar's messages in English for parsing; `LANG` is inherited from the user
    session and can be any `*.UTF-8` locale.
  - `check_locale()` now warns only when `LANG` has no UTF-8 encoding (e.g. bare `C`, `POSIX`),
    which would mangle non-ASCII file paths.  Any `*.UTF-8` locale — `en_US.UTF-8`, `de_DE.UTF-8`,
    `da_DK.utf8`, etc. — is accepted without warning.  The locale name normalisation also handles
    the Linux `utf8` (no hyphen) spelling alongside the standard `UTF-8` spelling.
  - Dead code removed: `REQUIRED_LANG` constant and `_locale_ok()` function in `dar_backup.py`
    (superseded by `LC_ALL=C` in `CommandRunner`).

- **Config parse errors now name the offending key and section** (`config_settings.py`) — a bad
  value such as `DIFF_AGE = 5x` previously produced a generic `"Invalid value in config: invalid
  literal for int() with base 10: '5x'"` with no indication of which key was at fault.  Now every
  integer parse failure reports the key name, section, and bad value:
  `"Expected an integer for 'DIFF_AGE' in [AGE], got: '5x'"`.  Changes:

  - New `_get_int(section, key)` helper used for all 7 mandatory integer fields in `__post_init__`
    (`MAX_SIZE_VERIFICATION_MB`, `MIN_SIZE_VERIFICATION_MB`, `NO_FILES_VERIFICATION`,
    `COMMAND_TIMEOUT_SECS`, `DIFF_AGE`, `INCR_AGE`, `ERROR_CORRECTION_PERCENT`).
  - `_get_optional_int` hardened with the same specific error (previously also did a bare `int()`).
  - The three per-backup-definition `PAR2_RATIO_*` overrides in `get_par2_config()` now raise
    `ConfigSettingsError` with key, section, and bad value rather than a raw `ValueError`.
  - Added `except ConfigSettingsError: raise` as the first handler in the `__post_init__`
    try/except block so specific errors raised internally are no longer swallowed by the broad
    `except Exception` fallback.

### Changed

- **`CommandRunner.stream_command()` consolidates streaming subprocess pattern** (`command_runner.py`, `manager.py`, `dar_backup.py`) —
  `list_catalogs()`, `list_archive_contents()`, and `list_contents()` each contained their
  own copy of the same ~40-line block: open `Popen`, drain stderr in a background thread with
  capping, read stdout line by line, wait with timeout, close the log file.  The block is now
  in a single `CommandRunner.stream_command(cmd, line_callback, *, timeout)` method; callers
  supply a callback that receives each decoded stdout line and decide what to keep or print.
  The per-function dual path (mock branch vs real subprocess branch) is gone; all paths go
  through `runner.stream_command()`.

- **`ArchiveName` dataclass replaces `backup_def_from_archive()`** (`util.py`, `manager.py`) —
  `backup_def_from_archive()` returned `None` when the archive name did not contain `_`, and
  callers propagated that `None` silently into database paths (producing `"None.db"` lookups).
  The function is removed; call sites in `cat_no_for_name()`, `list_archive_contents()`, and
  `remove_specific_archive()` now call `ArchiveName.parse()` and return early with an error when
  parsing fails.  `_parse_archive_info()` also migrated, removing its own inline regex and
  strptime block.  `ArchiveName` is defined once in `util.py` and shared by all callers.

- **ruff configured and many violations resolved** (`pyproject.toml`, multiple modules) — ruff was
  listed as a dev dependency but had no configuration and was never run.  Configured with
  `line-length = 150`, `target-version = "py311"`, and rule sets `E`, `F`, `W`, `UP`, `B`.
  Typing-modernisation rules `UP006/007/028/035/045` deferred to the ignore list (large-scale
  refactor, out of scope).  All remaining violations fixed:

  - **B904** — bare `raise` inside `except` blocks replaced with `raise … from e` in
    `config_settings.py`, `dar_backup.py`, and `util.py` (10+ sites).
  - **F401** — unused imports removed: `import time as time_module` (`manager.py`),
    dangling `timezone` after UP017 auto-fix (`dar_backup.py`).
  - **F841** — unused `start_time` variables removed from `manager.py` and `cleanup.py`.
  - **B007** — unused loop variables renamed to `_`-prefixed forms in `manager.py` and `cleanup.py`.
  - **B009** — `getattr(config, 'manager_db_dir')` replaced with `config.manager_db_dir` (`util.py`).
  - **UP017** — `timezone.utc` → `UTC` throughout `dar_backup.py` (11 sites, auto-fixed).
  - **UP022** — `stdout=PIPE, stderr=PIPE` → `capture_output=True` (`util.py`).
  - **UP031** — `%`-style format → f-string (`dashboard.py`).
  - **W191** — tabs → spaces in `downloads.py` (manual fix; ruff cannot auto-fix mixed indentation).
  - **E501** — 8 long lines split or annotated `# noqa: E501` (argparse completer chains and
    structured log messages where splitting would harm readability).
  - **W291/W293** — trailing whitespace in docstrings and license strings across 7 files.

- **`find_files_between_min_and_max_size()` deduplicates size-string parsing** (`dar_backup.py`) —
  the function previously maintained its own copy of the unit table (`dar_sizes`) and a duplicate
  `re.match` block that mirrored `_DAR_SIZE_UNITS` / `_parse_size_bytes()` defined ~70 lines below
  in the same file.  Replaced with a single call to `_parse_size_bytes()`.  Files whose size string
  uses an unrecognised unit are now silently excluded (consistent with the helper's `None` return)
  rather than raising `KeyError`.

### Added

- **ruff static-analysis gate in `release.sh`** — `ruff check src/` now runs as a pre-flight step
  before both dry-run and real releases; violations abort the release with a clear message.

- Dashboard gained checkmarks to disable PREREQ and POSTREQ errors, to more easily see "real" backup/restore errors

### Tests

- Fixed tests that broke due to the locale changes: removed dead `_locale_ok` / `REQUIRED_LANG`
  tests, rewrote `check_locale` and service-template assertions in `test_systemd_unit_generation.py`.
- `test_list_contents_unicode_filenames` extended with German umlaut filenames (`deutsch_üöäß.txt`,
  `DEUTSCH_ÜÖÄ.txt`, `ß`).
- New parametrised integration test `test_list_contents_non_english_utf8_locale` runs backup and
  list-contents with `LANG` set to each non-English UTF-8 locale installed on the machine.
  (e.g. `da_DK.utf8`), proving file-name handling is correct regardless of the caller's locale.
- Fixed 7 unit/component tests in `test_manager_coverage.py` and `test_dar_backup_additional_coverage.py`
  that mocked `subprocess.Popen` directly; updated to mock `runner.stream_command` (the new API after B-3).
- Deleted 5 now-empty tests in `test_manager_coverage.py` that were testing the old direct-Popen
  infrastructure (stderr capping, truncation, timeout) — that behaviour now lives in
  `CommandRunner.stream_command` and is already covered by `test_command_runner.py`.
- Fixed `ArchiveName` regex (`util.py`) to accept an optional trailing suffix after the date/time
  (e.g. `_01` sequence counter used by PITR integration tests, or `_manual` labels); restores
  `_parse_archive_info()` parsing for all PITR integration test archive names.
- `test_concurrent_same_definition_does_not_corrupt_catalog` marked `xfail(strict=False)` — a
  TOCTOU race between the `os.path.exists` guard and dar creation means the losing process can
  return rc=1 instead of rc=2; proper fix (per-definition `fcntl.flock`) tracked in `doc/todo.md`.
- `test_restore_test_failure_writes_failure_to_metrics_db` timing fixed — the polling loop now
  waits for the `.1.dar` slice size to be stable for 150 ms (3 × 50 ms) rather than firing as
  soon as the file appears, giving a precise signal that dar has closed the archive.  The
  subsequent manager subprocess and `dar -t` / `dar -x` calls add ≥0.7 s before `verify()`
  reads source files, so the source-file corruption reliably wins the race on fast NVMe hardware.

## v2-1.1.7 - 2026-06-07

### Fixed

- **OOM on large archives — par2 now runs per-slice** (`dar_backup.py: generate_par2_files()`) —
  commit `998906f` (January 2026) changed par2 generation to pass all dar slices in a single command,
  causing par2 to build the full recovery matrix across the entire archive in RAM simultaneously.
  For a 124 GB archive at 5% redundancy this produced a ~6.2 GB recovery matrix, triggering OOM kills.
  Restored the original per-slice loop: each slice is processed individually, capping par2's peak RAM
  to one slice's worth of redundancy (e.g. ~500 MB for a 10 GB slice at 5%).
  The `-B` portability flag is preserved so par2 files remain relocatable across mount points.
  The manifest (`.par2.manifest.ini`) is still written once per archive after all slices succeed.
  Par2 verify (when `PAR2_RUN_VERIFY = true`) is also run per-slice.

- **`list_contents()` — unbounded stdout buffer** (`dar_backup.py`) — the stdout-reading loop used
  `buffer += chunk` which accumulated the full `dar -l` output in RAM before processing any lines.
  Replaced with an incremental partial-line pattern that carries only an incomplete trailing fragment
  between chunks; peak RAM is now O(1) regardless of archive size.

- **`list_contents()` — `bytes`/`str` `TypeError` on dar failure** — `stderr_lines` was typed
  `List[str]` but the subprocess ran in binary mode (`text=False`), so `read_stderr()` appended
  `bytes` chunks. The subsequent `"".join(stderr_lines)` would raise `TypeError` whenever dar exited
  non-zero. Fixed: `stderr_lines: List[bytes]` and `b"".join(...).decode(...)` at the join site.

- **`list_contents()` — `log_file` resource leak on exception** — the log file handle was only
  closed on the normal code path. Any exception during stdout reading left it open. Fixed with
  `try/finally` around the Popen block.

- **`list_contents()` — missing timeout on `process.wait()`** — unlike every other subprocess call
  in the codebase, `list_contents()` called `process.wait()` with no timeout, allowing a hung `dar`
  to block indefinitely. Added a `timeout` parameter (wired to `config_settings.command_timeout_secs`
  at the call site) with a `TimeoutExpired` handler that kills the process and raises `RuntimeError`.

- **`list_contents()` — `selection` tokens not sanitised** — `--selection` arguments were split with
  `shlex.split()` but not checked against `is_safe_arg()`. Added a per-token check consistent with
  the `sanitize_cmd()` validation used everywhere else via `CommandRunner`.

- **`verify()` — full archive listing materialised in RAM** (`dar_backup.py`) — `list(get_backed_up_files(...))`
  materialised the entire XML listing as a Python list of tuples before sampling. For a large archive
  this held all `(path, size)` tuples in memory simultaneously. Fixed by passing the generator directly
  into `select_restoretest_samples()` (single pass, reservoir sampler) and building `size_lookup` from
  the small sample only (at most `NO_FILES_VERIFICATION` entries).

- **`select_restoretest_samples()` return type** (`dar_backup.py`) — changed from `List[str]` to
  `List[Tuple[str, str]]` so size information travels with the sample, eliminating the need to
  materialise the full listing to build `size_lookup`.

- **`DoctypeStripper.read(n=-1)` — unbounded read path** (`dar_backup.py`) — the `n < 0` branch
  read the entire XML file into a list and joined it into one string. `ET.iterparse` never calls
  `read()` without a positive size limit, so this path was dead in production but a latent OOM trap.
  Replaced with `raise NotImplementedError` to make any future accidental call visible immediately.

- **`ConfigSettings` — `logfile_no_count` / `logfile_backup_count` name mismatch** (`config_settings.py`) —
  the dataclass declared `logfile_no_count` but `OPTIONAL_CONFIG_FIELDS` wrote to `logfile_backup_count`
  via `setattr()`. The declared field was never populated; the written attribute was a ghost invisible
  to type checkers and `__repr__`. Renamed the dataclass field to `logfile_backup_count` with
  `default=5` matching `OPTIONAL_CONFIG_FIELDS`.

- **`ConfigSettings` — `manager_db_dir` not declared in dataclass** (`config_settings.py`) —
  `OPTIONAL_CONFIG_FIELDS` set `manager_db_dir` via `setattr()` but it was never declared as a
  dataclass field, making it invisible to type checkers, IDE completion, and `__repr__`. Added as
  `Optional[str] = field(init=False, default=None)`. Path expansion now applies to it correctly.

- **`ConfigSettings` — `command_capture_max_bytes` wrong default** (`config_settings.py`) —
  the dataclass field defaulted to `None` (unbounded capture) while `OPTIONAL_CONFIG_FIELDS` defaulted
  to `102400`. An early exception in `__post_init__` before the optional-fields loop would leave the
  field as `None`, silently removing the capture cap and allowing unbounded RAM accumulation in
  `CommandRunner`. Fixed: dataclass default aligned to `102400`.

- **`ConfigSettings` — missing defaults on log-rotation fields** (`config_settings.py`) —
  `logfile_max_bytes`, `trace_log_max_bytes`, and `trace_log_backup_count` were declared as
  `field(init=False)` with no default. An early exception before the optional-fields loop left them
  uninitialised, causing `AttributeError` on access. Added defaults matching `OPTIONAL_CONFIG_FIELDS`:
  `26214400`, `10485760`, and `1` respectively.

### Added

- **`large_scale_test.sh`** — pre-release torture test script. Runs a FULL and DIFF backup against a
  real source tree supplied by the caller as a heredoc (keeping personal paths out of version control),
  verifies par2 files are named per-slice, checks `dar -t` integrity, runs `par2 verify` on every slice,
  optionally injects bitrot into slice 1 and verifies par2 repair, monitors peak RSS for `dar-backup`,
  `dar`, and `par2` throughout, and writes a timestamped summary report and metrics DB entry. The
  metrics DB accumulates across runs for cross-release comparison. Nothing touches the production
  environment; the run directory is cleaned up on exit unless `--keep` is passed.

### Fixed (tests)

- **`test_bitrot.py`** — `check_bitrot_recovery()` updated to discover and repair per-slice par2 files
  (`{slice}.par2`) instead of the old archive-level `{archive_base}.par2`. `import re` added.

- **`test_par2.py`** — `test_ordered_by_slicenumber` updated: now collects one slice number per par2
  command (N commands, one per slice) and verifies they are issued in ascending order.
  `test_par2_verify_passes_on_intact_backup` loops over all per-slice par2 files.
  `_find_slice_par2_files()` helper added.

- **`test_par2_manifest.py`** — manifest path built from `archive_base` directly; verify and repair
  loop over per-slice files.

- **`test_par2_multi_definitions.py`** — `test_par2_multi_definition_repair_flow` and
  `test_par2_definition_isolation` use per-slice discovery and repair loops.
  `test_par2_run_verify_triggers_on_creation` log message updated from `"Verifying par2 set"` to
  `"Verifying par2 for"`.

- **`test_par2_repair_restore_verification.py`** — `_find_par2_file()` replaced with
  `_find_slice_par2_files()`; both test functions loop par2 repair over all slices.

- **`test_config_settings.py`** — two assertions updated to reflect correct declared-field behaviour
  for `manager_db_dir`: path expansion now applies (assert expanded value); non-`None` value now
  appears in `__repr__` (assert present, not absent).

- **`test_dar_backup.py`** — `test_generate_par2_files_success_invokes_par2` updated:
  `call_count == 1` → `call_count == 2` (one call per slice); assertions verify each slice appears
  in its own command and the two slices are never mixed into one command.

- **`test_dar_backup_additional_coverage.py`** — `FakeProcess.wait()` in both list-contents tests
  gains `timeout=None` parameter to match the new `process.wait(timeout=timeout)` call.

- **`test_real_verify_and_backup.py`** — `test_par2_verify_detects_corrupt_dar_slice` discovers
  per-slice par2 files and uses slice 1's par2 file for the corrupt-and-verify step.

- **`test_real_pitr_and_pipeline.py`** — `test_full_backup_verify_runs_before_par2_and_both_complete`
  confirms par2 ran by checking for any per-slice par2 file rather than the old archive-level index.

## v2-1.1.6 - 2026-06-05

### Added

- **`RESTORE_OWNERSHIP` config setting and `--preserve-ownership` / `--ignore-ownership` CLI flags** —
  ownership restoration during restores is now configurable.  The `.darrc` entry
  `--comparison-field=ignore-owner` has been commented out; dar-backup now injects the flag
  programmatically based on config and CLI.
  - `RESTORE_OWNERSHIP = no` (default, shipped in all config templates) — injects
    `--comparison-field=ignore-owner` on the dar CLI so non-root restores cannot fail due to ownership
    errors.  uid/gid are not restored.  Behaviour is identical to all previous releases.
  - `RESTORE_OWNERSHIP = yes` — omits the flag; dar restores original uid/gid.  Intended for root-run
    production restores only.  Non-root restores will fail when files are owned by a different user.
  - `--preserve-ownership` CLI flag on `dar-backup` and `manager` — forces uid/gid restoration for a
    single run without editing the config file (root only).  Intended for one-off production restores.
  - `--ignore-ownership` CLI flag on `dar-backup` and `manager` — forces ignore-owner for a single run,
    overriding `RESTORE_OWNERSHIP = yes` in the config.
  - The two flags are mutually exclusive; passing both is rejected by argparse.
  - Root warning: when running as root with `RESTORE_OWNERSHIP = no`, a `WARNING` is emitted to the log
    and stderr reminding the operator that ownership is not being preserved.
  - `compare_metadata()` in `util.py` gains a `check_ownership: bool = False` parameter; uid/gid are
    now compared after restore when ownership restoration is active.
  - **Existing users**: no action required.  When `RESTORE_OWNERSHIP` is absent from the config the
    default is `no`, preserving the previous behaviour exactly.

- **Config range validation** — `ConfigSettings` now enforces ranges at startup and raises
  `ConfigSettingsError` immediately rather than silently accepting bad values:
  - `ERROR_CORRECTION_PERCENT` must be 1–90 (0 gives no redundancy; >90 is rejected by par2)
  - `NO_FILES_VERIFICATION` must be >= 1 (0 makes restore tests vacuously pass)
  - `DIFF_AGE` and `INCR_AGE` must be >= 1; values above 365 / 31 days respectively are logged as a warning

- **Metadata verification after restore** — `verify()` in `dar_backup.py` now checks file metadata after
  the byte-for-byte content comparison. Permissions (`st_mode`) and modification time (`st_mtime_ns`) are
  always checked; uid/gid are checked when `RESTORE_OWNERSHIP = yes` is active. Any mismatch is reported
  as a failure. The logic lives in `compare_metadata()` in `util.py`.

- **Per-file restore-test metrics** — `verify()` now records the result of every file it exercises into a
  new `restore_test_samples` SQLite table (linked to `backup_runs` via `run_id`). Each row stores
  `file_path`, `file_size_bytes`, `result` (`PASS`/`FAIL`/`SKIP`), a foreign-key `fail_reason_id` into a
  seeded `restore_test_fail_reasons` lookup table (six stable codes: `CONTENT_MISMATCH`,
  `METADATA_MISMATCH`, `SOURCE_MISSING`, `RESTORED_MISSING`, `PERMISSION_ERROR`, `UNKNOWN_ERROR`), a
  `fail_detail` text field, and a `tested_at` timestamp. All rows for a run are written in one
  transaction. No-op when `METRICS_DB_PATH` is unset; existing databases are upgraded automatically on
  the next run via `ensure_metrics_db`.

- **SQLite WAL mode** — `ensure_metrics_db` now sets `PRAGMA journal_mode=WAL` on every metrics DB.
  WAL allows Datasette, DB Browser, and the `sqlite3` CLI to read the database concurrently without
  blocking backup writes. Existing databases are upgraded automatically on the next backup run.

- **Metrics isolation in `verify()`** — all four metrics code paths inside `verify()` are individually
  guarded with `try/except` so that any failure is logged as a `WARNING` and the backup result is
  completely unaffected.

- **CI path filter** — `.github/workflows/py-tests.yml` now ignores pushes that only touch
  `clonepulse/**`, preventing daily bot commits from consuming CI compute.

- **`--no-deleted` CLI flag on `dar-backup` and `manager`** — passes `--deleted=ignore` to dar so that
  deletion records in DIFF/INCR archives do not cause errors when restoring directly to an empty directory
  (i.e. without first restoring the FULL archive).  Without this flag, dar exits rc≠0 when a deletion
  record references a file that does not exist in the restore target.
  - The redundant `-/ Oo` overwriting policy has been removed from all restore commands; it was verified
    to be identical to dar's default behaviour on both dar 2.7.13 (Ubuntu 24.04 / CI) and 2.7.21.
    Its removal is what enables `--deleted=ignore` to work (dar ignores `--deleted=ignore` when `-/` is
    present).

- **`--fsa-scope none` documented in `.darrc`** — the `restore-options` section now contains a
  commented-out `--fsa-scope none` with an explanation of when to enable it. FSA covers birth time
  (btime) and Linux inode flags: immutable (`i`), append-only (`a`), secure-delete (`s`),
  undeletable (`u`), no-atime (`A`), synchronous writes (`S`), data journaling (`j`).
  - **When to enable:** btrfs can store a btime whose nanosecond component is ≥ 1,000,000,000
    (technically invalid per POSIX, but btrfs allows it internally). When dar tries to restore such a
    value via `utimensat`, the kernel rejects it and the restore fails with
    `cannot set birth time of file, value too high for the system integer type`.
    This is reproducibly triggered by browser-profile SQLite files under snap confinement
    (e.g. Firefox on btrfs). Uncommenting `--fsa-scope none` suppresses the error.
  - **Impact when enabled:** birth times are not restored; inode flags (including immutable `i` and
    append-only `a`) are not restored. File content, ownership, permissions, mtime, and atime are
    unaffected.
  - **Existing users:** no action required — the line ships commented out.

### Fixed

- **`continue` in `finally` block** — `dar_backup.py`: Python 3.14 raises `SyntaxWarning` for
  `continue` inside a `finally` block. Replaced with an `if/else` guard; identical behaviour, no warning.

- **Unclosed SQLite connections** — Python 3.14's GC is stricter about unclosed db handles. Fixed in
  `util.py` (4 sites) and all 10 test files by switching to `with closing(sqlite3.connect(...)) as conn:`.
  `test_import_archive_metrics.py`'s `_open_minimal_db` helper wraps setup in `try/except` so the
  connection is closed on error.

- **UTF-8 stdout encoding in `setup_logging()`** — on systems without a UTF-8 locale (or when a
  subprocess is started under `LC_ALL=C`), log messages containing non-ASCII characters raised
  `UnicodeEncodeError`. Fixed by calling `sys.stdout.reconfigure(encoding='utf-8', errors='replace')`
  before attaching the handler when the stream is not already UTF-8.

- **`locale.setlocale(LC_ALL, 'C')` global side-effect in `list_backups()`** — the fallback to
  `LC_ALL=C` permanently changed the process-wide locale to ASCII, breaking all subsequent `open()`
  calls using non-ASCII content. Fixed by replacing `locale.format_string()` with `f"{int(n):,}"`.

- **`PYTHONUTF8=1` in test suite** — `tests/conftest.py` now sets `os.environ["PYTHONUTF8"] = "1"` at
  collection time so every subprocess spawned during the test run starts in Python UTF-8 mode.

- **`closing()` does not commit** — `_make_old_db` in `test_metrics_db.py`: switching to
  `closing(sqlite3.connect())` removed the auto-commit, silently rolling back an `INSERT` and causing two
  migration tests to fail. Fixed with an explicit `conn.commit()`.

- **`scripts/import-archive-metrics.py` — two unclosed connections** — connections leaked until GC,
  producing 13 `ResourceWarning: unclosed database` warnings. Fixed with `closing()`.

- **`is_safe_arg` security** — `\r` (terminal-overwrite attack) and `\x00` (C string truncation) are now
  rejected alongside the existing shell metacharacters.

- **`requirements()` reliability** — removed a PYTEST_CURRENT_TEST branch that silently changed execution
  path in tests; now always uses `Popen` with streaming threads. Adds a configurable timeout;
  exceeding it kills the script and raises `RuntimeError` with a clear message.

- **Subprocess timeout coverage** — `get_binary_info()` and the two `dar_manager` tab-completion calls
  now pass `timeout=10` to `subprocess.run`, preventing silent hangs in shell-completion contexts.

- **`show_scriptname()`** — bare `except:` tightened to `except Exception:`.

### Added (tests)

- **`test_dar_ownership_precedence.py`** (4 integration tests) — invoke `dar` directly to document and
  lock down `--comparison-field` flag behaviour: CLI-only injection works without a darrc entry; darrc
  and CLI carrying the same flag coexist without error; CLI `--comparison-field=owner` alongside darrc
  `ignore-owner` is accepted by dar; and restore succeeds with no `--comparison-field` at all.

- **`test_dar_backup.py` — ownership warning and flag tests** — five unit tests using `os.getuid`
  monkeypatch: WARNING fires when root + `ignore_ownership=True`; no warning when root +
  `ignore_ownership=False`; no warning when non-root + `ignore_ownership=True`; dar command contains
  `--comparison-field=ignore-owner` when `ignore_ownership=True`; dar command omits it when
  `ignore_ownership=False` (`--preserve-ownership` path).

- **`test_config_settings.py` — `RESTORE_OWNERSHIP` parsing** — four tests: `yes` parses as `True`;
  `no` parses as `False`; key absent defaults to `False` (backward compat); invalid value raises
  `ConfigSettingsError`.

- **`test_util.py` — `compare_metadata` ownership tests** — `check_ownership=False` (default) ignores
  uid/gid differences; `check_ownership=True` detects uid/gid mismatches; identical uid/gid produce no
  false positive with `check_ownership=True`.

- **`test_util.py` — `list_backups()` locale-robustness tests** — verifies sizes are formatted correctly
  and `locale.getpreferredencoding()` is unchanged after the call.

- **`test_util.py`** — `test_requirements_timeout_kills_hanging_script`: runs `sleep 60` with
  `command_timeout_secs=1` and asserts `RuntimeError` containing "timed out".

- **`test_restore_content_verification.py` — `test_metadata_mismatch_detected`** — integration test: runs
  a real FULL backup, restores it, forces a permission change on one restored file, and asserts
  `verify_restored_matches_source()` raises `RuntimeError` with a `Metadata mismatch` message.

- **`test_restore_test_samples.py`** (17 unit tests) — covers `ensure_metrics_db` schema creation and
  seed idempotency, `write_restore_test_samples` for all result types, no-op behaviour when
  `metrics_db_path` is absent or `samples` is empty, and `_parse_size_bytes` for all dar size units.

- **`test_metrics_smoke.py`** — smoke integration tests: real FULL backup asserts `restore_test_samples`
  rows are written with correct `run_id` linkage, `file_size_bytes`, and `archive_name` format; metrics
  row has correct `archive_size_bytes`, `dar_exit_code`, and `hostname`.

- **`test_dashboard_smoke.py`** — smoke test (skipped when `datasette` is not installed): starts
  `dar-backup-dashboard --no-browser`, polls `/-/versions` via `urllib` until HTTP 200, queries the DB
  to confirm rows are served, then terminates the process group cleanly.

- **`test_verify_metrics_isolation.py`** (4 integration tests) — one test per guard in `verify()`; all
  four assert `result.passed is True` despite the injected failure.

- **`test_command_runner.py`** — parametrized `sanitize_cmd` tests for `\r` and `\x00` (rejected) and
  safe arguments (accepted).

- **`test_config_settings.py`** — parametrized edge-case tests for `ERROR_CORRECTION_PERCENT` and
  `NO_FILES_VERIFICATION` ranges.

- **`test_par2.py`** — added `test_par2_files_created_for_full_backup` and
  `test_par2_verify_passes_on_intact_backup` (both real runs, no mocks).

- **`test_prereq.py` / `test_postreq.py`** — full rewrites using real shell commands; removed subprocess
  mocks and `SimpleNamespace` stubs.

- **`test_real_verify_and_backup.py`** (10 real integration tests) — end-to-end runs against genuine dar
  archives covering corruption detection, stale restore replacement, archive listing, par2 verify, and
  catalog-add failure on a read-only DB.

- **`test_real_pitr_and_pipeline.py`** (10 real integration tests) — PITR file/directory restore,
  `--pitr-report-first`, verify-before-par2 ordering, backup with unwritable metrics DB,
  `--alternate-archive-dir`, and cleanup path-traversal rejection.

- **`test_real_manager_and_generic_backup.py`** (10 real integration tests) — `generic_backup()` direct
  call, manager catalog operations (`--add-specific-archive`, `--add-dir`, `--list-catalogs`,
  `--find-file`, `--list-archive-contents`), `verify()` error paths, and metrics DB pipeline.

- **`test_par2_multi_definitions.py`** — extended to 8 real integration tests covering all PAR2
  configuration permutations (global disable, per-definition disable, `PAR2_RUN_VERIFY`, `PAR2_DIR`
  manifest, FULL/DIFF/INCR sets, isolated definitions, ratio comparison).

### Documentation

- **`troubleshooting.md`** — corrected the blocked-characters table; added a `ConfigSettingsError on
  startup` section with a full cause/fix table and warning-only conditions.
- **`config-reference.md`** — added inline range comments to `NO_FILES_VERIFICATION`, `DIFF_AGE`,
  `INCR_AGE`, and `ERROR_CORRECTION_PERCENT`; added `RESTORE_OWNERSHIP` entry.
- **`cli-reference.md`** — removed duplicate `--restore` entry; added `--log-stdout` to the manager
  options block; added `--preserve-ownership` and `--ignore-ownership` to both `dar-backup` and
  `manager` option tables.
- **`dev.md`** — corrected `./build.py` to `./build.sh`.
- **`troubleshooting.md` / `systemd-setup.md`** — `en_US.UTF8` -> `en_US.UTF-8` throughout.
- **`release.sh` -- `--dry-run` mode**: runs all read-only pre-flight checks and prints what each step
  would do, without making any commits, moving the tag, building, signing, or uploading.
- **`release.sh` -- release audit trail**: on successful PyPI upload appends a structured entry to
  `v2/build-history.json`, stamps a clone-pulse annotation, and commits the full release log.
- **`release.sh` -- duplicate release guard**: aborts before the test suite runs if `build-history.json`
  already contains an entry for the current version.
- **`release.sh` -- release log**: all script output is captured via `tee` to
  `v2/doc/releases/release-<tag>.log`.

### Changed

- **Dashboard** — timestamps now shown in the browser's local timezone instead of UTC.

## v2-1.1.5 - 2026-05-17

### Added

- Added 10 PITR integration tests covering multi-archive boundary selection, catalog fallback, archive relocation, fail-fast on missing slices, timezone-aware when, multi-path restore, catalog isolation across backup definitions, and single-version file restore.

### Changed

- Discord report now much more readable

### Added

- Dashboard filter bar: filter by backup definition (dropdown populated from the DB), number of most-recent runs per definition, show-all toggle, and a start/end time range to seconds precision; all filters combine freely and apply to both the run table and the trend charts.
- Dashboard PHASES column extended with PRE and POST indicators; PRE shows the PREREQ script result, POST shows the POSTREQ script result. Old rows (before this release) show `—` for both new columns.
- SQLite metrics DB gains three new columns (`run_id`, `prereq_status`, `postreq_status`); existing databases are migrated automatically on the first backup run — no manual steps required.

### Bugfix

- When a PREREQ script failed, no FAILURE row was written to the SQLite metrics DB and the Dashboard showed no trace of the failed run. A `FAILURE` row with `failed_phase='PREREQ'` is now written for every affected definition (all definitions, or only the one selected with `-d`).

## v2-1.1.4 - 2026-05-07

### Added

- **Locale guard in `dar_backup_systemd.py`**: `check_locale()` warns at unit-generation time if `LANG` is not `en_US.UTF-8`; all generated service units now include `Environment=LANG=en_US.UTF-8` so `dar` always runs with the correct locale regardless of the calling shell.
- **Locale guard in `dar_backup.py`**: `_locale_ok()` helper and a startup warning to `stderr` when `LANG` is not `en_US.UTF-8`; `generic_backup()` skips `parse_dar_stats()` and returns an empty stats dict when the locale is wrong, preventing silently corrupt inode metadata.

### Added (tests)

- **Locale tests in `test_systemd_unit_generation.py`** (4 tests): positive — no warning when `LANG=en_US.UTF-8`, `Environment=LANG=en_US.UTF-8` present in both service and cleanup service units; negative — `check_locale()` prints a `WARNING` for a wrong locale.
- **Locale tests in `test_dar_backup_startup.py`** (5 tests): positive — `_locale_ok()` returns `True` and `parse_dar_stats` is called when locale is correct; negative — `_locale_ok()` returns `False`, `main()` emits a locale warning to `stderr`, and `generic_backup()` skips `parse_dar_stats` when locale is wrong.

- Tests added proving all signal handling scenarios: silent dar failure, NFS stall, Ctrl-C and SIGTERM during backup, restore, verify, and PITR restore.

### Changed

- **`release.sh`** auto-stamps the release date in both changelogs (`CHANGELOG.md`, `v2/Changelog.md`) and updates the `README.md` current-version reference as part of the post-test commit — eliminating two manual pre-release steps that were easy to forget.

### Bugfix

- perform_backup() now correctly records FAILURE in the metrics DB when dar exits 0 but writes no archive slices (e.g. due to an NFS mount stall). Previously, the run was silently recorded as SUCCESS.
- NFS stall scenario now logs a clear error in the main log. Previously the failure was visible only in the command log.
- KeyboardInterrupt (Ctrl-C) is now caught explicitly in perform_backup(). A clear error message naming the interrupted phase and warning that partial slices must not be used for restore is logged and recorded in the metrics DB. Previously, a Ctrl-C with a partial slice on disk could be recorded as SUCCESS.
- SIGTERM (`kill <pid>`) is now handled in dar-backup and manager — a handler converts it to KeyboardInterrupt so the same logging and cleanup chain fires as for Ctrl-C. Previously SIGTERM terminated the process immediately with no log entry and no metrics written.
- KeyboardInterrupt and SIGTERM are now caught in `restore_backup()`, `verify()`, `_is_directory_in_archive()`, `_restore_with_dar()` and `restore_at()` (PITR). Each handler logs a clear error naming the interrupted operation and warns that the target directory may be incomplete.
- CommandRunner.run() now kills the child process and joins streaming threads on KeyboardInterrupt, ensuring log buffers are flushed to disk before the process exits.
- CommandRunner fixed, so log lines in command log are not split. Test cases added.

## v2-1.1.3 - 2026-03-22

### Added

- PITR integration test `test_pitr_multislice_archive`: verifies PITR restore works correctly across multi-slice archives (`.1.dar`, `.2.dar`, …); proves that content in later slices is actually reached by checking restored file content rather than dar exit code (dar returns 0 on partial/graceful restores).
- PITR integration test `test_pitr_symlinks_and_hardlinks`: verifies that relative symlinks, dangling symlinks, and hard-link pairs are all preserved correctly after PITR restore (symlink targets checked with `os.readlink`; hard links verified via inode equality `os.stat().st_ino`).
- PITR integration test `test_pitr_special_char_filenames`: verifies PITR restore of files whose names contain spaces, Danish characters (æøå / ÆØÅ), colons, hashes, currency symbols, parentheses, `+`, `!`, and brackets; `&` excluded as a known `sanitize_cmd()` limitation (subprocess safety guard rejects `&` even without `shell=True`).
- New doc `v2/doc/pitr-archive-date-vs-file-mtime.md`: explains why dar-backup implements its own archive-creation-date PITR selection instead of delegating to `dar_manager -w`, with a concrete rename/mtime counter-example and a reference to the torture test that validates the design choice.
- New doc section in `v2/doc/restoring.md` — **"Restore a file by its mtime (file-version restore)"**: step-by-step guide for `dar_manager -w` direct use (find `.db`, run `-f` to list versions, restore with `-w -r -e`), date format `YYYY/MM/DD-HH:MM:SS`, caveats (deletions not handled per Denis's own man page; rename/mtime trap; bypasses dar-backup target safety checks). Requires dar >= 2.7.21 (DST `tm_isdst=1` bug fixed in `line_tools_convert_date()`).
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
- PITR fallback now restores via the latest FULL -> DIFF -> INCR chain and fails fast when required archives are missing.
- PITR restore now requires `--target` and blocks unsafe restore targets by default.
- Filtered `.darrc` temp files are created in a writable location and cleaned up reliably after runs.
- PITR fallback now validates chain completeness instead of skipping missing archives.
- `COMMAND_TIMEOUT_SECS = -1` disables timeouts for long-running operations.
- Catalog rebuild (`manager --add-dir`) now adds archives in FULL -> DIFF -> INCR order for the same date to avoid dar_manager prompts.
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

- DAR XML catalog parsing fixed (recursive -> iterative). Test case added.
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
