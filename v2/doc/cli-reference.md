# CLI Reference

Back to [README](../../README.md)

## CLI Tools Overview

| Command | Description |
| --- | --- |
| [dar-backup](#dar-backup-options) | Perform full, differential, or incremental backups with verification and restore testing |
| [manager](#manager-options) | Maintain and query catalog databases for archives |
| [cleanup](#cleanup-options) | Remove outdated DIFF/INCR archives (and optionally FULLs) |
| [clean-log](#clean-log-options) | Clean up excessive log output from dar command logs |
| [dar-backup-systemd](#dar-backup-systemd-options) | Generate (and optionally install) systemd timers and services for automated backups |
| [installer](#installer-options) | Set up directories and optionally create catalog databases according to a config file |
| [demo](#demo-options) | Set up required directories and config files for a demo |
| [dar-backup-dashboard](#dar-backup-dashboard-options) | Start Datasette and open the metrics dashboard in the browser |

---

## Dar-backup options

This script does backups including par2 redundancy, validation and restoring.

Available options:

```bash
-h, --help                           Show command-line help and exit.
-F, --full-backup                    Perform a full backup.
-D, --differential-backup            Perform a differential backup.
-I, --incremental-backup             Perform an incremental backup.
-d, --backup-definition <name>       Specify the backup definition file.
--alternate-reference-archive <file> Use a different archive for DIFF/INCR backups.
-c, --config-file <path>             Specify the path to the configuration file.
--darrc <path>                       Specify an optional path to .darrc.
--examples                           Show examples of using dar-backup.py.
-l, --list                           List available backups.
--list-contents <archive>            List the contents of a specified archive.
--list-definitions                   List backup definitions from BACKUP.D_DIR.
--selection <params>                 Define file selection for listing/restoring.
-r, --restore <archive>              Restore archive.
--restore-dir <path>                 Directory on which to restore.
--overwrite-restore-target           Restore in place into an existing privately controlled --restore-dir after a safety preflight. Requires --restore and an explicit --restore-dir.
--force-unsafe-restore-target        Root-only break-glass option that waives overridable overwrite preflight findings; structural protections remain. Requires --overwrite-restore-target.
--preserve-ownership                 Force uid/gid restoration for this run (overrides config; root only; mutually exclusive with --ignore-ownership).
--ignore-ownership                   Force uid/gid to be ignored for this run (overrides RESTORE_OWNERSHIP = yes in config; mutually exclusive with --preserve-ownership).
--no-deleted                         Do not process deletion records from DIFF/INCR archives (passes --deleted=ignore to dar). Useful when restoring a DIFF or INCR archive directly to an empty directory without first restoring the FULL.
--verbose                            Enable verbose output.
--suppress-dar-msg                   Filter out this from the darrc: "-vt", "-vs", "-vd", "-vf", "-va"
--log-level <level>                  `debug` or `trace`, default is `info`.
--log-stdout                         Also print log messages to stdout.
--do-not-compare                     Do not compare restores to file system.
--allow-unsafe-definition-names      Disable backup definition name validation (allows underscores or other characters).
--preflight-check                    Run preflight checks and exit (runs automatically; this flag just exits after checks).
--readme                             Print README.md and exit
--readme-pretty                      Print README.md with Markdown styling and exit
--changelog                          Print Changelog and exit
--changelog-pretty                   Print Changelog with Markdown styling and exit
--doc <name>                         Print a documentation file by name and exit (tab completion lists available docs)
--doc-pretty <name>                  Print a documentation file with Markdown styling and exit
-v, --version                         Show version and license information.
```

### Dar-backup option details

#### `-h`, `--help`

Prints the argparse-generated command synopsis and short option descriptions, then exits without loading the backup configuration or running an operation.

#### `-F`, `--full-backup`

Creates a FULL archive for the selected backup definition, or for every discovered definition when `--backup-definition` is omitted. Exactly one backup type should be selected; combining FULL, DIFF, and INCR flags does not run a backup.

#### `-D`, `--differential-backup`

Creates a DIFF archive using the latest suitable FULL as its reference. `--alternate-reference-archive` can override the automatically selected reference archive.

#### `-I`, `--incremental-backup`

Creates an INCR archive using the latest suitable archive in the chain as its reference. `--alternate-reference-archive` can override that automatic selection.

#### `-d`, `--backup-definition <name>`

Restricts the operation to one file from `BACKUP.D_DIR`. Definition names are validated before use; `--allow-unsafe-definition-names` bypasses that validation for legacy names.

#### `--alternate-reference-archive <archive>`

Uses the named archive from `BACKUP_DIR` as the reference for a DIFF or INCR backup instead of selecting the latest reference automatically. The archive must exist, and this option has no useful effect on FULL backups.

#### `-c`, `--config-file <path>`

Loads configuration from the specified file. It overrides `DAR_BACKUP_CONFIG_FILE`; when neither is supplied, the command uses its built-in default configuration path.

#### `--darrc <path>`

Uses the specified DAR configuration file instead of the configured/default `.darrc`. Restore commands use its `restore-options` section, while backup operations use the applicable backup sections.

#### `--examples`

Prints built-in command examples and exits before loading configuration or running an operation.

#### `-l`, `--list [<prefix>]`

Lists archives in `BACKUP_DIR`. An optional value filters by archive-name prefix; `--backup-definition` also supplies a filter when no explicit prefix is given.

#### `--list-contents <archive>`

Lists the contents of the named archive. `--selection` can restrict which archive entries DAR displays.

#### `--list-definitions`

Prints backup definition names found in `BACKUP.D_DIR` and exits. Unsafe names cause an error unless `--allow-unsafe-definition-names` is also supplied.

#### `--selection <params>`

Passes a shell-like string of selection arguments to DAR for `--list-contents` or `--restore`, for example `--selection="-I '*.NEF'"`. Quote the entire value so the calling shell does not expand patterns prematurely.

#### `-r`, `--restore <archive>`

Restores the named archive. The configured test restore directory is used unless `--restore-dir` is supplied; by default the selected target must be empty.

#### `--restore-dir <path>`

Selects the destination for `--restore`. Without it, ordinary restores use `TEST_RESTORE_DIR`; overwrite restores require an explicit path and never fall back to the configured test directory.

#### `--overwrite-restore-target`

Allows `--restore` to modify a non-empty, privately controlled `--restore-dir` after the whole-target safety preflight. It requires both `--restore` and an explicit `--restore-dir`; DAR may replace or delete existing paths, and a failed restore has no automatic rollback.

#### `--force-unsafe-restore-target`

Allows effective UID 0 to waive overridable findings from the overwrite safety preflight. It requires `--overwrite-restore-target`; structural protections remain enforced. See [Advanced restore](restoring-advanced.md) before using this break-glass option.

#### `--preserve-ownership`

Forces restoration of archived UID/GID ownership for this invocation, overriding `RESTORE_OWNERSHIP = no`. It is restricted to root and is mutually exclusive with `--ignore-ownership`.

#### `--ignore-ownership`

Passes `--comparison-field=ignore-owner` to DAR for this invocation, overriding `RESTORE_OWNERSHIP = yes`. It is mutually exclusive with `--preserve-ownership`.

#### `--no-deleted`

Passes `--deleted=ignore` to DAR so deletion records in DIFF/INCR archives are not applied. This is useful when restoring a single DIFF or INCR directly into an empty directory, but stale paths can remain during an overwrite restore.

#### `--verbose`

Adds operational settings and progress information to terminal output. It does not select the diagnostic log level; use `--log-level` for debug or trace logging.

#### `--suppress-dar-msg`

Creates a temporary filtered `.darrc` for this run that suppresses DAR verbosity options `-vt`, `-vs`, `-vd`, `-vf`, and `-va`. The original `.darrc` is not modified.

#### `--log-level <level>`

Sets application logging to `info` (default), `debug`, or `trace`. More detailed levels can expose command arguments and internal state in the log.

#### `--log-stdout`

Copies application log messages to standard output in addition to the configured log destination.

#### `--do-not-compare`

Skips the post-backup restore-and-compare verification step. Archive testing and the other configured backup phases still run, but source-versus-restore comparison results are not produced.

#### `--allow-unsafe-definition-names`

Disables backup-definition name validation for this invocation. Use it only for trusted legacy definitions because the normal validation protects paths, logs, lock files, and external command arguments.

#### `--preflight-check`

Runs the same prerequisite and configuration checks that normally precede an operation, then exits without backing up, listing, or restoring.

#### `--readme`, `--readme-pretty`

Print the packaged README and exit. The `--readme-pretty` form renders Markdown styling when terminal support is available, while `--readme` emits plain Markdown text.

#### `--changelog`, `--changelog-pretty`

Print the packaged changelog and exit. The `--changelog-pretty` form renders Markdown styling when possible; the plain form is suitable for redirection and text processing.

#### `--doc <name>`, `--doc-pretty <name>`

Print a packaged documentation file selected by name and exit. Shell completion lists available names; the pretty form renders Markdown styling and the plain form emits the source text.

#### `-v`, `--version`

Prints the installed version and license information, then exits before loading configuration.

### Dar-backup exit codes

- 0: Success.
- 1: Error (backup/restore/preflight failure).
  - includes DAR exit code 4: DAR aborted after a prompt, signal, or user response;
    any resulting archive is treated as incomplete and is not added to the PITR catalog
  - includes an invalid backup-definition name (see [naming rules](config-reference.md#backup-definition-example)) — as of v2-1.1.10 this is `rc=1` whether the invalid name was given explicitly via `-d` or found while scanning `BACKUP.D_DIR` for an all-definitions run; previously the latter case was only a warning (`rc=2`)
- 2: Warning (restore test failed or backup already exists and is skipped).
- 127: Typically an error during startup, file or config value missing
  - if the `dar -t` test fails, exit code 1 is emitted
  - restore tests could fail if the source file has changed after the backup

### Dar-backup env vars

| Env var | Value | Description |
| --- | --- | --- |
| DAR_BACKUP_CONFIG_FILE | Full path to config file | Overrides built-in default, overridden by --config-file |
| DAR_BACKUP_DISCORD_WEBHOOK_URL | https://discord.com/api/webhooks/\<userID\>/\<webhook UUID\> | The full url |
| DAR_BACKUP_COMMAND_TIMEOUT_SECS | -1 or > 0 | Overrides config `COMMAND_TIMEOUT_SECS`. Use `-1` to disable timeouts. |

---

## Manager Options

This script manages `dar` databases and catalogs.

Available options:

```bash
-h, --help                           Show command-line help and exit.
-c, --config-file <path>             Path to dar-backup.conf.
--create-db                          Create missing databases for all backup definitions.
--alternate-archive-dir <path>       Use this directory instead of BACKUP_DIR in the config file.
--add-dir <path>                     Add all archive catalogs in this directory to databases.
-d, --backup-def <name>              Restrict operations to this backup definition.
--add-specific-archive <archive>     Add a specific archive to the catalog database.
--remove-specific-archive <archive>  Remove a specific archive from the catalog database.
-l, --list-catalogs                  List catalogs in databases for all backup definitions.
--list-archive-contents <archive>    List the contents of an archive's catalog by archive name.
--find-file <file>                   Search catalogs for a specific file.
--restore-path <path> [<path> ...]   Restore specific path(s) (Point-in-Time Recovery).
--when <timestamp>                   Date/time for restoration (used with --restore-path).
--target <path>                      Required target directory for restoration.
--overwrite-restore-target           Restore in place into an existing privately controlled --target after a safety preflight. Requires --restore-path and cannot be used with --pitr-report.
--force-unsafe-restore-target        Root-only break-glass option that waives overridable overwrite preflight findings; structural protections remain. Requires --overwrite-restore-target and cannot be used with --pitr-report.
--preserve-ownership                 Force uid/gid restoration for this run (overrides config; root only; mutually exclusive with --ignore-ownership).
--ignore-ownership                   Force uid/gid to be ignored for this run (overrides RESTORE_OWNERSHIP = yes in config; mutually exclusive with --preserve-ownership).
--no-deleted                         Do not process deletion records from DIFF/INCR archives (passes --deleted=ignore to dar). Useful when restoring a DIFF or INCR archive directly to an empty directory.
--pitr-report                        Report and validate the PITR archive chain without restoring.
--pitr-report-first                  Validate the PITR chain before restore; abort if archives are missing or incomplete.
--relocate-archive-path <old> <new>  Rewrite archive path prefix in the catalog DB (requires --backup-def).
--relocate-archive-path-dry-run      Show archive path changes without applying them (use with --relocate-archive-path).
--verbose                            Enable verbose output.
--log-level <level>                  Set log level (`debug` or `trace`, default is `info`).
--log-stdout                         Also print log messages to stdout.
--more-help                          Show extended help and exit.
-v, --version                        Show version and license information.
```

### Manager option details

#### `-h`, `--help`

Prints the generated command synopsis and short option descriptions, then exits without loading configuration or opening a catalog database.

#### `-c`, `--config-file <path>`

Loads configuration from the specified file. It overrides `DAR_BACKUP_CONFIG_FILE`; when neither is supplied, the manager uses its default configuration path.

#### `--create-db`

Creates missing catalog databases. With `--backup-def`, it handles only that definition; otherwise it processes all files in `BACKUP.D_DIR`. Existing healthy databases are retained, while a detected corrupt database is renamed aside before recreation.

#### `--alternate-archive-dir <path>`

Uses the specified existing directory instead of `BACKUP_DIR` when locating archive slices for the requested manager operation.

#### `--add-dir <path>`

Adds all recognized `.1.dar` archives in a directory to their corresponding databases, ordered by archive date and FULL/DIFF/INCR type. It cannot be combined with `--add-specific-archive`; `--backup-def` can restrict the scan.

#### `-d`, `--backup-def <name>`

Restricts database operations to one configured backup definition. It is required by `--find-file`, `--restore-path`, and `--relocate-archive-path`.

#### `--add-specific-archive <archive>`

Adds the named archive catalog to its database. It cannot be combined with `--remove-specific-archive` or `--add-dir`.

#### `--remove-specific-archive <archive>`

Removes the named archive catalog from its database without deleting the DAR archive itself. It cannot be combined with `--add-specific-archive`.

#### `-l`, `--list-catalogs`

Lists catalogs recorded in the database for `--backup-def`, or in every configured definition database when no definition is selected.

#### `--list-archive-contents <archive>`

Lists the paths recorded in the named archive catalog. The archive name must be non-empty; shell completion can suggest catalogued archives.

#### `--find-file <path>`

Searches catalog history for the specified path. It requires `--backup-def` so the manager knows which database to query.

#### `--restore-path <path> [<path> ...]`

Restores one or more paths using the selected definition’s catalog history. It requires `--backup-def` and, unless `--pitr-report` is used, an explicit `--target`.

#### `--when <timestamp>`

Chooses the point in time for `--restore-path`. It is required with `--pitr-report`; an omitted value on a normal restore means the latest applicable state.

#### `--target <path>`

Sets the destination directory for `--restore-path`. It is required for an actual restore and is not needed for the report-only `--pitr-report` operation.

#### `--overwrite-restore-target`

Allows PITR to modify a non-empty, privately controlled `--target` after a whole-target safety preflight. It requires `--restore-path`, cannot be used with `--pitr-report`, and provides no rollback if restoration fails partway through.

#### `--force-unsafe-restore-target`

Allows effective UID 0 to waive overridable overwrite-preflight findings. It requires `--overwrite-restore-target`, cannot be used with `--pitr-report`, and never disables structural protections.

#### `--pitr-report`

Reports and validates the archive chain needed for `--restore-path` at `--when` without restoring data. Both `--restore-path` and `--when` are required.

#### `--pitr-report-first`

Validates the PITR chain before an actual `--restore-path` operation and aborts restoration if the report fails. When `--when` is omitted, the report uses the current time.

#### `--relocate-archive-path <old> <new>`

Rewrites a stored archive-path prefix in the selected catalog database, for example after moving an archive directory. It requires `--backup-def`.

#### `--relocate-archive-path-dry-run`

Shows the changes that `--relocate-archive-path` would make without updating the database. It is invalid unless `--relocate-archive-path` is also supplied.

#### `--preserve-ownership`

Forces PITR to restore archived UID/GID ownership, overriding `RESTORE_OWNERSHIP = no`. It requires root and is mutually exclusive with `--ignore-ownership`.

#### `--ignore-ownership`

Forces PITR to ignore archived ownership, overriding `RESTORE_OWNERSHIP = yes`. It is mutually exclusive with `--preserve-ownership`.

#### `--no-deleted`

Passes `--deleted=ignore` to each DAR restore step so deletion records are not applied. This can preserve paths that did not exist at the requested point in time, especially in a non-empty overwrite target.

#### `--verbose`

Adds operational settings and restore progress to terminal output. It is separate from diagnostic logging controlled by `--log-level`.

#### `--log-level <level>`

Sets logging to `info` (default), `debug`, or `trace`.

#### `--log-stdout`

Copies application log messages to standard output as well as the configured log destination.

#### `--more-help`

Prints the manager’s extended help text and exits. The current extended text provides the command’s `NAME` description.

#### `-v`, `--version`

Prints the installed version and license information, then exits.

### Manager env vars

| Env var | Value | Description |
| --- | --- | --- |
| DAR_BACKUP_CONFIG_FILE | path to the config file | Default is $HOME/.config/dar-backup/dar-backup.conf |
| DAR_BACKUP_COMMAND_TIMEOUT_SECS | -1 or > 0 | Overrides config `COMMAND_TIMEOUT_SECS`. Use `-1` to disable timeouts. |

---

## Cleanup options

This script removes old backups and par2 files according to `[AGE]` settings in config file.

Catalogs in catalog databases are also removed.

Supported options:

```bash
-h, --help                                      Show command-line help and exit.
-d, --backup-definition                           Backup definition to cleanup.
-c, --config-file                                 Path to 'dar-backup.conf'
-v, --version                                     Show version & license information.
--alternate-archive-dir                           Clean up in this directory instead of the default one.
--cleanup-specific-archives [<archive>,...]       Clean up only the named archives; additional archive names may follow as positional arguments.
-l, --list                                        List available archives (filter using the -d option).
--dry-run                                        Show what would be deleted without removing files.
--verbose                                         Print various status messages to screen.
--log-level <level>                               `debug` or `trace`, default is `info`", default="info".
--log-stdout                                      Print log messages to stdout.
--test-mode                                       This is used when running pytest test cases
```

### Cleanup option details

#### `-h`, `--help`

Prints the generated command synopsis and short option descriptions, then exits without loading configuration or deleting archives.

#### `-d`, `--backup-definition <name>`

Restricts age-based cleanup or archive listing to one backup definition. Without it, normal cleanup processes every definition found in `BACKUP.D_DIR`.

#### `-c`, `--config-file <path>`

Loads configuration from the specified file. It overrides `DAR_BACKUP_CONFIG_FILE`; otherwise the default configuration path is used.

#### `-v`, `--version`

Prints the installed cleanup version information and exits.

#### `--alternate-archive-dir <path>`

Uses the specified existing directory instead of `BACKUP_DIR` for listing and deletion. The directory must be readable; deletion still follows the selected cleanup policy.

#### `--cleanup-specific-archives [<archive>,...]`

Deletes only explicitly named archives instead of performing age-based DIFF/INCR cleanup. Names may be supplied as a comma-separated option value and as additional positional arguments; unsafe names are rejected, and FULL deletion requires confirmation.

#### `-l`, `--list`

Lists available archives without deleting them. `--backup-definition` filters the displayed archive names.

#### `--dry-run`

Runs the selected cleanup logic and reports intended deletions without removing archive slices, PAR2 files, or catalog entries.

#### `--verbose`

Adds configuration and operation details to terminal output. Diagnostic log detail is controlled separately by `--log-level`.

#### `--log-level <level>`

Sets application logging to `info` (default), `debug`, or `trace`.

#### `--log-stdout`

Copies application log messages to standard output as well as the configured log destination.

#### `--test-mode`

Enables test-only behaviour used by the pytest suite, including non-interactive handling around controlled fixtures. It is not intended for production cleanup.

### Cleanup env vars

| Env var | Value | Description |
| --- | --- | --- |
| DAR_BACKUP_CONFIG_FILE | path to the config file | Default is $HOME/.config/dar-backup/dar-backup.conf |
| DAR_BACKUP_COMMAND_TIMEOUT_SECS | -1 or > 0 | Overrides config `COMMAND_TIMEOUT_SECS`. Use `-1` to disable timeouts. |

---

## Clean-log options

This script removes excessive logging output from `dar` logs, improving readability and efficiency. Available options:

```bash
-f, --file <path>          Specify the log file(s) to be cleaned.
-c, --config-file <path>   Path to dar-backup.conf.
--dry-run                  Show which lines would be removed without modifying the file.
-v, --version              Display version and licensing information.
-h, --help                 Displays usage info
```

### Clean-log option details

#### `-h`, `--help`

Prints command-line usage and exits without reading or modifying a log file.

#### `-f`, `--file <path> [<path> ...]`

Cleans one or more explicitly named log files. When omitted, the configured `LOGFILE_LOCATION` is used; every selected file must remain inside that configured log directory, and path traversal is rejected.

#### `-c`, `--config-file <path>`

Loads the configuration used to determine the default and permitted log directory. Resolution order is this option, `DAR_BACKUP_CONFIG_FILE`, then `~/.config/dar-backup/dar-backup.conf`.

#### `--dry-run`

Reports the lines that would be removed without replacing the source log file.

#### `-v`, `--version`

Prints the installed version and license information, then exits.

---

## Dar-backup-systemd options

Generates and optionally install systemd user service units and timers.

```bash
-h, --help           Show this help message and exit
--venv VENV          Path to the Python venv with dar-backup
--dar-path DAR_PATH  Optional path to dar binary's directory
--install            Install the units to ~/.config/systemd/user
```

### Dar-backup-systemd option details

#### `-h`, `--help`

Prints command-line usage and exits without generating or installing unit files.

#### `--venv <path>`

Specifies the required Python virtual environment containing the dar-backup commands. The path is embedded in generated `ExecStart` commands and must not contain a single quote.

#### `--dar-path <path>`

Adds an optional directory containing the DAR executable to the generated command environment. Like `--venv`, the value must not contain a single quote.

#### `--install`

Installs the generated service and timer units in `~/.config/systemd/user`, enables and starts the timers, and reloads the user systemd daemon. Without this flag, the command only generates the unit files.

---

## Installer options

Sets up `dar-backup` according to provided config file.

The installer creates the necessary backup catalog databases if `--create-db` is given.

```bash
--config                 Path to a config file. The configured directories will be created.
--create-db              Create backup catalog databases. Use this option with `--config`.
--install-autocompletion Add bash or zsh auto completion - idempotent.
--remove-autocompletion  Remove the auto completion from bash or zsh.
-v, --version            Display version and licensing information.
-h, --help               Displays usage info.
```

### Installer option details

#### `-h`, `--help`

Prints command-line usage and exits without creating directories, databases, or shell configuration.

#### `--config <path>`

Loads the specified configuration and creates its required directories after validating their paths. The file must exist; without this option the directory/database installation phase is skipped.

#### `--create-db`

Creates catalog databases for backup definitions after processing `--config`. It has no effect unless `--config` is also supplied.

#### `--install-autocompletion`

Adds dar-backup shell-completion setup to the detected shell startup file. It is mutually exclusive with `--remove-autocompletion`.

#### `--remove-autocompletion`

Removes dar-backup shell-completion setup from the shell startup file. It is mutually exclusive with `--install-autocompletion`.

#### `-v`, `--version`

Prints the installed version and license information, then exits.

---

## Demo options

Sets up `dar-backup` in a demo configuration.

It is non-destructive and stops if directories are already in place.

Create directories:

- ~/.config/dar-backup/
  - ~/.config/dar-backup/backup.d/
- ~/dar-backup/
  - ~/dar-backup/backups/
  - ~/dar-backup/restore/

Sets up demo config files:

- ~/.config/dar-backup/dar-backup.conf
- ~/.config/dar-backup/backup.d/demo

```bash
-i, --install       Sets up `dar-backup`.
--root-dir          Specify the root directory for the backup.
--dir-to-backup     Directory to backup, relative to the root directory.
--backup-dir        Directory where backups and redundancy files are put.
--override          By default, the script will not overwrite existing files or directories.
                    Use this option to override this behavior.
-g, --generate      Generate config files and put them in /tmp/ for inspection
                    without writing to $HOME.
--cleanup           Remove demo directories previously created under /tmp.
-v, --version       Display version and licensing information.
-h, --help          Displays usage info
```

### Demo option details

#### `-h`, `--help`

Prints command-line usage and exits without creating or removing demo data.

#### `-i`, `--install`

Creates the demo directories, configuration, backup definition, and default sample data. Existing paths cause the operation to fail unless `--override` is supplied.

#### `--root-dir <path>`

Overrides the demo backup definition’s `ROOT_DIR`. It must be supplied together with `--dir-to-backup`.

#### `--dir-to-backup <path>`

Overrides the directory selected beneath `--root-dir`. It must be supplied together with `--root-dir`.

#### `--backup-dir <path>`

Overrides the directory where the demo writes backup archives and redundancy files.

#### `--override`

Allows demo generation or installation to overwrite existing generated files and work with existing directories. Review custom paths carefully before enabling it.

#### `-g`, `--generate`

Renders only the demo configuration and backup-definition files beneath the demo `/tmp` configuration directory for inspection. It does not create the rest of the demo directory tree.

#### `--cleanup`

Removes the demo directories under `/tmp` that are managed by this command. It does not target arbitrary paths supplied to the other demo options.

#### `-v`, `--version`

Prints the installed version and license information, then exits.

---

## Dar-backup-dashboard options

Start Datasette and open the metrics dashboard in the browser.

```text
-h, --help         Show command-line help and exit.
--db PATH          Path to the metrics database.
                   Overrides METRICS_DB_PATH from the config file.
-c / --config-file PATH
                   Path to dar-backup.conf.
                   Default: $DAR_BACKUP_CONFIG_FILE or
                   ~/.config/dar-backup/dar-backup.conf
--port PORT        Preferred Datasette port (default: 8001).
                   A nearby free port is used automatically if taken.
--no-browser       Start Datasette but do not open a browser window.
                   Prints the dashboard URL to stdout instead.
```

### Dar-backup-dashboard option details

#### `-h`, `--help`

Prints command-line usage and exits without starting Datasette or opening a browser.

#### `--db <path>`

Uses the specified SQLite metrics database, overriding `METRICS_DB_PATH` from the selected configuration. The file must already exist.

#### `-c`, `--config-file <path>`

Loads dashboard settings from the specified configuration. It takes precedence over `DAR_BACKUP_CONFIG_FILE`, which in turn takes precedence over the default `~/.config/dar-backup/dar-backup.conf`.

#### `--port <port>`

Requests the Datasette listening port; the default is `8001`. If that port is occupied, the dashboard searches nearby ports and uses the first available one.

#### `--no-browser`

Starts Datasette without launching a browser and prints the dashboard URL to standard output instead.
