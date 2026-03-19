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
--restore <archive>                  Restore a specified archive.
-r, --restore <archive>              Restore archive.
--restore-dir                        Directory on which to restore
--verbose                            Enable verbose output.
--suppress-dar-msg                   Filter out this from the darrc: "-vt", "-vs", "-vd", "-vf", "-va"
--log-level <level>                  `debug` or `trace`, default is `info`.
--log-stdout                         Also print log messages to stdout.
--do-not-compare                     Do not compare restores to file system.
--allow-unsafe-definition-names      Disable backup definition name validation (allows underscores or other characters).
--preflight-check                    Run preflight checks and exit (runs automatically; this flag just exits after checks).
--examples                           Show examples of using dar-backup.
--readme                             Print README.md and exit
--readme-pretty                      Print README.md with Markdown styling and exit
--changelog                          Print Changelog and exit
--changelog-pretty                   Print Changelog with Markdown styling and exit
-v, --version                         Show version and license information.
```

### Dar-backup exit codes

- 0: Success.
- 1: Error (backup/restore/preflight failure).
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
--target <path>                      Target directory for restoration (default: current dir).
--pitr-report                        Report PITR archive chain for --restore-path/--when without restoring.
--pitr-report-first                  Run PITR chain report before restore and abort if missing archives.
--relocate-archive-path <old> <new>  Rewrite archive path prefix in the catalog DB (requires --backup-def).
--relocate-archive-path-dry-run      Show archive path changes without applying them (use with --relocate-archive-path).
--verbose                            Enable verbose output.
--log-level <level>                  Set log level (`debug` or `trace`, default is `info`).
```

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
-d, --backup-definition                           Backup definition to cleanup.
-c, --config-file                                 Path to 'dar-backup.conf'
-v, --version                                     Show version & license information.
--alternate-archive-dir                           Clean up in this directory instead of the default one.
--cleanup-specific-archives "<archive>, <>, ..."  Comma separated list of archives to cleanup.
-l, --list                                       List available archives (filter using the -d option).
--dry-run                                        Show what would be deleted without removing files.
--verbose                                         Print various status messages to screen.
--log-level <level>                               `debug` or `trace`, default is `info`", default="info".
--log-stdout                                      Print log messages to stdout.
--test-mode                                       This is used when running pytest test cases
```

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

---

## Dar-backup-systemd options

Generates and optionally install systemd user service units and timers.

```bash
-h, --help           Show this help message and exit
--venv VENV          Path to the Python venv with dar-backup
--dar-path DAR_PATH  Optional path to dar binary's directory
--install            Install the units to ~/.config/systemd/user
```

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
--generate          Generate config files and put them in /tmp/ for inspection
                    without writing to $HOME.
-v, --version       Display version and licensing information.
-h, --help          Displays usage info
```

---

## Dar-backup-dashboard options

Start Datasette and open the metrics dashboard in the browser.

```text
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
