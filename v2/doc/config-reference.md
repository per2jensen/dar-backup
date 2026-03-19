# Configuration Reference

Back to [README](../../README.md)

## Config file

The configuration file's default location is: `~/.config/dar-backup/dar-backup.conf`

If you have your config file somewhere else, use the `--config-file` option to point to it.

Tilde `~` and environment variables can be used in the paths for various file locations.

```text
[MISC]
LOGFILE_LOCATION=~/.dar-backup.log
# optional parameters
# LOGFILE_MAX_BYTES = 26214400  # 25 MB max file size is default, change as neeeded
# LOGFILE_BACKUP_COUNT = 5      # 5 backup log files is default, change as needed
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 1
NO_FILES_VERIFICATION = 5
# timeout in seconds for backup, test, restore and par2 operations
# The author has such `dar` tasks running for 10-15 hours on the yearly backups, so a value of 24 hours is used.
# If a timeout is not specified when using the util.run_command(), a default timeout of 30 secs is used.
# Use -1 to disable timeouts.
COMMAND_TIMEOUT_SECS = 86400

[DIRECTORIES]
BACKUP_DIR = /some/where/dar-backup/backups/
BACKUP.D_DIR = /some/where/dar-backup/backup.d
TEST_RESTORE_DIR = /tmp/dar-backup/restore/
# Optional parameter
# If you want to store the catalog databases away from the BACKUP_DIR, use the MANAGER_DB_DIR variable.
#MANAGER_DB_DIR = /some/where/else/

[AGE]
# age settings are in days
# `cleanup` script removes archives and their .par redundancy files if older than configured.
# `cleanup` does not remove FULL archives, unless specifically told to and a "y" is answered to "are you sure?".
DIFF_AGE = 100
INCR_AGE = 40

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True
# Optional PAR2 configuration
# PAR2_DIR = /path/to/par2-store
# PAR2_RATIO_FULL = 10
# PAR2_RATIO_DIFF = 5
# PAR2_RATIO_INCR = 5
# PAR2_RUN_VERIFY = false

# Optional per-backup overrides (section name = backup definition)
[media-files]
PAR2_DIR = /mnt/par2/media-files
PAR2_RATIO_FULL = 10

# scripts to run before the backup to setup the environment
[PREREQ]
SCRIPT_1 = ls -l /tmp
#SCRIPT_2 = another_script.sh

[POSTREQ]
SCRIPT_1 = df -h
#SCRIPT_2 = another_script.sh
```

PAR2 notes:

- If `PAR2_DIR` is unset, par2 files are created next to the archive slices (legacy behavior) and no manifest is written
- When `PAR2_DIR` is set, dar-backup writes a manifest next to the par2 set:
  `archive_base.par2.manifest.ini`
- When generating a par2 set, par2 reads all archive slices before writing any output files; for large backups, this initial read can take hours
- Verify or repair using:
  `par2 verify -B <archive_dir> <par2_set.par2>`
  `par2 repair -B <archive_dir> <par2_set.par2>`

## .darrc

The package includes a default `darrc` file which configures `dar`.

You can override the default `.darrc` using the `--darrc` option.

The default `.darrc` contents are as follows:

```text
#  .darrc configuration file for `dar` as used by the `dar-backup` script.
#  `dar-backup` lives here: https://github.com/per2jensen/dar-backup


##############################################################

#  target: verbose

#  remove comments belov for dar being more verbose

verbose:

# shows files teated due to filtering inclusion or no filtering at all

# -vt

# shows skipped files du to exclusion

# -vs

# shows diretory currently being processed
# dar-backup logs `dar` stdout in real time, so directories being processed are now shown in the log file.
# this is quite useful in long running jobs
 -vd

# shows detailed messages, not related to files and directories
# -vm

# shows summary of each treated directory, including average compression
# dar-backup logs `dar` stdout in real time, so directories being processed are now shown in the log file.
# this is quite useful in long running jobs
 -vf

# equivalent to "-vm -vs -vt"
# -va


restore-options:
# don't restore File Specific Attributes
#--fsa-scope none

# ignore owner, useful when used by a non-privileged user
--comparison-field=ignore-owner


# Exclude specific file types from compression
compress-exclusion:

# First setting case insensitive mode on:
-an
-ag

-Z    "*.gz"
-Z    "*.bz2"
-Z    "*.xz"
-Z    "*.zip"
-Z    "*.rar"
-Z    "*.7z"
-Z    "*.tar"
-Z    "*.tgz"
-Z    "*.tbz2"
-Z    "*.txz"
# Exclude common image file types from compression
-Z    "*.jpg"
-Z    "*.jpeg"
-Z    "*.png"
-Z    "*.gif"
-Z    "*.bmp"
-Z    "*.tiff"
-Z    "*.svg"
-Z    "*.ico"
-Z    "*.webp"
# The author uses Nikon compressed NEFs raw files
-Z    "*.NEF"
# Exclude common movie file types from compression
-Z    "*.mp4"
-Z    "*.avi"
-Z    "*.mkv"
-Z    "*.mov"
-Z    "*.wmv"
-Z    "*.flv"
-Z    "*.mpeg"
-Z    "*.mpg"

# These are zip files. Not all are compressed, but considering that they can
# get quite large it is probably more prudent to leave this uncommented.
-Z    "*.pk3"
-Z    "*.zip"

-Z    "*.lz4"
-Z    "*.zoo"

-Z    "*.Po"
-Z    "*.aar"
-Z    "*.bx"
-Z    "*.chm"
-Z    "*.doc"
-Z    "*.epub"
-Z    "*.f3d"
-Z    "*.gpg"
-Z    "*.htmlz"
-Z    "*.iix"
-Z    "*.iso"
-Z    "*.jin"
-Z    "*.ods"
-Z    "*.odt"
-Z    "*.ser"
-Z    "*.svgz"
-Z    "*.swx"
-Z    "*.sxi"
-Z    "*.whl"
-Z    "*.wings"


# Dar archives (may be compressed).
-Z    "*.dar"

# Now we swap back to case sensitive mode for masks which is the default
#mode:
-acase
```

## Backup definition example

This piece of configuration is a backup definition. It is placed in the `BACKUP.D_DIR` (see config file description).
The name of the file is the name of the backup definition.

Backup definition naming rules:
- Must contain only letters, numbers, spaces, or hyphens (`-`).
- No underscores (`_`).
- Must start and end with a letter or number (no leading/trailing spaces or hyphens).
If you need to keep legacy names, run `dar-backup` with `--allow-unsafe-definition-names` to disable the check.

You can use as many backup definitions as you need.

> Note
>
> Environment variables and tilde (~) not allowed here. `dar` does not expand them.

```text
 # Switch to ordered selection mode, which means that the following
 # options will be considered top to bottom
 -am

# Backup Root Dir
# This is the top directory, where the backups start.
#Directories mentioned below, are relative to the Root Dir.
 -R /home/user/

# Directories to backup below the Root dir
# uncomment the next line to backup only the Documents directory
# -g Documents

# Directories to exclude below the Root dir
 -P mnt
 -P tmp
 -P .cache
 -P .config/Code/CachedData

# compression level
 -z5

# no overwrite, if you rerun a backup, 'dar' halts and asks what to do
# due to the -Q option given to `dar`, the program will terminate and give en error.
 -n

# size of each slice in the archive
 --slice 7G

# bypass directores marked as cache directories
# http://dar.linux.free.fr/doc/Features.html
# https://bford.info/cachedir/
--cache-directory-tagging
```

---

## Config history

This section documents configuration changes introduced in each version.

### 1.0.1

#### DISCORD WEBHOOK

For Discord notifications use the `DAR_BACKUP_DISCORD_WEBHOOK_URL` environment variable. It should not be placed in the config file.

DAR_BACKUP_DISCORD_WEBHOOK_URL is the entire endpoint like this:

```bash
export DAR_BACKUP_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/\<userId\>/\<uuid\>
```

#### Restore test config

Restore tests choose random files from the archive and compare them with the live filesystem.
To avoid noisy paths (caches, temp files, logs), you can exclude candidates before the random
selection happens. All matching is case-insensitive.

Config keys (in [MISC]):

- RESTORETEST_EXCLUDE_PREFIXES: comma-separated path prefixes to skip. Matches from the start of
  the path (after trimming a leading "/"). Use trailing "/" for directories.
- RESTORETEST_EXCLUDE_SUFFIXES: comma-separated filename suffixes to skip.
- RESTORETEST_EXCLUDE_REGEX: optional regex to skip anything matching the path.

Example:

```ini
[MISC]
RESTORETEST_EXCLUDE_PREFIXES = .cache/, .local/share/Trash/, .mozilla/, snap/firefox/common/.mozilla/
RESTORETEST_EXCLUDE_SUFFIXES = .sqlite-wal, .sqlite-shm, .log, .tmp, .lock, .journal
RESTORETEST_EXCLUDE_REGEX = (^|/)(Cache|cache|Logs|log)/
```

Regex tips (case-insensitive):

- Match common cache/log directories anywhere:
  `(^|/)(cache|logs)/`
- Skip thumbnails and temp dirs:
  `(^|/)(thumbnails|tmp|temp)/`
- Exclude browser profile noise while keeping other files:
  `(^|/)\.mozilla/|/snap/firefox/common/\.mozilla/`

#### Par2

New optional PAR2 settings were added to the config file. If none of these keys are added, dar-backup behaves exactly as before (PAR2 files next to archives, per-slice parity).

| Name | Description | When it is in effect | Suggested value |
|------|-------------|----------------------|-----------------|
| PAR2_DIR | Directory to store .par2 and .vol*.par2 files | When set | A different device or mount from BACKUP_DIR |
| PAR2_RATIO_FULL | Redundancy percent for FULL | When set | 10 (%) |
| PAR2_RATIO_DIFF | Redundancy percent for DIFF | When set | 5  (%)|
| PAR2_RATIO_INCR | Redundancy percent for INCR | When set | 5  (%)|
| PAR2_RUN_VERIFY | Verify after create | When set | false |

Notes:

- PAR2_RATIO_*, and PAR2_RUN_VERIFY apply even if PAR2_DIR is not set (i.e. par2 output stays next to the archives).

Per-backup overrides use a section named after the backup definition with the same PAR2_* keys:

```text

######################################################################
# Per-backup configuration example overrides
######################################################################

# --------------------------------------------------------------------
# Per-backup overrides (section name must match backup.d filename stem)
# Example: backup.d/home.conf  ->  [home]
# --------------------------------------------------------------------

#[home]
# Disable PAR2 entirely for this backup definition
PAR2_ENABLED = false
#
#[media]
# Store PAR2 files in a separate location for this backup definition
#PAR2_DIR = /samba/par2/media
# Raise redundancy only for FULL
#
[documents]
# Run verify par2 sets after creation
PAR2_RUN_VERIFY = true
#
#[etc]
# Keep global PAR2 settings but tweak ratios for this backup definition
# RATIO is given in percent (%)
#PAR2_RATIO_FULL = 15
#PAR2_RATIO_DIFF = 8
#PAR2_RATIO_INCR = 8
```

[Per-backup override test case: `tests/test_par2_overrides.py`](../tests/test_par2_overrides.py)

### 1.0.2

#### Trace Logging

To support debugging without cluttering the main log file, a secondary trace log is now created (e.g., `dar-backup.trace.log`).
This file captures all `DEBUG` level messages and full exception stack traces.

You can configure its rotation in the `[MISC]` section:

- `TRACE_LOG_MAX_BYTES`: Max size of the trace log file in bytes. Default is `10485760` (10 MB).
- `TRACE_LOG_BACKUP_COUNT`: Number of rotated trace log files to keep. Default is `1`.

Example:

```ini
[MISC]
TRACE_LOG_MAX_BYTES = 10485760
TRACE_LOG_BACKUP_COUNT = 1
```

#### Command output Capture

- New optional `[MISC]` setting: `COMMAND_CAPTURE_MAX_BYTES` (default 102400).
  - Limits how much stdout/stderr is kept in memory per command while still logging full output.
  - Set to `0` to disable buffering entirely. Command output is still streamed to dar-backup-commands.log
  - If set to `0`, the calling function cannot rely on output from the executed command. The exit value is the only result provided.

Example:

```ini
[MISC]
COMMAND_CAPTURE_MAX_BYTES = 102400
```

### 1.1.0

COMMAND_TIMEOUT_SECS=-1 now disables timeout for commands executed.

### 1.1.1

Env var `DAR_BACKUP_COMMAND_TIMEOUT_SECS` now overrides config file var `COMMAND_TIMEOUT_SECS`.

### 1.1.2

#### METRICS_DB_PATH

Optional. When set, dar-backup records a row of operational metrics into a SQLite database after each backup run.

```ini
[MISC]
METRICS_DB_PATH = /var/lib/dar-backup/metrics.db
```

Tilde and environment variable expansion are supported:

```ini
METRICS_DB_PATH = ~/dar-backup/metrics.db
METRICS_DB_PATH = $XDG_DATA_HOME/dar-backup/metrics.db
```

If `METRICS_DB_PATH` is absent or empty, metrics collection is silently disabled — no database is created and backups are unaffected.

The database is created automatically on first use. If an older database exists (created before this version), the new columns are added automatically; no data is lost.

Metrics recorded per run include timing (total, dar, verify, PAR2), archive size, free disk space, hostname, inode statistics from dar's summary output (files saved, failed, excluded, not saved, deleted, etc.), and the outcome (SUCCESS / WARNING / FAILURE).

A metrics write failure never aborts or affects the backup — errors are logged at WARNING level and swallowed.
