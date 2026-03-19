# Shell Autocompletion

Back to [README](../../README.md)

The `dar-backup`, `manager`, and `cleanup` scripts support dynamic tab-completion, making them easier and faster to use.

## Features

- Autocomplete for all long options (--config-file, --restore, etc.)

- Dynamic suggestions based on your config:

- --backup-definition shows available definitions from backup.d/

- Show relevant archives when a backup definition has been chosen:

  dar-backup: --restore, --list-contents, and --alternate-reference-archive

  cleanup: --cleanup-specific-archives

  manager:  --list-archive-contents, --add-specific-archive (autocomplete those **not** in the catalog database), --remove-specific-archive

- Supports paths like ~ and $HOME correctly

## Use it

Try typing:

```bash
dar-backup --<TAB>
```

You should see all available flags like --full-backup, --restore, etc.

Try completion of backup definition and then list contents:

```bash
    dar-backup --backup-definition <TAB>
    dar-backup -d <the chosen backup-definition> --list-contents <TAB>
```

## Archive name completion (smart, context-aware)

When using `manager --list-archive-contents`, the tab-completer suggests valid archive names.

The behavior is smart and context-aware:

- If a --backup-definition (-d) is provided, archive suggestions are restricted to that .db catalog.

- If no backup definition is given, the completer will:
  - Scan all .db files in the backup_dir
  - Aggregate archive names across all catalogs
  - Sort results by:
    - Backup name (e.g. pCloudDrive, media-files)
    - Date inside the archive name (e.g. 2025-04-19)

It's blazing fast and designed for large backup sets.

```bash
# With a backup definition
manager -d pCloudDrive --list-archive-contents <TAB>
# ⤷ Suggests: pCloudDrive_FULL_2025-03-04, pCloudDrive_INCR_2025-04-19, ...

# Without a backup definition
manager --list-archive-contents <TAB>
# ⤷ Suggests: all archives across all known backup definitions
# ⤷ Example: media-files_FULL_2025-01-04, pCloudDrive_INCR_2025-04-19, ...

# Filter by prefix
manager --list-archive-contents media-<TAB>
# ⤷ Suggests: media-files_FULL_2025-01-04, media-files_INCR_2025-02-20, ...
```

## Enabling Bash completion

Try auto completion in your session:

```bash
eval "$(register-python-argcomplete dar-backup)"
eval "$(register-python-argcomplete cleanup)"
eval "$(register-python-argcomplete manager)"
#complete -o nosort -C 'python -m argcomplete cleanup' cleanup
#complete -o nosort -C 'python -m argcomplete manager' manager
```

To make it persistent across sessions, add this to your ~/.bashrc:

```bash
# Enable autocompletion for dar-backup
eval "$(register-python-argcomplete dar-backup)"
eval "$(register-python-argcomplete cleanup)"
eval "$(register-python-argcomplete manager)"
# This disables bash sorting, so sorting is by <backup definition> and <date>
#complete -o nosort -C 'python -m argcomplete cleanup' cleanup
#complete -o nosort -C 'python -m argcomplete manager' manager
```

If you're using a virtual environment and register-python-argcomplete isn't in your global PATH, use:

```bash
# Enable autocompletion for dar-backup
eval "$($(which register-python-argcomplete) dar-backup)"
eval "$($(which register-python-argcomplete) cleanup)"
eval "$($(which register-python-argcomplete) manager)"

# If it's not working, try reactivating your virtualenv and restarting your terminal.
```

Then reload your shell:

```bash
source ~/.bashrc
```

## Enable Zsh Completion

If you're using Zsh, add this to your .zshrc:

```zsh
autoload -U bashcompinit
bashcompinit
eval "$(register-python-argcomplete dar-backup)"
eval "$(register-python-argcomplete cleanup)"
eval "$(register-python-argcomplete manager)"
```

Then reload Zsh:

```zsh
source ~/.zshrc
```
