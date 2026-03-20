# Getting Started

📦 All official dar-backup releases from v2-beta-0.6.18 are signed with GPG — see the
[GPG signing key](https://github.com/per2jensen/dar-backup#gpg-signing-key) section.

## 1 - installation

Install as shown in the [TL;DR](https://github.com/per2jensen/dar-backup#tldr) or [Quick Guide](quick-guide.md).

A handy alias to activate the venv and launch `dar-backup` in one step:

```bash
grep -qxF 'alias db="' ~/.bashrc \
  || echo 'alias db=". ~/tmp/venv/bin/activate; dar-backup -v"' >> ~/.bashrc

source ~/.bashrc
```

Typing `db` at the command line gives something like this:

```bash
(venv) user@machine:~$ db
dar-backup 1.1.2
...
```

## 2 - configuration

The dar-backup [installer](cli-reference.md#installer-options) application sets up the needed
directories for `dar-backup` to work. It creates necessary directories as prescribed in the config
file and optionally creates manager databases. It can also configure shell auto completion.

1. Create a config file — [see details on config file](config-reference.md#config-file)

2. Create one or more backup definitions — [see details on backup definitions](config-reference.md#backup-definition-example)

3. Run the installer:

```bash
installer --config <path to dar-backup.conf> --install-autocompletion
```

## 3 - generate catalog databases

Generate the archive catalog database(s).

`dar-backup` expects the catalog databases to be in place — it does not create them automatically
(by design).

```bash
manager --create-db
```

## 4 - give dar-backup a spin

You are now ready to do backups as configured in your backup definition(s).

```bash
dar-backup --full-backup --verbose

# list backups
dar-backup --list

# list contents of a dar backup
dar-backup --list-contents <TAB>... <choose a backup>

# see some examples on usage
dar-backup --examples

# see the log file
cat "$HOME/dar-backup/dar-backup.log"
```

If you want to see dar-backup's log entries in the terminal, use the `--log-stdout` option.

If you want more log messages, use `--verbose` or `--log-level debug` for even more.

To back up a single backup definition:

```bash
dar-backup --full-backup -d <your backup definition>
```

When done, deactivate the venv with `deactivate`.
