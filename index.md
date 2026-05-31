<!-- markdownlint-disable MD024 -->
# `dar-backup`

**Long-term archival backups for Linux — with integrity you can prove and repair**

[![codecov](https://codecov.io/gh/per2jensen/dar-backup/branch/main/graph/badge.svg)](https://codecov.io/gh/per2jensen/dar-backup)
[![Snyk](https://snyk.io/test/github/per2jensen/dar-backup/badge.svg)](https://security.snyk.io/vuln/?search=dar-backup)
[![CI](https://github.com/per2jensen/dar-backup/actions/workflows/py-tests.yml/badge.svg)](https://github.com/per2jensen/dar-backup/actions/workflows/py-tests.yml)
[![PyPI version](https://img.shields.io/pypi/v/dar-backup.svg)](https://pypi.org/project/dar-backup/)
[![PyPI downloads](https://img.shields.io/badge/dynamic/json?color=blue&label=PyPI%20downloads&query=total_downloads&url=https%3A%2F%2Fraw.githubusercontent.com%2Fper2jensen%2Fdar-backup%2Fmain%2Fclonepulse%2Fdownloads.json)](https://pypi.org/project/dar-backup/)

`dar-backup` is a Python CLI that orchestrates [DAR](https://github.com/Edrusb/DAR) backups
for Linux users who want **serious, long-term archival** — not just file copies.
Every archive is automatically verified, restore-tested, and equipped with PAR2 redundancy
files for bitrot repair. Years from now, on hardware you don't own yet, you'll be able to
recover any file to any point in time.

## Is this for you?

✅ You back up irreplaceable data — photos, documents, home-made video — and need to be
certain you can restore any file to any point in time, years from now

✅ You run backups as a **normal user** — root is not required, and FUSE-mounted filesystems
(Nextcloud, rclone, sshfs) work correctly

✅ You want **bitrot repair** to travel with your archives — onto USB disks, offsite copies,
and cloud storage — without depending on the original system

✅ You want unattended, scheduled backups with **Discord notifications** on success or failure

✅ You want a transparent, no-lock-in tool built on proven Unix components

✗ You need a GUI, Windows support, or just a quick incremental sync — `rsync` or `restic` may
suit you better

✗ You need **multiple backups per day** — `dar-backup` is designed around one backup run per
day per definition. For hourly or continuous backups, look at `restic` or `BorgBackup`

## Quick Start

```bash
sudo apt -y install dar par2 python3 python3-venv
INSTALL_DIR=/tmp/dar-backup; mkdir "$INSTALL_DIR" && cd "$INSTALL_DIR"
python3 -m venv venv && . venv/bin/activate
pip install dar-backup
demo --install && manager --create-db
dar-backup --full-backup
```

## What It Does

After each archive, `dar-backup` automatically:

1. **Verifies** the archive with `dar -t`
2. **Restore-tests** a random sample of files and compares them byte-for-byte against the source
3. **Creates PAR2 redundancy files** so the archive can be repaired if bitrot occurs later
4. **Notifies** your Discord channel on completion or failure

Schedules are managed by systemd timers (generated for you). Catalogs of every archive are
maintained by `dar_manager`, enabling single-file Point-in-Time Recovery (PITR) without a
database server.

## Built on Two Exceptional Tools

- **[dar](https://github.com/Edrusb/DAR)** — a powerful, actively maintained archiver by Denis
Corbin with native FULL/DIFF/INCR cycles, built-in verification, catalogue databases, and
precise file selection. `dar` is the engine that makes long-term archival practical.
- **[par2cmdline](https://github.com/Parchive/par2cmdline)** — Reed-Solomon based redundancy
that can detect and repair corruption in any file, years after the fact, with no connection to
the original source.

> If you find `dar-backup` useful, consider giving those upstream projects a star too.

## Why not restic / BorgBackup / tar?

| Concern                                     | dar-backup                             |
| ------------------------------------------- | -------------------------------------- |
| Run as non-root on FUSE mounts              | ✅ designed for this                    |
| Bitrot repair without re-downloading        | ✅ PAR2 travels with the archive        |
| Restore a single file to a specific date    | ✅ PITR via dar\_manager catalogs       |
| No dependency on original system to restore | ✅ one static `dar` binary is enough    |
| Archive integrity testable anywhere         | ✅ `par2verify` + `dar -t` work offline |

→ [Full comparison with restic, BorgBackup, and tar](https://github.com/per2jensen/dar-backup#why-not-just-use-restic--borgbackup--rsync)

## Status

- **1000+ tests** — unit and integration, covering PAR2 bitrot repair, full/diff/incr restore chains, PITR verification, and edge cases
- **CI on every commit**
- The author has used `dar-backup` for ~5 years and has been saved by it multiple times
- Reached **v1.0.0** on October 9, 2025 · [Changelog](https://github.com/per2jensen/dar-backup/blob/main/CHANGELOG.md)
- Python >= 3.11 required

## Documentation

| Document | Description |
| -------- | ----------- |
| [Quick Guide](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/quick-guide.md) | Get started in minutes using the demo app |
| [Getting Started](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/getting-started.md) | Manual setup for a real installation |
| [Configuration Reference](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/config-reference.md) | Config file, .darrc, backup definitions |
| [Restoring](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/restoring.md) | Point-in-Time Recovery (PITR), restore examples |
| [PAR2 Redundancy](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/par2.md) | Verify, repair, and create PAR2 files |
| [systemd Setup](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/systemd-setup.md) | Generate and install systemd timers/services |
| [Dashboard & Metrics](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/dashboard-and-metrics.md) | Metrics database, Datasette, dashboard |
| [CLI Reference](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/cli-reference.md) | All command options, exit codes, env vars |
| [Troubleshooting](https://github.com/per2jensen/dar-backup/blob/main/v2/doc/troubleshooting.md) | Error codes, FUSE issues, special characters |

## Links

- GitHub repo: https://github.com/per2jensen/dar-backup
- PyPI: https://pypi.org/project/dar-backup/
- Scope notes: no built-in encryption (assumes storage is already encrypted); Linux only; not a backup appliance
