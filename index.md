<!-- markdownlint-disable MD024 -->
# `dar-backup`

**Reliable DAR backups, automated in clean Python**

[![codecov](https://codecov.io/gh/per2jensen/dar-backup/branch/main/graph/badge.svg)](https://codecov.io/gh/per2jensen/dar-backup)
[![PyPI version](https://img.shields.io/pypi/v/dar-backup.svg)](https://pypi.org/project/dar-backup/)
[![PyPI downloads](https://img.shields.io/badge/dynamic/json?color=blue&label=PyPI%20downloads&query=total_downloads&url=https%3A%2F%2Fraw.githubusercontent.com%2Fper2jensen%2Fdar-backup%2Fmain%2Fdownloads.json)](https://pypi.org/project/dar-backup/)
[![# clones](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/per2jensen/dar-backup/main/clonepulse/badge_clones.json)](https://github.com/per2jensen/dar-backup/blob/main/clonepulse/weekly_clones.png)

`dar-backup` is a Python CLI that orchestrates [DAR](https://github.com/Edrusb/DAR) backups and catalog management. It focuses on reliable, repeatable backups with restore verification and practical guardrails for long-term use. It is especially useful when backing up user-space filesystems (FUSE, cloud mounts) where running backups as root is not suitable.

## Objectives

- Keep backups reliable over time with automated verification and restore checks.
- Make restores straightforward, even years later.
- Work well for non-privileged, user-space filesystems.
- Avoid surprises: clear logs, safe defaults, and explicit restore targets.

## What It Does

- Full, differential, and incremental backups with validation.
- Optional restore tests to ensure archives are usable.
- Par2 redundancy files for bitrot repair.
- Catalog databases to speed up restores and Point-in-Time Recovery (PITR).
- PITR restore by timestamp using catalog metadata.
- Shell autocompletion and systemd unit generation for automation.

## Scope Notes

- No built-in encryption (assumes storage is already encrypted).
- Linux-first workflow; depends on DAR and Par2.
- Not a "backup appliance"; it is a toolchain for people who want control.

## Status

- Actively used by the author for several years.
- Python version is `v2` (see repo link below).
- Python >= 3.11 required (older versions affected by a known XXE vulnerability).

## Quick Links

- GitHub repo: https://github.com/per2jensen/dar-backup
- Version 2 source: https://github.com/per2jensen/dar-backup/tree/main/v2
- Changelog: https://github.com/per2jensen/dar-backup/blob/main/v2/Changelog.md
- Full documentation: https://github.com/per2jensen/dar-backup/blob/main/README.md
- PyPI: https://pypi.org/project/dar-backup/
