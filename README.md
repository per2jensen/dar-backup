<!-- markdownlint-disable MD024 -->
# `dar-backup`

**Long-term archival backups for Linux — with integrity you can prove and repair**

[![Codecov](https://codecov.io/gh/per2jensen/dar-backup/branch/main/graph/badge.svg)](https://codecov.io/gh/per2jensen/dar-backup)
[![Snyk Vuln findings](https://snyk.io/test/github/per2jensen/dar-backup/badge.svg)](https://security.snyk.io/vuln/?search=dar-backup)
![CI](https://github.com/per2jensen/dar-backup/actions/workflows/py-tests.yml/badge.svg)
[![PyPI version](https://img.shields.io/pypi/v/dar-backup.svg)](https://pypi.org/project/dar-backup/)
[![PyPI downloads](https://img.shields.io/badge/dynamic/json?color=blue&label=PyPI%20downloads&query=total_downloads&url=https%3A%2F%2Fraw.githubusercontent.com%2Fper2jensen%2Fdar-backup%2Fmain%2Fclonepulse%2Fdownloads.json)](https://pypi.org/project/dar-backup/)
[![# clones](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/per2jensen/dar-backup/main/clonepulse/badge_clones.json)](https://github.com/per2jensen/dar-backup/blob/main/clonepulse/weekly_clones.png)
[![Milestone](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/per2jensen/dar-backup/main/clonepulse/milestone_badge.json)](https://github.com/per2jensen/dar-backup/blob/main/clonepulse/weekly_clones.png)  <sub>🎯 Stats powered by [ClonePulse](https://github.com/per2jensen/clonepulse)</sub>

`dar-backup` is for Linux users who want **serious, long-term backups** — not just file copies.
It automates FULL / DIFF / INCR archive cycles built on two exceptional open-source tools:

- **[dar](https://github.com/Edrusb/DAR)** (Disk ARchiver) — a powerful, actively maintained
  archiver by Denis Corbin that handles differential and incremental archives, built-in
  verification, catalogue databases, and precise file selection. `dar` is the engine that makes
  long-term archival practical. It deserves to be far better known than it is.
- **[par2cmdline](https://github.com/Parchive/par2cmdline)** — the Parchive suite's
  implementation of PAR2, a Reed-Solomon based redundancy format that can detect and repair
  corruption in any file, years after the fact, with no connection to the original source.
  A quiet but remarkable piece of technology.

`dar-backup` wires these two tools together into a fully automated backup system, with every
archive verified and restore-tested before the job completes.

**Is this for you?**

✅ You back up irreplaceable data — photos, documents, home-made video — and want to be
   certain you can restore any file to any point in time, years from now

✅ You run backups as a **normal user** — root is not required, and FUSE-mounted filesystems (Nextcloud, rclone, sshfs) work correctly

✅ You want **bitrot repair** to travel with your archives — onto USB disks, offsite copies, and cloud storage — without depending on the original system

✅ You want unattended, scheduled backups with **Discord notifications** on success or failure

✅ You want a transparent, no-lock-in tool built on proven Unix components

✗ You need a GUI, Windows support, or just a quick incremental sync — `rsync` or `restic` may suit you better

✗ You need **multiple backups per day** — dar-backup is designed around one backup run per day
   per definition (one FULL, one DIFF, one INCR). If you need hourly or continuous backups,
   look at `restic` or `BorgBackup` instead

---

## TL;DR

```bash
# prep
sudo apt -y install dar par2 python3 python3-venv
INSTALL_DIR=/tmp/dar-backup; mkdir "$INSTALL_DIR" && cd "$INSTALL_DIR"
python3 -m venv venv    # create a virtual environment
. venv/bin/activate     # activate the virtual environment
# install and run dar-backup
pip install dar-backup
demo --install && manager --create-db
dar-backup --full-backup
```

`dar-backup` runs FULL, DIFF, and INCR backup cycles across as many backup definitions as you
need (e.g. `photos`, `documents`, `homevideos`). After each archive it:

1. **Verifies** the archive with `dar -t`
2. **Restore-tests** a random sample of files and compares them byte-for-byte against the source
3. **Creates PAR2 redundancy files** so the archive can be repaired if bitrot occurs later
4. **Notifies** your Discord channel on completion or failure

Schedules are managed by systemd timers (generated for you). Catalogs of every archive are
maintained by `dar_manager`, enabling single-file Point-in-Time Recovery without a database
server.

Version **1.1.2** · reached **1.0.0** on October 9, 2025 · [Changelog](CHANGELOG.md)

---

## Why not just use restic / BorgBackup / rsync?

Those are excellent tools. `dar-backup` fills a different niche:

| Concern | dar-backup |
|---|---|
| Run as non-root on FUSE mounts | ✅ designed for this |
| Bitrot repair without re-downloading | ✅ PAR2 travels with the archive |
| Restore a single file to a specific date | ✅ PITR via dar_manager catalogs |
| No dependency on original system to restore | ✅ one static `dar` binary is enough |
| Archive integrity testable anywhere | ✅ `par2verify` + `dar -t` work offline |
| Transparent, auditable backup content | ✅ `dar` archives are well-documented |

If your threat model is *"I need to recover a file I deleted three months ago, on a machine I
no longer have, from a USB disk I kept offsite"* — `dar-backup` is built for exactly that.

---

## Why not just use tar?

`tar` is the tool almost every Linux user reaches for first — and for good reason. It is simple, universal, and ships on every system. `dar` was written as a deliberate improvement on `tar` for long-term archival, and the differences matter:

| Capability | tar | dar-backup |
|---|---|---|
| FULL / DIFF / INCR backup cycles | ❌ workarounds only | ✅ native, first-class |
| Archive integrity test | ❌ no built-in verify | ✅ `dar -t` after every backup |
| Restore-test a random sample | ❌ manual | ✅ automatic after each run |
| Repair a corrupt archive | ❌ not possible | ✅ PAR2 files travel with the archive |
| Restore a single file to a specific date | ❌ no catalogue | ✅ PITR via `dar_manager` catalogs |
| Sliced archives (fits onto fixed-size media) | ❌ | ✅ configurable slice size |
| Extended attributes and ACLs | ⚠️ flag-dependent | ✅ handled correctly by default |
| No dependency on original system to restore | ✅ | ✅ one static `dar` binary is enough |

In short: `tar` is excellent for one-off archiving and moving files around.
`dar-backup` is for people who want to know their data is intact and recoverable — years from now,
on hardware they don't own yet.

---

## Features

- **FULL / DIFF / INCR backup cycles** — per backup definition, independently scheduled
- **Automatic archive verification** — `dar -t` after every backup run
- **Automatic restore test** — random files extracted and compared to source after each backup;
  configurable excludes for cache dirs, temp files, locks
- **PAR2 redundancy** — configurable coverage per backup type (FULL/DIFF/INCR);
  optionally stored in a separate directory (different device or offsite mount)
- **Point-in-Time Recovery** — `dar_manager` catalogs let you locate and restore any file
  to any date across your full archive history
- **Metrics and dashboard** - optional [detailed metrics](v2/doc/dashboard-and-metrics.md#metrics-database) and [dashboard](v2/doc/dashboard-and-metrics.md#dashboard)
- **Runs as a normal user** — no root needed; works correctly on FUSE-mounted filesystems
- **systemd integration** — timer units generated for you with sensible default schedules
- **Discord notifications** — webhook alerts on backup success or failure, from all CLI tools
- **Shell autocompletion** — bash and zsh, context-aware (archive names filtered by definition)
- **Clean logging** — three log files (main, command output, trace/debug), all rotating and
  size-capped; `clean-log` strips verbose `dar` output when not needed
- **No lock-in** — standard `dar` archives, standard PAR2 files; restore with just the `dar`
  binary, no `dar-backup` installation required on the restore machine
- **750+ tests** — unit and integration tests covering PAR2 bitrot repair, full/diff/incr
  restore chains, PITR verification, and edge cases; CI on every commit

✅ The author has used `dar-backup` ~5 years and has been saved by it multiple times.

> `dar-backup` stands on the shoulders of two projects that do the real work.
> Sincere thanks to **Denis Corbin** for `dar`, and to the **Parchive team** for `par2`.
> If you find `dar-backup` useful, consider giving those projects a star too.

---

## Dashboard

Every backup run writes structured metrics to a SQLite database. The built-in
`dar-backup-dashboard` command fires up [datasette](https://datasette.io/) and
opens the dashboard in your browser:

[![dar-backup metrics dashboard](v2/doc/dar-backup-dashboard.png)](v2/doc/dar-backup-dashboard-full.png)

→ [Dashboard & metrics documentation](v2/doc/dashboard-and-metrics.md)

---

## High-level architecture

[![dar-backup overview](v2/doc/dar-backup-overview-small.png)](v2/doc/dar-backup-overview.png)

---

## Documentation

| Document | Description |
|---|---|
| [Quick Guide](v2/doc/quick-guide.md) | Get started in minutes using the demo app |
| [Getting Started](v2/doc/getting-started.md) | Manual setup for a real installation |
| [Configuration Reference](v2/doc/config-reference.md) | Config file, .darrc, backup definitions, config history |
| [Restoring](v2/doc/restoring.md) | Point-in-Time Recovery (PITR), restore examples |
| [PAR2 Redundancy](v2/doc/par2.md) | Verify, repair, and create PAR2 files |
| [systemd Setup](v2/doc/systemd-setup.md) | Generate and install systemd timers/services |
| [Shell Autocompletion](v2/doc/shell-completion.md) | Bash and zsh tab-completion setup |
| [Dashboard & Metrics](v2/doc/dashboard-and-metrics.md) | Metrics database, Datasette, dashboard |
| [dar Tips](v2/doc/dar-tips.md) | File selection, merging archives, logging tips |
| [CLI Reference](v2/doc/cli-reference.md) | All command options, exit codes, env vars |
| [Troubleshooting](v2/doc/troubleshooting.md) | Error codes, FUSE issues, special characters |
| [Development](v2/doc/dev.md) | Dev setup, testing, PyPI, building dar |
| [Changelog](CHANGELOG.md) | High-level release history |
| [Detailed Changelog](v2/Changelog.md) | Per-release details |

---

## My use case

I needed the following:

- Backup my workstation to a remote server
- Backup primarily photos, home made video and different types of documents
- I have cloud storage mounted on a directory within my home dir. The filesystem is [FUSE based](https://www.kernel.org/doc/html/latest/filesystems/fuse.html), which gives it a few special features
  - Backup my cloud storage (cloud is convenient, but I want control over my backups)
  - A non-privileged user can perform a mount
  - A privileged user cannot look into the filesystem --> a backup script running as root is not suitable

- Have a simple way of restoring, possibly years into the future. 'dar' fits that scenario with a single statically linked binary (kept with the archives). There is no need install/configure anything - restoring is simple and works well.
- During backup archives must be tested and a restore test (however small) performed
- Archives stored on a server with a reliable file system (easy to mount a directory over sshfs)
- Easy to verify archive's integrity, after being moved around.

 I do not need the encryption features of dar, as all storage is already encrypted.

## My setup

1. Primary backup to server with an ext4 file system on mdadm RAID1

2. Secondary copies to multiple USB disks / cloud

3. Archive integrity verification anywhere using [Par2](v2/doc/par2.md) and `dar -t`.

4. Archive repair anywhere if needed. By default `dar-backup` creates par2 redundancy files with 5% coverage. Enough to fix localized bitrot.

5. No dependency on original system

### Why PAR2 is especially good for portable / offsite copies

PAR2 parity is:

> Self-contained (travels with the data)
>
>Format-agnostic (works on any filesystem)
>
>Location-agnostic (local disk, USB, cloud object storage)
>
>Tool-stable (PAR2 spec has not changed in years)
>
>That means:
>
>**Integrity protection moves with the archive**.

### Design choices

My design choices are boring, proven and pragmatic:

- mdadm handles disks
- PAR2 handles data integrity
- You control when and how verification happens
- Errors have a fair chance of being diagnosed and fixed, due to well known tooling.
- No hidden magic, no lock-in

---

## Quick Guide

Step-by-step walkthrough using the built-in `demo` application — install, backup, list, restore.

→ [Quick Guide](v2/doc/quick-guide.md)

---

## dar-backup principles

### dar-backup

`dar-backup` is built in a way that emphasizes getting backups. It loops over the backup definitions, and in the event of a failure while backing up a backup definition, dar-backup shall log an error and start working on the next backup definition.

There are 3 levels of backups, FULL, DIFF and INCR.

- The author does a FULL yearly backup once a year. This includes all files in all directories as defined in the backup definition(s) (assuming `-d` was not given).
- The author makes a DIFF once a month. The DIFF backs up new and changed files **compared** to the **FULL** backup.

  - No DIFF backups are taken until a FULL backup has been taken for a particular backup definition.

- The author takes an INCR backup every 3 days. An INCR backup includes new and changed files **compared** to the **DIFF** backup.

  - So, a set of INCR's will contain duplicates (this might change as I become more used to use the catalog databases)

  - No INCR backups are taken until a DIFF backup has been taken for a particular backup definition.

After each backup of a backup definition, `dar-backup` tests the archive and then performs a few restore operations of random files from the archive (see [config file](v2/doc/config-reference.md#config-file)). The restored files are compared to the originals to check if the restore went well.

`dar-backup` skips doing a backup of a backup definition if an archive is already in place. So, if you for some reason need to take a new backup on the same date, the first archive must be deleted (I recommend using [cleanup](v2/doc/cli-reference.md#cleanup-options)).

### cleanup

The `cleanup` application deletes DIFF and INCR if the archives are older than the thresholds set up in the configuration file.

`cleanup` will only remove FULL archives if the option  `--cleanup-specific-archives` is used. It requires the user to confirm deletion of FULL archives.

Use `--dry-run` to preview which archives, PAR2 files, and catalogs would be removed without deleting anything.

Examples:

```bash
cleanup --dry-run -d media-files --log-stdout
cleanup --dry-run --cleanup-specific-archives -d media-files media-files_INCR_2025-12-22
```

### manager

`dar`has the concept of catalogs which can be exported and optionally be added to a catalog database. That database makes it much easier to restore the correct version of a backed up file if for example a target date has been set.

`dar-backup` adds archive catalogs to their databases (using the `manager` script). Should the operation fail, `dar-backup` logs an error and continue with testing and restore validation tests.

---

## How to run

Manual setup for a real installation — configuration, catalog databases, first backup.

→ [Getting Started](v2/doc/getting-started.md)

---

## Status

**1.0.0 milestone reached**

October 9, 2025, version **1.0.0** was released after extensive testing. The current release is **1.1.2**.

### GPG Signing key

To increase the security and authenticity of dar-backup packages, all releases from v2-beta-0.6.18 onwards will be digitally signed using the GPG key below.

<br>

<details>

<summary>🎯 GPG Signing Key Details</summary>

```text
Name:        Per Jensen (author of dar-backup)
Email:       dar-backup@pm.me
Primary key: 4592 D739 6DBA EFFD 0845  02B8 5CCE C7E1 6814 A36E
Signing key: B54F 5682 F28D BA36 22D7  8E04 58DB FADB BBAC 1BB1
Created:     2025-03-29
Expires:     2030-03-28
Key type:    ed25519 (primary, SC)
Subkeys:     ed25519 (S), ed25519 (A), cv25519 (E)
```

<br>

<details>

<summary>🎯 Where to Find Release Signatures</summary>

PyPI does *Not* host .asc Signature Files

Although the `dar-backup` packages on PyPI are GPG-signed, PyPI itself does **not support uploading** .asc detached signature files alongside `.whl` and `.tar.gz` artifacts.

Therefore, you will not find `.asc` files on PyPI.

**Where to Get `.asc` Signature Files**

You can always download the signed release artifacts and their `.asc` files from the official GitHub Releases page:

📁 GitHub Releases for `dar-backup`

Each release includes:

- `dar_backup-x.y.z.tar.gz`

- `dar_backup-x.y.z.tar.gz.asc`

- `dar_backup-x.y.z-py3-none-any.whl`

- `dar_backup-x.y.z-py3-none-any.whl.asc`

</details>

<br>

<details>

<summary>🎯 How to Verify a Release from GitHub</summary>

1. Import the GPG public key:

   ```bash
   curl https://keys.openpgp.org/vks/v1/by-fingerprint/4592D7396DBAEFFD084502B85CCEC7E16814A36E | gpg --import
   ```

2. Download the wheel or tarball and its .asc signature from the GitHub.

3. Run GPG to verify it:

   ```bash
   gpg --verify dar_backup-x.y.z.tar.gz.asc dar_backup-x.y.z.tar.gz
   # or
   gpg --verify dar_backup-x.y.z-py3-none-any.whl.asc dar_backup-x.y.z-py3-none-any.whl
   ```

4. If the signature is valid, you'll see:

   ```text
   gpg: Good signature from "Per Jensen (author of dar-backup) <dar-backup@pm.me>"
   ```

🛡️ Reminder: Verify the signing subkey

Only this subkey is used to sign PyPI packages:

```text
B54F 5682 F28D BA36 22D7  8E04 58DB FADB BBAC 1BB1
```

You can view it with:

```bash
gpg --list-keys --with-subkey-fingerprints dar-backup@pm.me
```

</details>

</details>

---

## License

  These scripts are licensed under the GPLv3 license.
  Read more here: [GNU  GPL3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), or have a look at the ["LICENSE"](LICENSE) file in this repository.

## Requirements

- A linux system
- dar
- parchive (par2)
- python3
- python3-venv

On Ubuntu, install the requirements this way:

```bash
    sudo apt install dar par2 python3 python3-venv
```

## Homepage - Github

'dar-backup' package lives here: [Github - dar-backup](https://github.com/per2jensen/dar-backup/tree/main/v2)

## Community

Please review the [Code of Conduct](CODE_OF_CONDUCT.md) to help keep this project welcoming and focused.

## Projects these scripts benefit from

 1. [The wonderful dar achiver](https://github.com/Edrusb/DAR)
 2. [The Parchive suite](https://github.com/Parchive)
 3. [shellcheck - a bash linter](https://github.com/koalaman/shellcheck)
 4. [Ubuntu of course :-)](https://ubuntu.com/)
 5. [PyPI](https://pypi.org/)

<!-- markdownlint-enable MD024 -->
