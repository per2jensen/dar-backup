# My Use Case and Setup

This document describes the author's personal use case, setup, and design rationale behind `dar-backup`.
For the project's general documentation, see the [README](../../README.md).

---

## My use case

I needed the following:

- Backup my workstation to a remote server
- Backup primarily photos, home made video and different types of documents
- I have cloud storage mounted on a directory within my home dir. The filesystem is [FUSE based](https://www.kernel.org/doc/html/latest/filesystems/fuse.html), which gives it a few special features
  - Backup my cloud storage (cloud is convenient, but I want control over my backups)
  - A non-privileged user can perform a mount
  - A privileged user cannot look into the filesystem --> a backup script running as root is not suitable

- Have a simple way of restoring, possibly years into the future. `dar` fits that scenario
  particularly well: the restore tool can be preserved with the archives, reducing dependence on
  the original machine or package repositories.
- During backup archives must be tested and a restore test (however small) performed
- Archives stored on a server with a reliable file system (easy to mount a directory over sshfs)
- Easy to verify archive's integrity, after being moved around.

I do not need the encryption features of dar, as all storage is already encrypted.

---

## My setup

1. Primary backup to server with an ext4 file system on mdadm RAID1

2. Secondary copies to multiple USB disks / cloud

3. Archive integrity verification anywhere using [Par2](../../v2/doc/par2.md) and `dar -t`.

4. Archive repair anywhere if needed. By default `dar-backup` creates par2 redundancy files with 5% coverage. Enough to fix localized bitrot.

5. No dependency on original system

6. Docker image archived alongside the dar archives

   The [dar-backup Docker image](https://github.com/per2jensen/dar-backup-image)
   packages `dar-backup`, `dar`, and `par2` in a self-contained environment — a time
   capsule of the exact tools needed to restore your archives, years from now, without
   hunting for the right versions or fighting package managers.

   A small helper script,

   [`save-dar-backup-image.sh`](https://github.com/per2jensen/dar-backup-image/blob/main/scripts/save-dar-backup-image.sh),
   checks the latest released image against
   [`build-history.json`](https://github.com/per2jensen/dar-backup-image/blob/main/doc/build-history.json)
   and saves it as a compressed tar alongside the dar archives on the backup server.
   Run it as a cron job or systemd timer — it is idempotent and only pulls when a new
   image is available.

   ```bash
   # Example: run daily via cron
   DOCKER_ARCHIVE_DIR=/mnt/dar/docker-archives ~/.local/bin/save-dar-backup-image.sh
   ```

   The result: my `rsync` to USB disks on the storage server picks up the Docker image automatically, so the
   restore environment travels with the archives onto every offsite copy.

   This is intentionally treated as part of the backup set rather than as a convenience download.
   The long-term goal is that a future restore can begin with the preserved artifacts themselves,
   without first reconstructing today's software environment from the Internet.

   A useful preservation practice is to periodically perform a **cold recovery drill**: restore
   using only the archive set, PAR2 files, catalogs, saved documentation, and preserved restore
   image. That tests the preservation system rather than merely the current installation.

---

### Why PAR2 is especially good for portable / offsite copies

PAR2 parity is:

> Self-contained (travels with the data)
>
> Format-agnostic (works on any filesystem)
>
> Location-agnostic (local disk, USB, cloud object storage)
>
> Tool-stable (PAR2 spec has not changed in years)
>
> That means:
>
> **Integrity protection moves with the archive**.

---

### Design choices

My design choices are deliberately simple, proven, and pragmatic:

- mdadm handles disks
- PAR2 handles data integrity
- You control when and how verification happens
- Errors have a fair chance of being diagnosed and fixed, due to well known tooling
- No hidden magic, no lock-in
