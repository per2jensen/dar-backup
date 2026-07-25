# Restoring

Back to [README](../../README.md)

This is the operator entry point for restores. Use a dedicated restore target,
check the command before running it, and verify the restored data before using
it.

## Choose the restore method

| What you need | Use |
| --- | --- |
| Filesystem state captured by the latest backup on or before a point in time | PITR with `manager --restore-path` and `--when` |
| Everything, or selected entries, from one named archive | Direct archive restore with `dar-backup --restore` |
| A file version selected by its recorded modification time | Manual `dar_manager -w` |
| Low-level DAR inspection, FSA handling, or complex selection expressions | Advanced restore procedures |

PITR selects by **archive creation date**, not file mtime. See
[PITR restore details](restoring-pitr.md) for its complete behavior, archive
chain selection, timezones, and damaged-archive recovery.

Manual and specialized procedures are documented in
[Advanced restore procedures](restoring-advanced.md). Commands that invoke
`dar` or `dar_manager` directly do not receive dar-backup's target-safety
checks.

## Restore-target safety

In a recovery situation, prefer a new private directory under `/tmp`. Do not
repair permissions on a live system directory merely to make a safety check
pass. A new target is easier to reason about and preserves the failed target
for diagnosis.

### Prepare a target

For a restore as your current, non-root user:

```bash
set -euo pipefail

restore_target="/tmp/dar-restore-$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 -- "${restore_target}"
find "${restore_target}" -mindepth 1 -maxdepth 1 -print
test -d /proc/self/fd
```

The `find` command should print nothing. Use this new path as `--target` or
`--restore-dir`.

For a restore that must run as root:

```bash
set -euo pipefail

restore_target="/tmp/dar-root-restore-$(date +%Y%m%d-%H%M%S)"
sudo install -d -o root -g root -m 0700 -- "${restore_target}"
sudo stat -c 'owner=%U group=%G mode=%a path=%n' -- "${restore_target}"
sudo getfacl -p -- "${restore_target}"
test -d /proc/self/fd
```

The target must be owned by a trusted UID, must not be writable by other
users, and must not have an extended POSIX ACL. Group write is accepted only
when NSS proves that the directory owner is the group's sole member.
`getfacl` may need to be installed separately. For selected-path PITR into an
existing tree, inspect the existing directory components too:

```bash
namei -l -- "/path/to/target/path/to/item"
getfacl -p -- "/path/to/target" "/path/to/target/path" "/path/to/target/path/to"
```

Create a new private target if any ownership or access rule is unclear. Do not
blindly run recursive `chown`, `chmod`, or `setfacl` against an existing or
live system tree; those commands can damage the very system being recovered.

### Know which existing data is permitted

dar-backup fails closed when a target does not satisfy the policy for the
requested operation:

| Restore operation | Existing-data policy | Protected directories |
| --- | --- | --- |
| PITR of specific paths | Requested paths must not already exist | Rejected |
| PITR archive root (`--restore-path .`) | Entire target must be empty | Rejected |
| Direct archive restore | Entire target must be empty | Rejected |
| Direct or PITR with `--overwrite-restore-target` | Existing data may be changed after a whole-target safety preflight | Rejected |
| Manual `dar` or `dar_manager` command | No dar-backup protection | No dar-backup protection |

For direct restores and PITR of `.`, use an entirely empty target. Hidden
files, directories, and dangling symlinks all make it nonempty. For PITR of
specific paths, unrelated existing data is permitted, but none of the selected
paths may already exist.

`--overwrite-restore-target` permits existing data to be modified, but it does
not bypass protected-directory checks. In particular, restoring directly into
`/etc` is still not possible through dar-backup, even when its permissions are
safe. Restore into a private temporary directory, verify the result, and copy
the required files into place using the normal system recovery procedure.

Root has a last-resort `--force-unsafe-restore-target` option for understood
overwrite-preflight policy findings. It does not disable structural
protections or permit `/etc`; read the
[break-glass runbook](restoring-advanced.md#root-only-break-glass-override)
before an incident.

### Plan disk space and final placement

dar-backup currently extracts directly into the path supplied with `--target`
or `--restore-dir`. It does not automatically move or publish that directory
afterward. If your recovery procedure is “restore to staging, verify, then
move the completed tree into place,” the staging location is an operator
choice and must be planned before extraction starts.

For a fast rename, the staging directory and final destination must be on the
same **mounted filesystem**. Being on the same physical disk is not enough:
separate filesystems or mount points on that disk can still make `rename()`
fail with `EXDEV`. A cross-filesystem `mv` normally becomes copy-then-delete;
it is not an atomic publication and it needs space on the destination
filesystem for the copied tree.

Do not assume `/tmp` is on the correct filesystem. Check the proposed staging
parent and final parent first:

```bash
set -euo pipefail

staging_parent="/var/tmp"
final_parent="/path/to/final-parent"

findmnt --target "${staging_parent}"
findmnt --target "${final_parent}"
stat -c 'device=%d path=%n' -- "${staging_parent}" "${final_parent}"
df -h -- "${staging_parent}" "${final_parent}"
```

The `findmnt` output should identify the same mounted filesystem, and the
`stat` device numbers should match. If they do not, do not rely on `mv` being
an atomic rename. Choose a different staging location or deliberately plan
for a verified copy.

Staged publication temporarily requires enough capacity for:

1. The complete existing destination tree, if one is already present.
2. The complete restored staging tree.
3. Filesystem metadata and operational headroom.

The compressed archive size is not a safe estimate of restored space. Check
available capacity before starting and monitor it during a large recovery.
Running out of space leaves a partial staging tree; treat the restore as
failed and retry in a new target after resolving capacity.

If the final destination does not exist, one same-filesystem rename can
publish the staged tree atomically. Replacing an existing nonempty directory
usually requires first renaming the old tree aside and then renaming the
staged tree into place. Each rename is atomic, but the two-step sequence as a
whole is not: there is a short interval in which the final pathname is absent.
Stop services and other users of the destination before performing that
switch, and retain the old tree until the restored system has been verified.

#### When there is not enough room for staging

`--overwrite-restore-target` is available for recoveries where the filesystem
cannot hold a second complete tree. It restores in place instead of requiring
a complete staged copy, so it can substantially reduce peak space usage.

In-place overwrite trades disk space for recovery risk:

- Publication is not atomic and there is no simple whole-tree rollback.
- An error, interruption, or full filesystem can leave a mixture of old and
  restored state.
- New files and file growth still require free space.
- Deletions recorded by DIFF/INCR archives can alter the live tree.
- Services, deployment agents, cleanup jobs, and other writers must be
  stopped before the restore.
- Descriptor binding, selected-path symlink rejection, access-policy checks,
  and protected-directory policy still apply. Overwrite permission must not
  disable them.

The planned `--disregard-protected-dirs` option is a separate decision: it
controls *where* restoration is permitted, while
`--overwrite-restore-target` controls *whether existing data may be
replaced*. A low-space restore into a protected location such as `/etc` would
require both policies and should normally be performed from rescue or
single-user mode with a verified backup and recovery path. Until protected
target support is implemented, use a staged restore or the documented manual
advanced procedures.

Do not add this option merely to get past a nonempty-target error. Before an
incident, read and test the complete
[in-place overwrite runbook](restoring-advanced.md#in-place-overwrite-restores).
It documents the preflight ownership/access rules, home-directory examples,
deletion behavior, capacity limits, and failure recovery.

### What the target protections mean

- Protected destinations include `/`, `/etc`, `/usr`, `/bin`, `/sbin`,
  `/var`, `/root`, `/boot`, `/lib`, `/proc`, `/sys`, and `/dev`, including
  paths below them. `/tmp`, `/var/tmp`, and `/home` are permitted restore
  locations.
- Target paths are resolved before the protected-directory check. A target
  symlink pointing to `/root`, `/sbin`, or another protected destination is
  rejected.
- For selected-path PITR, existing symlinks in the path below the target are
  rejected, including dangling symlinks. This prevents a restore from being
  redirected outside the target.
- The validated target directory is opened once and DAR restores through that
  inherited directory descriptor. Replacing the requested pathname or one of
  its parent directories after validation cannot redirect extraction to a
  different directory.
- Do not rename, remove, or repoint the target while a restore is running. If
  the pathname is replaced after it is opened, DAR remains bound to the
  originally opened directory. Restored data may therefore be under the
  directory's new name rather than the pathname shown in the original command,
  but it will not be written through the replacement symlink.
- The opened target is locked cooperatively while it is checked and while DAR
  runs. A concurrent dar-backup restore to the same target is rejected.
- During an overwrite preflight, every directory must have a trusted owner,
  no other-write bit, and no extended POSIX ACL. A group-write bit is accepted
  only when an immutable NSS snapshot resolves that group to exactly the
  directory owner's UID. Existing directory components traversed by
  selected-path PITR receive the same protection.
- Safe descriptor-bound extraction requires Linux `/proc/self/fd` support.
  dar-backup fails closed if that interface is unavailable.
- These checks do not protect against a malicious process running as the same
  trusted identity, especially another root process. Stop deployment agents,
  cleanup jobs, and other writers that can alter the target during recovery.
- A failed or interrupted extraction may leave a partial target. Do not reuse
  it. Preserve it for diagnosis and retry into a new clean target.

### If dar-backup refuses the target

| Message mentions | Meaning | Safest response |
| --- | --- | --- |
| protected system directory | The requested target is `/`, a protected directory, or below one | Use a new private target under `/tmp`; direct protected-target restore is not currently enabled |
| target is not empty | This operation can write anywhere below the target | Keep the existing directory unchanged and retry with a new empty target |
| already contains path(s) to restore | A selected PITR path would overwrite existing data | Retry with a new target, or select a different non-overlapping path |
| is a symlink | An existing component could redirect extraction | Do not follow or replace it during the incident; use a clean target and investigate the symlink |
| owned by another uid | A privileged restore does not have exclusive control | Create a new root-owned target; do not recursively change ownership on a live tree |
| group-writable through a group with another, missing, or unresolved member | The preflight cannot prove that group write is limited to the owner | Inspect `id`, `getent passwd`, and `getent group`; prefer a new target and do not recursively chmod a live tree |
| writable by other users | The other-write bit lets any local identity change paths | Create a new private target and stop other writers |
| extended POSIX ACL | Additional identities may have access not visible in the mode bits | Prefer a new target; remove an ACL only after reviewing why it exists |
| changed while it was being opened | Another process replaced or renamed the target during validation | Stop and investigate concurrent writers; do not immediately retry against the same path |
| `/proc/self/fd` unavailable | DAR cannot be safely tied to the opened target | Ensure Linux procfs is mounted or correctly exposed in the recovery container; do not bypass the check |
| locked by a concurrent restore | Another dar-backup restore holds the cooperative lock | Confirm whether that restore is active; wait for it or terminate it deliberately before retrying |

Treat any non-zero exit status as a failed restore. Read the first target-safety
error, correct that condition using a new target where possible, then rerun the
same restore command. Never add a broad permission change merely to silence
the error.

## Point-in-Time Recovery quick start

Activate the virtual environment and restore a relative catalog path:

```bash
. <the virtual env>/bin/activate
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path path/to/file.txt \
  --when "2026-01-29 15:00:39" \
  --target /tmp/restore-pitr \
  --log-stdout --verbose
deactivate
```

Restore a directory by making the directory intent explicit with a trailing
slash:

```bash
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path path/to/directory/ \
  --when "2026-01-29 15:00:39" \
  --target /tmp/restore-pitr \
  --log-stdout --verbose
```

Restore multiple paths by passing them after one `--restore-path`:

```bash
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path path/to/data media/photos media/film \
  --when "2025-12-31 23:59:59" \
  --target /tmp/restore-pitr \
  --log-stdout --verbose
```

Select the complete archive tree with `.`. Because this can write anywhere
below the destination, the target must be completely empty:

```bash
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path . \
  --when "2025-12-31 23:59:59" \
  --target /tmp/restore-pitr-empty \
  --log-stdout --verbose
```

Preview and validate the selected archive chain without extracting:

```bash
manager --config-file <dar-backup.conf> \
  --backup-def <definition> \
  --restore-path path/to/directory/ \
  --when "2026-01-29 15:00:39" \
  --pitr-report \
  --log-stdout --verbose
```

Add `--pitr-report-first` to a restore command to run that preflight before
extraction. Continue with [PITR restore details](restoring-pitr.md) before a
disaster-recovery operation or when restoring across a FULL → DIFF → INCR
chain.

## Direct archive restore quick start

Restore one named archive into an explicitly chosen empty directory:

```bash
. <the virtual env>/bin/activate
dar-backup --restore <archive-name> \
  --restore-dir /tmp/archive-restore-empty \
  --log-stdout --verbose
deactivate
```

When `--restore-dir` is omitted, dar-backup uses the configured
`TEST_RESTORE_DIR` and cleans it before the direct restore. An explicitly
supplied directory is never cleaned automatically and must already be empty.

If the archive was created with:

```text
-R /
-g home/user/Documents
```

then restoring with `--restore-dir /tmp/archive-restore-empty` places the files
under `/tmp/archive-restore-empty/home/user/Documents`.

Restore one file or directory from the archive:

```bash
dar-backup --restore <archive-name> \
  --restore-dir /tmp/archive-restore-empty \
  --selection="-g path/to/file" \
  --log-stdout --verbose
```

```bash
dar-backup --restore <archive-name> \
  --restore-dir /tmp/archive-restore-empty \
  --selection="-g path/to/directory" \
  --log-stdout --verbose
```

`--selection` accepts DAR selection expressions, but it cannot contain options
that redirect the target, load batch options, or execute commands:
`-R`/`--fs-root`, `-B`/`--batch`, `-E`/`--execute`, and
`-F`/`--ref-execute` are rejected.

To inspect only the saved content of a DIFF or INCR archive, see
[Inspecting a DIFF or INCR archive](restoring-advanced.md#inspecting-a-diff-or-incr-archive).

## After the command

Treat a non-zero exit status as a failed restore. For a successful command:

1. Inspect the restored tree and confirm the expected paths are present.
2. Compare critical files with known checksums or another trusted source.
3. Preserve the original archive and catalog until verification is complete.
4. Move data into its final location only after verification.

For archive damage, catalog relocation, historical timezones, deletion states,
and PITR chain behavior, continue with
[PITR restore details](restoring-pitr.md).
