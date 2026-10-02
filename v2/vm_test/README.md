# Fresh Ubuntu VM compatibility tests

This runner creates disposable Multipass VMs for Ubuntu 24.04 and 26.04,
installs dar-backup's system and Python dependencies, and runs the committed
application source and tests from the same immutable Git revision.

VM disks, downloaded Multipass images, source staging, and test reports are
kept on a dedicated SSD. The controller refuses to run unless the configured
SSD root is itself a mounted filesystem on a different device from `/`. It
also verifies that the effective systemd `MULTIPASS_STORAGE` value points to
the root-owned `multipass` directory on that same filesystem.

## One-time SSD and Multipass configuration

Mount the SSD persistently at `/mnt/vm-work` by filesystem UUID. Multipass is
a confined snap, so grant its daemon access to mounts below `/mnt`:

```bash
sudo snap connect multipass:removable-media
```

The Multipass snap does not grant `removable-media` to its command-line app,
even though the daemon uses it for `MULTIPASS_STORAGE`. The controller
therefore opens staged inputs and retrieved report files itself, transferring
their bytes via Multipass standard input/output. This keeps the files on the
SSD without requiring the confined CLI to open paths below `/mnt`.

Stop Multipass and create
`/etc/systemd/system/snap.multipass.multipassd.service.d/override.conf`:

```ini
[Unit]
RequiresMountsFor=/mnt/vm-work

[Service]
Environment=MULTIPASS_STORAGE=/mnt/vm-work/multipass
```

Create `/mnt/vm-work/multipass` as documented by Multipass, reload systemd,
and restart the snap. `MULTIPASS_STORAGE` is global: migrate any existing
instances according to the Multipass documentation or remove disposable
instances before changing it.

## Run the matrix

The checkout must be clean because `git archive` supplies both application
source and tests to each guest from `HEAD`:

```bash
python3 v2/vm_test/run_vm_matrix.py --mode full
```

After an initialized run, the controller appends one public, schema-versioned
record to the tracked evidence file:

```text
v2/doc/test-report/vm-matrix-results.jsonl
```

The append intentionally makes the checkout dirty after testing. Review and
commit that line to publish the compatibility evidence on GitHub. Each
schema-v2 record contains both VM outcomes, source commits, tool versions,
the Multipass image alias and release, the full SHA-256 of the exact source
image used to create each VM, a complete installed Debian package manifest and
its canonical SHA-256, pytest counts and duration, the sorted pytest node ID
and reason for every skipped test, compact pytest failure/error details, and a
structured mypy summary. The mypy evidence records its exact version, target,
effective enabled error codes, strictness options, per-module overrides,
configuration digest, exit status, and diagnostic counts. Image and manifest
digests must be complete 64-character SHA-256 values. Pytest counts, the
package manifest, and mypy summaries are cross-validated so
environment-specific differences cannot be silently omitted.
Hostnames, usernames, instance names, and absolute local paths are excluded so
the file is safe to publish and consume from a future README badge generator.

The generated `v2/README.md` is intentionally ignored by Git. After extracting
the immutable archive, each guest mirrors the normal build workflow by copying
the committed root `README.md` into `v2/README.md` before package installation.

Useful options:

```text
--ssd-root PATH      SSD mount point (default: /mnt/vm-work)
--minimum-free-gib N fail below this free-space threshold (default: 40)
--keep-failed        retain failed VMs for interactive diagnosis
--keep-all           retain every VM
--mode MODE          fast, smoke, integration, or full
--evidence-jsonl PATH tracked evidence path (default: v2/doc/test-report/vm-matrix-results.jsonl)
```

Results are written below:

```text
/mnt/vm-work/dar-backup-vm-tests/results/<UTC-time>-<commit>/
```

The controller exits `0` when every image passes, `1` for pytest/mypy
failures, and `2` for provisioning, VM, transfer, or result-contract errors.
Guest console output, pytest text/JSON/JUnit reports, collection inventory,
coverage, the complete structured mypy diagnostics, the raw Debian package
manifest, tool versions, and host controller logs are retained for diagnosis.
Each SSD run directory also contains `vm-matrix-result.json`, the exact
public-safe object appended to the tracked JSONL history. Evidence is written
with an exclusive file lock, flushed, and synchronized before the controller
returns. A malformed existing history or failed durable append is an
infrastructure failure; the SSD artifacts are preserved for recovery.
