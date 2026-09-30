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
a confined snap, so grant access to mounts below `/mnt`:

```bash
sudo snap connect multipass:removable-media
```

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

Useful options:

```text
--ssd-root PATH      SSD mount point (default: /mnt/vm-work)
--minimum-free-gib N fail below this free-space threshold (default: 40)
--keep-failed        retain failed VMs for interactive diagnosis
--keep-all           retain every VM
--mode MODE          fast, smoke, integration, or full
```

Results are written below:

```text
/mnt/vm-work/dar-backup-vm-tests/results/<UTC-time>-<commit>/
```

The controller exits `0` when every image passes, `1` for pytest/mypy
failures, and `2` for provisioning, VM, transfer, or result-contract errors.
Guest console output, pytest text/JSON/JUnit reports, collection inventory,
coverage, tool versions, and host controller logs are retained for diagnosis.
