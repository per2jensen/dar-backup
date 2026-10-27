# Fresh Linux VM compatibility tests

This runner creates disposable Multipass VMs for Ubuntu 24.04, Ubuntu 26.04,
and Fedora 44, installs dar-backup's system and Python dependencies, and runs
the committed application source and tests from the same immutable Git
revision.

The matrix is declarative. Each entry identifies its distribution, expected
Multipass catalogue release, required `os-release` identity, and allow-listed
provisioner. This is particularly important for Multipass's unversioned
`fedora` alias: the controller refuses to launch tests unless it still resolves
to Fedora 44, then validates `ID=fedora` and `VERSION_ID=44` in the guest.

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

Full runs also generate one deterministic restore-test corpus on the dedicated
SSD and stream the identical tar archive into every VM. The corpus contains
1,000 files between 5 KiB and 5 MiB (approximately 2.5 GB in total). Each VM
verifies the transfer digest, extracts the corpus onto its native filesystem,
and independently creates a 500 MB-sliced archive through `dar-backup`. That
VM-local archive is then checked once with 10% percentage sampling and once
with 1% sampling plus complete data-slice coverage. The multi-gigabyte corpus
and DAR slices remain disposable; compact dataset and restore evidence is
retained with the normal guest results. Successful runs remove the staged host
corpus, while failed runs retain it for diagnosis.

Each matrix guest uses a 40 GB virtual disk. After successful extraction, the
guest removes the transferred source and dataset tar archives, installs Python
dependencies without a persistent pip cache, and records filesystem, inode,
mount, and available quota diagnostics before pytest starts. Pytest base
directories, application temporary files, and parallel coverage databases use
a fresh guarded directory below the disk-backed guest work directory. They do
not use `/tmp`, which is a size-limited tmpfs on some matrix distributions.

After an initialized run, the controller appends one public, schema-versioned
record to the tracked evidence file:

```text
v2/doc/test-report/vm-matrix-results.jsonl
```

For a full matrix, the controller also regenerates the marker-delimited Linux
VM table in the root `README.md` and the Shields endpoint data in
`v2/doc/test-report/vm-matrix-badge.json`. Failed full runs replace a previous
green status; fast, smoke, and integration runs do not replace the published
full-suite result. The badge changes on GitHub after these generated files are
committed and pushed.

These updates intentionally make the checkout dirty after testing. Review and
commit the history, README, and badge together to publish the compatibility
evidence on GitHub.

Each schema-v5 record contains all VM outcomes, source commits, the installed
dar-backup version, tool versions,
the Multipass image alias and release, the full SHA-256 of the exact source
image used to create each VM, package manager and manifest format, a complete
installed package manifest, and its canonical SHA-256. Debian manifests retain
the schema-v2 package-and-architecture mapping. Fedora manifests contain
deterministically ordered RPM name, epoch, version, release, and architecture
records. Schema-v2, schema-v3, and schema-v4 historical records remain readable;
older records without application-version evidence display `not recorded`.

Fedora's standard `/run/lock` remains root-owned and mode `0755`; the VM runner
does not alter it. Unprivileged backup processes use dar-backup's deterministic
private lock directory below their registered home, while SELinux remains
enabled and no test is skipped because of the distribution. Schema-v5 evidence
records the actual SELinux availability, runtime mode, and loaded policy, plus
AppArmor availability, mode, current process label, status-tool availability,
and profile counts. Fedora requires enforcing SELinux and records the complete
AppArmor section as unavailable. The Ubuntu images require SELinux to be
unavailable and AppArmor to be enabled. A host with neither system records both
sections explicitly as unavailable. These mutually exclusive expectations are
validated without installing packages, adding profiles, or changing native OS
security policy. Raw status and current-label output is retained in each run's
private `security/` result directory for diagnosis.

Evidence also includes pytest counts and duration, the sorted pytest node ID
and reason for every skipped test, compact pytest failure/error details, and a
structured mypy summary. The mypy evidence records its exact version, target,
effective enabled error codes, strictness options, per-module overrides,
configuration digest, exit status, and diagnostic counts. Image and manifest
digests must be complete 64-character SHA-256 values. Pytest counts, package
manifests, and mypy summaries are cross-validated so
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
--refresh-presentation regenerate README and badge from the latest tracked full run
```

Presentation-only refresh does not launch Multipass or require the SSD:

```bash
python3 v2/vm_test/run_vm_matrix.py --refresh-presentation
```

Results are written below:

```text
/mnt/vm-work/dar-backup-vm-tests/results/<UTC-time>-<commit>/
```

The controller exits `0` when every image passes, `1` for pytest/mypy
failures, and `2` for provisioning, VM, transfer, or result-contract errors.
Guest console output, pytest text/JSON/JUnit reports, collection inventory,
coverage, the complete structured mypy diagnostics, the raw distribution
package manifest, tool versions, and host controller logs are retained for
diagnosis.
Restore-test compatibility artifacts are retained under each guest result's
`restoretest-catalog/` directory: DAR version output, raw XML, raw slicing
stdout/stderr, positional Data/EA/FSA row evidence, the parsed reconciliation
mapping, selected-file extraction and comparison states, exact
predicted/extracted/verified slice sets, and DAR command output from extraction.
A successful multi-image full matrix is rejected unless
its recorded DAR versions explicitly include both the 2.7 and 2.8 branches.
Each SSD run directory also contains `vm-matrix-result.json`, the exact
public-safe object appended to the tracked JSONL history. Evidence is written
with an exclusive file lock, flushed, and synchronized before the controller
returns. A malformed existing history or failed durable append is an
infrastructure failure; the SSD artifacts are preserved for recovery.
