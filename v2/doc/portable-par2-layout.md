## Creating portable PAR2 files (layout matters)

This example shows how to generate PAR2 files **away from the DAR archives** while keeping them **fully portable** across disks, mount points, and locations.

The key requirement is that **directory layout must be preserved**.  
Mount points may change — directory structure must not.

---

### Directory layout (canonical)

Choose a logical root that will exist on *all* disks:

```
/mnt/
├── backups/
│   └── årsbackups/
│       ├── 2025_FULL_*.dar
│       ├── 2025_DIFF_*.dar
│       └── 2025_INCR_*.dar
└── par2/
```

- `/mnt/backups` contains the DAR archives
- `/mnt/par2` contains the generated PAR2 files
- Both directories may later be moved together to another disk
- **The relative layout under `/mnt/` must remain identical**

---

### Creating PAR2 files (portable)

Use `par2 create` with `-B` pointing to the **logical root**, not the mount point:

```bash
par2 create \
  -B /mnt \
  -r10 \
  /mnt/par2/2025.par2 \
  /mnt/backups/årsbackups/*.dar
```

What this does:

- PAR2 reads files using full paths (safe and explicit)
- `-B /mnt` strips the mount prefix from filenames stored *inside* the PAR2 metadata
- Stored paths become:

  ```bash
  backups/årsbackups/2025_FULL_*.dar
  ```

- The PAR2 file itself can live anywhere (`/mnt/par2` here)

---

### Moving to another disk (important)

On a second disk, you may mount the data anywhere:

```bash
/some/other/mount/
├── backups/
│   └── årsbackups/
└── par2/
```

As long as the **relative layout is identical**, everything works.

---

### Verifying on the second disk

Run verification from the logical root:

```bash
cd /some/other/mount
par2 verify par2/2025.par2
```

or equivalently:

```bash
par2 verify /some/other/mount/par2/2025.par2
```

PAR2 will correctly locate:

```
backups/årsbackups/*.dar
```

regardless of where the disk is mounted.

---

### Repairing (same invariant)

If repair is needed, use the same layout:

```bash
cd /some/other/mount
par2 repair par2/2025.par2
```

---

### Critical rules (do not skip)

- Always use `-B` to strip the mount point
- Keep archive and PAR2 directories under a shared logical root
- Preserve directory layout when moving data
- Do **not** embed absolute mount paths in PAR2 metadata
- Do **not** change directory structure between disks

---

### Summary

If you can say:

> “On any disk, `par2 verify par2/2025.par2` works from the root”

then your layout is correct.

This guarantees **portable, future-proof verification and repair**, even years later and on different machines.
