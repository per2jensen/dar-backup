# PAR2 Redundancy

Back to [README](../../README.md)

## Why PAR2?

Why keep PAR2 on a different storage device:

- Reduces single-disk failure impact: bitrot on the archive disk does not affect the parity.
- Easier offsite rotation: you can sync only the PAR2 sets to a different failure domain.

Redundancy guidance:

- FULL backups: 10% is a practical default for larger data sets and longer retention.
- DIFF/INCR: 5% is often enough because the delta is smaller and easier to re-create.
- Increase the ratio if the storage is flaky or the backup is hard to re-run.

Rule of thumb table:

| Backup type | Suggested PAR2 ratio | Notes |
|-------------|----------------------|-------|
| FULL        | 10%                  | Longer retention, larger data set |
| DIFF        | 5%                   | Smaller delta |
| INCR        | 5%                   | Smaller delta |

>
>For large, contiguous archives on reliable local storage, 7–8% has proven sufficient in practice; 10% remains a conservative default.
>

Cloud sync / air-gap note:

- Syncing PAR2 sets to a different device or remote store protects against bitrot and small corruption, but it cannot recover a completely lost archive.
- An air-gapped PAR2 store is useful when the archive disk is exposed to ransomware or accidental deletion.

## PAR2 verify/repair

### PAR2 files kept with archives

If PAR2 files are stored next to the archives (legacy per-slice behavior), you can verify like this:

```bash
for file in <archive>*.dar.par2; do
  par2 verify "$file"
done
```

if there are problems with a slice, try to repair it like this:

```bash
  par2 repair <archive>.<slice number>.dar.par2
```

### PAR2 files in separate directory

See [docs on disk layout matters](portable-par2-layout.md)

>Test case proving this flow:
>
>[tests/test_par2_manifest.py](../tests/test_par2_manifest.py)

## PAR2 create redundancy files

If you have merged archives, you will need to create the .par2 redundency files manually.
Here is an example

```bash
for file in <some-archive>_FULL_yyyy-mm-dd.*; do
  par2 c -r5 -n1 "$file"
done
```

where "c" is create, -r5 is 5% redundency and -n1 is 1 redundency file

If you want to create a single parity set for all slices in an archive:

```bash
par2 create -B <archive_dir> -r5 <par2_dir>/<archive_base>.par2 <archive_dir>/<archive_base>.*.dar
```

**OBSERVE** [docs on disk layout matters](portable-par2-layout.md)

## Performance tip

This [dar benchmark page](https://dar.sourceforge.io/doc/benchmark.html) has an interesting note on the slice size.

Slice size should be smaller than available RAM, apparently a large performance hit can be avoided keeping the par2 data in memory.
