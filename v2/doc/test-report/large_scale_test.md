
# Large scale test run

This file documents runs of `[v2/scripts/large_scale_test.sh](https://github.com/per2jensen/dar-backup/blob/main/v2/scripts/large_scale_test.sh)`.

The summary shows size of FULL and DIFF + max memory consumption of various programs.

## 2026-06-10

Git commit: c5e4e76

```text
══════════════════════════════════════════
  Phase 3 — Point-In-Time Restore Validation
══════════════════════════════════════════
  INFO  Cleaning restore target directory to satisfy manager safety checks...
  INFO  Invoking manager to process PITR extraction for diff-primer data...
  PASS  Restore sequence completed execution via manager
  PASS  Hard Link Inodes match (1003517)

══════════════════════════════════════════
  Summary
══════════════════════════════════════════
dar-backup test pass: 2026-06-10_19-37-43
FULL elapsed: 4180s (~116.23 GB)
DIFF elapsed: 5s (~0.29 GB)
Peak Engine Memory Consumption:
  ├── dar-backup : 30.1 MB
  ├── dar backend: 26.5 MB
  ├── par2 engine: 147.0 MB
  └── db manager : 37.1 MB
Failures:      0

✓ ALL TESTS PASSED SUCCESSFULLY
```

## 2026-06-09

Git commit: 37227c7

```text
══════════════════════════════════════════
  Summary
══════════════════════════════════════════
dar-backup test pass: 2026-06-09_16-10-04
FULL elapsed: 3742s (~116.23 GB)
DIFF elapsed: 5s (~0.29 GB)
Peak Engine Memory Consumption:
  ├── dar-backup : 33.8 MB
  ├── dar backend: 26.5 MB
  ├── par2 engine: 146.9 MB
  └── db manager : 37.1 MB
Failures:      0

✓ ALL TESTS PASSED SUCCESSFULLY
```

