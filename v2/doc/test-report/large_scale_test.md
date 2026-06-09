
# Large scale test run

This file documents runs of `[v2/scripts/large_scale_test.sh](https://github.com/per2jensen/dar-backup/blob/main/v2/scripts/large_scale_test.sh)`.

The summary shows size of FULL and DIFF + max memory consumption of various programs.

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
