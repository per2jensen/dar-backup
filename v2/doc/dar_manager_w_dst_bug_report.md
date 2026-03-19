# Bug Report: dar_manager -w date parsing ignores actual DST status

## Summary

`dar_manager -r -w <date>` fails to find files that are known to exist in the
database. The root cause is that `line_tools_convert_date()` hardcodes
`tm_isdst = 1` (DST active) when building the `struct tm` passed to
`mktime()`. During standard-time months this shifts the parsed timestamp
**one hour backward**, so every file whose stored date falls inside that
one-hour window appears to be "in the future" relative to the `-w` date and
is silently excluded.

## Affected versions

- dar 2.7.19 / dar_manager 1.9.0 (compiled from source)
- dar 2.7.13 / dar_manager 1.9.0 (Ubuntu 24.04 package)
- The same code exists on the master branch, so 2.8.x is also affected.

## Environment

- OS: Ubuntu 24.04 (Linux 6.17)
- Timezone: Europe/Copenhagen (CET, UTC+1 standard / CEST, UTC+2 DST)
- Date of testing: 2026-03-18 (standard time; EU DST begins 2026-03-29)

## Source location

File: `src/dar_suite/line_tools.cpp`, function `line_tools_convert_date()`,
approximately line 1165:

```cpp
scan(const tm & now)
{
    etat = init;
    when = now;
    when.tm_sec = when.tm_min = when.tm_hour = 0;
    when.tm_wday = 0;            // ignored by mktime
    when.tm_yday = 0;            // ignored by mktime
    when.tm_isdst = 1;           // <--- BUG: hardcodes DST as active
    tmp = 0;
};
```

Later (line 1329):

```cpp
tmp = scanner.get_struct();
when = mktime(&tmp);
```

## Root cause analysis

`mktime()` interprets `struct tm` fields as local time. The `tm_isdst` field
tells `mktime()` whether the caller asserts that DST is in effect:

| `tm_isdst` | Meaning |
|---|---|
| `-1` | Let `mktime()` determine DST status from the system timezone database |
| `0` | Caller asserts DST is **not** in effect |
| `1` | Caller asserts DST **is** in effect |

When `tm_isdst = 1` and the actual date falls in standard time, `mktime()`
trusts the caller and interprets the hour field as a DST hour. For CET/CEST
this means:

- **Intended interpretation:** `19:13:38 CET` (UTC+1) = `18:13:38 UTC`
- **Actual interpretation:** `19:13:38 CEST` (UTC+2) = `17:13:38 UTC`

The resulting `time_t` is **3600 seconds too early**.

In `data_tree::get_data()` the filter is:

```cpp
if(it->second.date >= max_seen_date
   && (date.is_null() || it->second.date <= date))
```

A file with stored date `18:13:37 UTC` fails the check
`18:13:37 <= 17:13:38` (false), so it is excluded. `get_data()` returns
`not_found`, and the user sees:

```
File not found in database: <path>
<path> did not exist before specified date and cannot be restored
```

## Reproduction

### Minimal shell reproduction

```bash
#!/bin/bash
# Run this during standard time (non-DST) in any timezone with DST.
# For CET: between last Sunday of October and last Sunday of March.

set -euo pipefail

WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT

mkdir -p "$WORKDIR"/{data,backup,db,restore}

# 1. Create a file
echo "hello" > "$WORKDIR/data/a.txt"
sleep 1

# 2. Record current time (will be used as -w argument)
W_DATE=$(date +"%Y/%m/%d-%H:%M:%S")
echo "Using -w date: $W_DATE"

# 3. Create a FULL backup
cat > "$WORKDIR/backup.def" <<EOF
-R /
-s 10G
-g ${WORKDIR#/}/data
EOF

dar -c "$WORKDIR/backup/full" -N -B "$WORKDIR/backup.def" -Q 2>/dev/null

# 4. Create database and add archive
dar_manager -C "$WORKDIR/db/test.dmd" 2>/dev/null
dar_manager -B "$WORKDIR/db/test.dmd" -A "$WORKDIR/backup/full" 2>/dev/null

# 5. Confirm file IS in the database with a date BEFORE $W_DATE
echo "=== File in database (should show date before $W_DATE) ==="
dar_manager -B "$WORKDIR/db/test.dmd" -f "${WORKDIR#/}/data/a.txt" 2>/dev/null

# 6. Attempt restore with -w — this should succeed but FAILS
echo "=== Attempting restore with -w $W_DATE ==="
dar_manager -B "$WORKDIR/db/test.dmd" \
    -w "$W_DATE" -v \
    -e "-R $WORKDIR/restore -wa -Q" \
    -r "${WORKDIR#/}/data/a.txt" 2>&1

echo "Exit code: $?"

# 7. Verify restore directory is empty (proving the bug)
echo "=== Restore directory contents (should have files, but is empty) ==="
find "$WORKDIR/restore" -type f 2>/dev/null || echo "(empty)"

# 8. For comparison: restore WITHOUT -w succeeds
echo "=== Restore WITHOUT -w (should succeed) ==="
dar_manager -B "$WORKDIR/db/test.dmd" \
    -e "-R $WORKDIR/restore -wa -Q" \
    -r "${WORKDIR#/}/data/a.txt" 2>&1
echo "Exit code: $?"
find "$WORKDIR/restore" -type f
```

**Expected output** (during standard time):

```
File not found in database: .../data/a.txt
.../data/a.txt did not exist before specified date and cannot be restored
```

**Expected behavior:** The file should be restored, since its mtime is before
the `-w` date.

### C program proving the mktime shift

```c
/* Compile: gcc -o mktime_dst_bug mktime_dst_bug.c
 * Run during standard time (non-DST) in any timezone with DST.
 *
 * Demonstrates that tm_isdst=1 during standard time shifts mktime()
 * output by one hour compared to tm_isdst=-1.
 */
#include <stdio.h>
#include <time.h>

int main(void) {
    struct tm when = {0};
    time_t with_dst, with_auto;

    /* Use a date known to be in standard time.
     * For CET: 2026-03-18 is before DST switch on 2026-03-29. */
    when.tm_year  = 2026 - 1900;
    when.tm_mon   = 3 - 1;   /* March */
    when.tm_mday  = 18;
    when.tm_hour  = 19;
    when.tm_min   = 13;
    when.tm_sec   = 38;

    /* dar's behavior: hardcode tm_isdst = 1 */
    when.tm_isdst = 1;
    with_dst = mktime(&when);
    printf("tm_isdst=1  (dar):    time_t=%ld  localtime=%s",
           (long)with_dst, ctime(&with_dst));

    /* Correct behavior: let mktime auto-detect */
    when.tm_year  = 2026 - 1900;
    when.tm_mon   = 3 - 1;
    when.tm_mday  = 18;
    when.tm_hour  = 19;
    when.tm_min   = 13;
    when.tm_sec   = 38;
    when.tm_isdst = -1;
    with_auto = mktime(&when);
    printf("tm_isdst=-1 (correct): time_t=%ld  localtime=%s",
           (long)with_auto, ctime(&with_auto));

    long diff = (long)(with_auto - with_dst);
    printf("\nDifference: %ld seconds", diff);
    if (diff != 0)
        printf(" *** BUG: %ld-second shift due to tm_isdst=1 ***\n", diff);
    else
        printf(" (no shift — DST is currently active, so bug is hidden)\n");

    /* Simulate dar_manager -w comparison */
    time_t file_mtime = with_auto - 1;  /* file saved 1 second before -w date */
    printf("\nSimulated dar_manager -w comparison:\n");
    printf("  file stored date:  %ld\n", (long)file_mtime);
    printf("  parsed -w date:    %ld  (with tm_isdst=1)\n", (long)with_dst);
    printf("  file <= parsed_w?  %s\n",
           file_mtime <= with_dst ? "YES -> would restore (correct)"
                                  : "NO  -> 'did not exist' (BUG)");

    return 0;
}
```

**Output during CET standard time:**

```
tm_isdst=1  (dar):    time_t=1773854018  localtime=Wed Mar 18 18:13:38 2026
tm_isdst=-1 (correct): time_t=1773857618  localtime=Wed Mar 18 19:13:38 2026

Difference: 3600 seconds *** BUG: 3600-second shift due to tm_isdst=1 ***

Simulated dar_manager -w comparison:
  file stored date:  1773857617
  parsed -w date:    1773854018  (with tm_isdst=1)
  file <= parsed_w?  NO  -> 'did not exist' (BUG)
```

## Impact

- **`dar_manager -r -w` is completely broken** during standard-time months in
  any timezone that observes DST. The parsed date is always 1 hour too early
  (for UTC+1 zones; the shift equals the DST offset for other zones).

- The bug is invisible during DST months because `tm_isdst = 1` happens to
  match reality.

- For timezones without DST (e.g., UTC, IST), `tm_isdst = 1` may cause
  unpredictable behavior depending on the C library's handling of an invalid
  DST assertion.

- The same `line_tools_convert_date()` function is used by `dar` itself for
  the `-w` option in backup operations (`-c -A -w`), so the bug may also
  affect date-filtered backups.

## Suggested fix

Change `tm_isdst = 1` to `tm_isdst = -1`, which tells `mktime()` to
determine the correct DST status from the system timezone database:

```diff
--- a/src/dar_suite/line_tools.cpp
+++ b/src/dar_suite/line_tools.cpp
@@ -1162,7 +1162,7 @@
 	    when.tm_sec = when.tm_min = when.tm_hour = 0;
 	    when.tm_wday = 0;            // ignored by mktime
 	    when.tm_yday = 0;            // ignored by mktime
-	    when.tm_isdst = 1;           // provided time is local daylight saving time
+	    when.tm_isdst = -1;          // let mktime determine DST from timezone database
 	    tmp = 0;
 	};
```

This is the POSIX-recommended approach and is what all standard date-parsing
utilities use. It correctly handles:
- Standard time (DST inactive)
- Summer time (DST active)
- Ambiguous hours during DST transitions (mktime resolves them using the
  timezone database)

## Discovery context

This bug was found while developing PITR (Point-in-Time Recovery) support for
the [dar-backup](https://github.com/per2jensen/dar-backup) project. We
attempted to use `dar_manager -r -w -e` as the native PITR mechanism but
found that it silently failed to restore any files during standard-time months
in the CET timezone. After source-level analysis of dar 2.7.19, we traced the
issue to the hardcoded `tm_isdst = 1` in `line_tools_convert_date()`.

Reported by: Per Jensen (dar-backup project)
