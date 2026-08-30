# Bash aliases

Here are some bash aliases which help me in day to day management of dar-backup archives and par2 files.

```bash
# dar-backup archive helpers
#
# Assumes filenames contain:
#   <definition>_<FULL|DIFF|INCR>_YYYY-MM-DD
#
# Examples:
#   media-files_FULL_2025-01-04.58.dar
#   media-files_FULL_2025-01-04.58.dar.par2
#   media-files_DIFF_2026-03-19.12.dar


# 1. Unique backup runs, sorted by definition/name
alias dblist="find . -maxdepth 1  -type f   -printf '%f\n' \
  | sed -nE 's/^(.+_(FULL|DIFF|INCR)_[0-9]{4}-[0-9]{2}-[0-9]{2}).*/\1/p' \
  | sort -u"


# 2. Unique backup runs, sorted chronologically by date
alias dblist-date="find . -maxdepth 1 -type f    -printf '%f\n' \
  | sed -nE 's/^(.+_(FULL|DIFF|INCR)_([0-9]{4}-[0-9]{2}-[0-9]{2})).*/\3 \1/p' \
  | sort -u \
  | sort -k1,1 \
  | cut -d' ' -f2-"


# 3. Show only FULL backups
alias dblist-full="find . -maxdepth 1  -type f   -printf '%f\n' \
  | sed -nE 's/^(.+_FULL_[0-9]{4}-[0-9]{2}-[0-9]{2}).*/\1/p' \
  | sort -u"


# 4. Count files belonging to each backup run
#    Includes DAR slices, PAR2 files, etc.
alias dbcount="find . -maxdepth 1  -type f   -printf '%f\n' \
  | sed -nE 's/^(.+_(FULL|DIFF|INCR)_[0-9]{4}-[0-9]{2}-[0-9]{2}).*/\1/p' \
  | sort \
  | uniq -c \
  | sort -k2"


# 5. Total disk usage for each backup run
#    GNU du/find version; reports human-readable totals.
alias dbsize="find . -maxdepth 1  -type f    -printf '%f\n' \
  | sed -nE 's/^(.+_(FULL|DIFF|INCR)_[0-9]{4}-[0-9]{2}-[0-9]{2}).*/\1/p' \
  | sort -u \
  | while read -r backup; do \
      size=\$(find . -type f -name \"\$backup*\" -printf '%s\n' \
        | awk '{s+=\$1} END {print s+0}'); \
      printf '%12s  %s\n' \"\$(numfmt --to=iec-i --suffix=B \"\$size\")\" \"\$backup\"; \
    done"

```