#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# lock-old-archives.sh
#
# Example of the author's approach to server-side hardening for backup artifact
# directories on an NFS server.
#
# For this to work, the `cleanup` script must be run on the server holding the
# filesystem. Multiple ways to run it: ssh + sudo, cron job, systemd timer, etc.
# It should be run periodically (e.g. daily)
#
#
# Purpose
#   Server-side hardening: make backup artifacts older than 48 hours non-writable and
#   owned by root, so NFS clients cannot modify or delete them (when parent
#   dir has sticky bit enabled).
#
# What it does
#   - Loops over DAR archive directory and PAR2 directory
#   - Targets only known backup artifact extensions (dar slices, par2)
#   - Skips files already owned by root
#   - Skips symlinks (never follow/alter them)
#   - Uses null-delimited piping (safe for spaces/newlines in filenames)
#   - Logs actions and returns non-zero on errors
#
# Configuration (env overrides)
#   DAR_ARCHIVES_DIR  (default: /samba/dar)
#   PAR2_DIR          (default: /mnt/par2)
#   AGE_MINUTES       (default: 2880 = 48h)
#   DRY_RUN           (default: 0; set to 1 to print what would change)
#
# Requirements
#   - Must run as root on the server holding the filesystem.
#   - Parent directories should be owned by root:<writers> and be sticky+group writable, e.g.:
#       chown root:backup /samba/dar
#       chmod 1770 /samba/dar
#
set -euo pipefail
IFS=$'\n\t'

DAR_ARCHIVES_DIR="${DAR_ARCHIVES_DIR:-/samba/dar}"
PAR2_DIR="${PAR2_DIR:-/mnt/par2}"
AGE_MINUTES="${AGE_MINUTES:-2880}"  # 48h
DRY_RUN="${DRY_RUN:-0}"

log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"

if [[ "$DRY_RUN" == "1" ]]; then
  log "DRY_RUN=1 (no changes will be made)"
fi

# Build list of directories to process (skip missing dirs with a warning)
DIRS=()
if [[ -d "$DAR_ARCHIVES_DIR" ]]; then
  DIRS+=("$DAR_ARCHIVES_DIR")
else
  log "WARN: DAR_ARCHIVES_DIR not found, skipping: $DAR_ARCHIVES_DIR"
fi

if [[ -d "$PAR2_DIR" ]]; then
  DIRS+=("$PAR2_DIR")
else
  log "WARN: PAR2_DIR not found, skipping: $PAR2_DIR"
fi

(( ${#DIRS[@]} > 0 )) || die "no valid directories to process"

# Collect files across all dirs, then apply changes in bulk.
# -xdev: do not cross filesystem boundaries (helps avoid surprises if mounts exist below)
# File patterns:
#   - DAR archives: *.dar (including slice naming)
#   - DAR catalogs: *.darc (if present)
#   - PAR2: *.par2
#
files=()
for d in "${DIRS[@]}"; do
  mapfile -d '' found < <(
    find "$d" \
      -xdev \
      -type f \
      \( -name '*.dar' -o -name '*.darc' -o -name '*.par2' \) \
      -mmin +"$AGE_MINUTES" \
      ! -user root \
      -print0
  )
  if (( ${#found[@]} > 0 )); then
    files+=("${found[@]}")
  fi
done

if (( ${#files[@]} == 0 )); then
  log "No files to lock (age>${AGE_MINUTES}m, non-root owned) in: ${DIRS[*]}"
  exit 0
fi

log "Locking ${#files[@]} file(s) (age>${AGE_MINUTES}m) across: ${DIRS[*]}"

if [[ "$DRY_RUN" == "1" ]]; then
  # Print the list (one per line) for review
  printf '%s\0' "${files[@]}" | xargs -0 -n 1 printf 'Will chown & chmod on: %s\n'
  exit 0
fi

# Apply ownership and permissions in two passes for clarity and debuggability.
# Use -- to prevent any path starting with '-' from being interpreted as an option.
printf '%s\0' "${files[@]}" | xargs -0 chown -- root:root
printf '%s\0' "${files[@]}" | xargs -0 chmod -- 0444

log "Done"
