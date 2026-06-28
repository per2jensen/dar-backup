#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# copy_docs.sh — copy user-facing docs into src/dar_backup/ for wheel inclusion
#
# Called by build.sh, release.sh, and test fixtures so that README.md,
# Changelog.md, and doc/*.md are present in installed packages and the
# --readme / --changelog / --readme-pretty / --changelog-pretty CLI options
# can find them via _resolve_doc_path().
#
# Must be run from the v2/ directory.
# Cleanup of the copied files is the caller's responsibility.

set -euo pipefail

[[ -f "pyproject.toml" && -d "src/dar_backup" ]] \
    || { echo "ERROR: must be run from the v2/ directory" >&2; exit 1; }

cp ../README.md   src/dar_backup/README.md
cp Changelog.md   src/dar_backup/Changelog.md

mkdir -p src/dar_backup/doc
find doc/ -maxdepth 1 -name "*.md" \
    ! -name "todo.md" \
    ! -name "dev.md" \
    ! -name "dar_manager_w_dst_bug_report.md" \
    ! -name "NFS server notes.md" \
    -exec cp {} src/dar_backup/doc/ \;

echo "docs copied to src/dar_backup/"
