#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# pre-commit-version-bump.sh — keep __about__.__version__ dev counter current
#
# Install once from the repo root:
#   ln -sf ../../v2/scripts/pre-commit-version-bump.sh .git/hooks/pre-commit
#
# On every commit this hook:
#   1. Reads __version__ from src/dar_backup/__about__.py.
#   2. Skips silently if the version has no .dev suffix (release.sh owns that state).
#   3. Counts commits since the last v2-X.Y.Z release tag, adds 1 for the commit
#      now in progress, and writes "X.Y.Z.dev<N>" back to __about__.py.
#   4. Verifies the write landed, then stages the file.
#
# Fallback: if no v2-X.Y.Z release tag exists yet, counts all commits in history.
# Errors are fatal — a broken hook blocks the commit so problems are never silent.

set -euo pipefail

die() { echo "  [hook] ERROR: $*" >&2; exit 1; }

REPO_ROOT=$(git rev-parse --show-toplevel)
ABOUT_FILE="${REPO_ROOT}/v2/src/dar_backup/__about__.py"

[[ -f "$ABOUT_FILE" ]] || die "__about__.py not found at: ${ABOUT_FILE}"

CURRENT_VERSION=$(grep -Po '(?<=__version__ = ")[^"]+' "$ABOUT_FILE" || true)
[[ -n "$CURRENT_VERSION" ]] || die "could not extract __version__ from ${ABOUT_FILE}"

# Skip if no .dev suffix — release.sh has already stripped it; nothing to do.
[[ "$CURRENT_VERSION" =~ \.dev[0-9]+$ ]] || exit 0

BASE_VERSION="${CURRENT_VERSION%.dev*}"

# Find the nearest release tag and count commits since it.
# +1 accounts for the commit now being made (pre-commit runs before it exists).
LAST_TAG=$(git describe --tags --abbrev=0 --match "v2-[0-9]*.[0-9]*.[0-9]*" HEAD 2>/dev/null || true)
if [[ -n "$LAST_TAG" ]]; then
    N=$(( $(git rev-list --count "${LAST_TAG}..HEAD") + 1 ))
else
    # No release tag yet — count every commit in history.
    N=$(( $(git rev-list --count HEAD) + 1 ))
fi

NEW_VERSION="${BASE_VERSION}.dev${N}"

# Nothing changed (e.g. amending without new commits) — skip silently.
[[ "$NEW_VERSION" == "$CURRENT_VERSION" ]] && exit 0

sed -i "s/__version__ = \"${CURRENT_VERSION}\"/__version__ = \"${NEW_VERSION}\"/" "$ABOUT_FILE"

# Verify the substitution actually landed before staging.
WRITTEN=$(grep -Po '(?<=__version__ = ")[^"]+' "$ABOUT_FILE" || true)
[[ "$WRITTEN" == "$NEW_VERSION" ]] \
    || die "substitution failed in ${ABOUT_FILE} (expected ${NEW_VERSION}, found ${WRITTEN})"

git add "$ABOUT_FILE"
echo "  [hook] __version__: ${CURRENT_VERSION} → ${NEW_VERSION}"
