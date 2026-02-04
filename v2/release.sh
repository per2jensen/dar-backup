#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# release.sh — controlled release script for dar-backup v2
#
# Purpose
# -------
# This script performs a *defensive, reproducible release* of dar-backup.
# It ensures that the code being released is exactly the code referenced
# by a required git tag, that the full test suite passes, and that
# generated artifacts are signed and optionally uploaded.
#
# The script is intentionally strict and will refuse to proceed unless
# all invariants are satisfied.
#
# What this script guarantees
# ---------------------------
# - A git tag is REQUIRED and must exist.
# - HEAD must point exactly at the tagged commit (no accidental releases).
# - The git tag must match the version defined in src/dar_backup/__about__.py
#   using the format: v2-<version>
# - The full pytest suite is executed via scripts/pytest_report.sh (mode: full).
# - Test reports (JSON + TXT) are generated and committed under doc/test-report/
#   if and only if they changed.
# - Build artifacts are created from the tagged commit only.
# - All artifacts are cryptographically signed and verified before upload.
#
# Required environment
# --------------------
# - Must be run from the dar-backup v2 repository root.
# - Required tools in PATH: git, python3, pytest (+ pytest-json-report), build, gpg, pinentry-tty
# - A Python virtual environment must exist at ./venv and be usable.
# - Tag naming convention: v2-<version> (e.g. v2-1.0.0, v2-1.0.0.1)
#
# Failure behavior
# ----------------
# Any violation causes immediate exit with non-zero status.
# Partial releases are intentionally impossible.
#
# Usage
# -----
#   ./release.sh --tag v2-<version>
#   ./release.sh --tag v2-<version> --upload-to-pypi
#

set -euo pipefail

########################################
# Parse arguments (TAG required)
########################################
UPLOAD=false
TAG=""

usage() {
    echo "Usage: $0 --tag v2-<version> [--upload-to-pypi]"
    echo "Examples:"
    echo "  $0 --tag v2-1.1.0"
    echo "  $0 --tag v2-1.1.0 --upload-to-pypi"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --upload-to-pypi)
            UPLOAD=true
            shift
            ;;
        --tag)
            TAG="${2:-}"
            if [[ -z "$TAG" ]]; then
                echo "❌ Error: --tag requires a value"
                usage
                exit 1
            fi
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "❌ Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ -z "$TAG" ]]; then
    echo "❌ Error: --tag is required"
    usage
    exit 1
fi

########################################
# Helpers
########################################
red()   { echo -e "\033[1;31m$*\033[0m"; }
green() { echo -e "\033[1;32m$*\033[0m"; }

########################################
# Environment checks (early exit gates)
########################################

# 0) Must be in a git repo
git rev-parse --git-dir >/dev/null 2>&1 \
  || { red "❌ Not a git repository"; exit 1; }

# 1) Tag must exist
git show-ref --tags --verify --quiet "refs/tags/${TAG}" \
  || { red "❌ Tag does not exist: ${TAG}"; exit 1; }

# 2) HEAD must be exactly at the tag commit
TAG_COMMIT="$(git rev-list -n 1 "${TAG}")"
HEAD_COMMIT="$(git rev-parse HEAD)"
if [[ "$TAG_COMMIT" != "$HEAD_COMMIT" ]]; then
    red "❌ HEAD is not at tag ${TAG}"
    echo "Tag commit:  ${TAG_COMMIT}"
    echo "HEAD commit: ${HEAD_COMMIT}"
    exit 1
fi

# 3) Working tree must be clean
if ! git diff --quiet || ! git diff --cached --quiet; then
    red "❌ Working tree has uncommitted changes; aborting release"
    git status --porcelain
    exit 1
fi

# 4) pinentry-tty must exist (gpg UX)
if ! command -v pinentry-tty &> /dev/null; then
    red "❌ Error: 'pinentry-tty' not found in PATH."
    echo "💡 Install:"
    echo "    sudo apt install pinentry-tty"
    echo ""
    echo "Configure GnuPG to use it:"
    echo "    echo 'pinentry-program /usr/bin/pinentry-tty' >> ~/.gnupg/gpg-agent.conf"
    echo "    gpgconf --kill gpg-agent"
    exit 1
fi

########################################
# Release configuration
########################################
VENV_DIR="./venv"
DIST_DIR="dist"
SIGNING_SUBKEY="B54F5682F28DBA3622D78E0458DBFADBBBAC1BB1"

# Make gpg ask for passphrase in the terminal
export GPG_TTY
GPG_TTY="$(tty)"

########################################
# Virtualenv
########################################
if [[ ! -e "$(realpath "$VENV_DIR")" ]]; then
    red "Virtual environment not found (no $VENV_DIR)"
    echo "See doc/dev.md for setup instructions"
    exit 1
fi

if [[ -z "${VIRTUAL_ENV:-}" ]] || [[ "$VIRTUAL_ENV" != "$(realpath "$VENV_DIR")" ]]; then
    green "Activating virtual environment in $VENV_DIR"
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
fi

########################################
# Version and tag policy
########################################
VERSION="$(python - <<'PY'
from pathlib import Path
ns = {}
exec(Path("src/dar_backup/__about__.py").read_text(encoding="utf-8"), ns)
print(ns["__version__"])
PY
)"

EXPECTED_TAG="v2-${VERSION}"
if [[ "$TAG" != "$EXPECTED_TAG" ]]; then
    red "❌ Error: tag/version mismatch"
    echo "Expected tag: ${EXPECTED_TAG}"
    echo "Provided tag: ${TAG}"
    exit 1
fi

########################################
# Prepare README/Changelog copies for wheel inclusion
########################################
cp ../README.md "${PWD}/README.md"

TEMP_README="src/dar_backup/README.md"
cp README.md "$TEMP_README"  ||
    { red "❌ Error: Failed to copy README.md to $TEMP_README"; exit 1; }

TEMP_CHANGELOG="src/dar_backup/Changelog.md"
cp Changelog.md "$TEMP_CHANGELOG"  ||
    { red "❌ Error: Failed to copy Changelog.md to $TEMP_CHANGELOG"; exit 1; }

trap 'rm -f "$TEMP_README" "$TEMP_CHANGELOG"' EXIT

########################################
# Run FULL test suite and commit report output
########################################
green "Running full pytest suite with report generation..."
mkdir -p doc/test-report

export COVERAGE_PROCESS_START="$PWD/.coveragerc"

# set -u is enabled; PYTHONPATH may be unset in a clean shell
# Prepend repo root to PYTHONPATH only if it already exists.
if [[ -n "${PYTHONPATH:-}" ]]; then
    export PYTHONPATH="$PWD:$PYTHONPATH"
else
    export PYTHONPATH="$PWD"
fi

# This MUST abort the release on test failure.
# - release.sh has: set -euo pipefail
# - pytest_report.sh must have: set -euo pipefail
scripts/pytest_report.sh full || { red "❌ Test suite failed; aborting release"; exit 1; }

# Commit generated reports (only if there are changes)
if ! git diff --quiet -- doc/test-report/; then
    TS="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
    git add doc/test-report/
    git commit -m "test-report: dar-backup ${VERSION} full ${TS}"
    green "Committed test reports to doc/test-report/"
else
    green "No changes in doc/test-report/; nothing to commit"
fi

########################################
# Safety check: only allow tag move if the ONLY changes between
# the existing tag commit and current HEAD are inside doc/test-report/

# At this point we just created a commit (HEAD) that should only touch doc/test-report/.
# Enforce that invariant before moving the tag.

OLD_TAG_COMMIT="$(git rev-list -n 1 "${TAG}")"
NEW_HEAD_COMMIT="$(git rev-parse HEAD)"

# List all changed paths between the old tag commit and HEAD.
# (This includes all commits between them, which should be exactly the test-report commit.)
CHANGED_PATHS="$(
  git diff --name-only "${OLD_TAG_COMMIT}..${NEW_HEAD_COMMIT}" || true
)"

# If there are no changed paths, something is off (we claimed we committed changes).
if [[ -z "${CHANGED_PATHS}" ]]; then
    red "❌ Safety check failed: expected changes between ${TAG} and HEAD, but diff is empty"
    exit 1
fi

# Ensure every changed path is under doc/test-report/
# Any path not matching that prefix is a hard abort.
VIOLATIONS="$(
  printf '%s\n' "${CHANGED_PATHS}" | awk 'NF && $0 !~ /^doc\/test-report\// {print}'
)"

if [[ -n "${VIOLATIONS}" ]]; then
    red "❌ Safety check failed: changes outside doc/test-report/ detected between ${TAG} and HEAD"
    echo "Old tag commit: ${OLD_TAG_COMMIT}"
    echo "New HEAD commit: ${NEW_HEAD_COMMIT}"
    echo ""
    echo "Violating paths:"
    printf '%s\n' "${VIOLATIONS}"
    echo ""
    echo "Aborting WITHOUT moving tag."
    exit 1
fi

green "✅ Safety check passed: only doc/test-report/ changed between ${TAG} and HEAD"

########################################
# Now move the tag 
########################################
green "Moving tag ${TAG} to include test-report commit..."
TAG_OBJ_TYPE="$(git cat-file -t "refs/tags/${TAG}")"

if [[ "${TAG_OBJ_TYPE}" == "tag" ]]; then
    TAG_MSG="$(git for-each-ref --format='%(contents)' "refs/tags/${TAG}")"
    git tag -f -a "${TAG}" -m "${TAG_MSG}" HEAD
else
    git tag -f "${TAG}" HEAD
fi

# Re-assert invariant
TAG_COMMIT="$(git rev-list -n 1 "${TAG}")"
HEAD_COMMIT="$(git rev-parse HEAD)"
if [[ "$TAG_COMMIT" != "$HEAD_COMMIT" ]]; then
    red "❌ Failed to move tag ${TAG} to new HEAD"
    echo "Tag commit:  ${TAG_COMMIT}"
    echo "HEAD commit: ${HEAD_COMMIT}"
    exit 1
fi

green "✅ Tag ${TAG} now points at release commit ${HEAD_COMMIT}"


########################################
# Build
########################################
rm -rf "$DIST_DIR" || { red "❌ Error: Failed to remove $DIST_DIR"; exit 1; }
python3 -m build

########################################
# Sign + verify
########################################
for f in $DIST_DIR/*.{whl,tar.gz}; do
    if gpg --batch --yes --detach-sign -a --local-user "$SIGNING_SUBKEY" "$f"; then
        green "✅ Signed: $f"
    else
        red "❌ GPG signing failed for $f"
        exit 1
    fi
done

for f in $DIST_DIR/*.{whl,tar.gz}; do
    if gpg --verify "$f.asc" "$f"; then
        green "✅ Verified signature: $f.asc"
    else
        red "❌ Signature verification failed: $f.asc"
        exit 1
    fi

    SIGNER_FPR=$(
      gpg --list-packets "$f.asc" \
      | awk '/signature packet/,/hashed subpkt/ { if ($1 == "issuer-fpr") print $2 }' \
      | head -n1
    )
    if [[ -n "$SIGNER_FPR" ]]; then
        echo -e "\n📌 Signed by subkey fingerprint: $SIGNER_FPR\n"
    fi
done

########################################
# Upload (optional)
########################################
if $UPLOAD; then
    green "Uploading to PyPI..."
    if twine upload "$DIST_DIR"/*; then
        green "🎉 Done: Version $VERSION uploaded successfully"
    else
        red "❌ Upload failed: twine returned non-zero exit code"
        exit 1
    fi
else
    green "Dry run: Skipping upload to PyPI"
    echo  "To upload, run:"
    echo  "  ./release.sh --tag ${TAG} --upload-to-pypi"
fi

