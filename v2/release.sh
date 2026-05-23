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
# - On successful upload, build-history.json and the clone-pulse annotation are
#   updated and committed in two separate post-release commits (beyond the tag).
# - All output is captured to doc/releases/release-<tag>.log.
#
# Required environment
# --------------------
# - Must be run from the dar-backup v2 repository root.
# - Required tools in PATH: git, python3, pytest (+ pytest-json-report), build, gpg, pinentry-tty
# - A Python virtual environment must exist at ./venv and be usable.
# - Tag naming convention: v2-<version> (e.g. v2-1.0.0, v2-1.0.0.1)
# - TWINE_USERNAME / TWINE_PASSWORD must be set when using --upload-to-pypi.
#
# Failure behavior
# ----------------
# Any violation causes immediate exit with non-zero status.
# Partial releases are intentionally impossible.
# Post-upload failures print exact recovery commands so the user can complete
# the bookkeeping manually without touching PyPI again.
#
# Usage
# -----
#   ./release.sh --tag v2-<version>
#   ./release.sh --tag v2-<version> --upload-to-pypi
#   ./release.sh --tag v2-<version> --dry-run
#
# --dry-run runs all read-only pre-flight checks (tag, version, clean tree,
# duplicate guard) and reports what would happen, without making any commits,
# moving the tag, building, signing, or uploading.
#

set -euo pipefail

########################################
# Parse arguments (TAG required)
########################################
UPLOAD=false
DRY_RUN=false
TAG=""

usage() {
    echo "Usage: $0 --tag v2-<version> [--upload-to-pypi] [--dry-run]"
    echo "Examples:"
    echo "  $0 --tag v2-1.1.0"
    echo "  $0 --tag v2-1.1.0 --upload-to-pypi"
    echo "  $0 --tag v2-1.1.0 --dry-run"
    echo ""
    echo "  --dry-run  Run all pre-flight checks only; make no commits, no tag moves,"
    echo "             no builds, no signing, no upload."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --upload-to-pypi)
            UPLOAD=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
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
# Release log — captures all output from this point on
########################################
if $DRY_RUN; then
    LOG_FILE="doc/releases/release-${TAG}-dryrun.log"
else
    LOG_FILE="doc/releases/release-${TAG}.log"
fi
exec > >(tee -a "${LOG_FILE}") 2>&1
echo "=== Release run: $(date -u +%Y-%m-%dT%H:%M:%SZ) | tag: ${TAG}${DRY_RUN:+ | DRY RUN} ==="

########################################
# Helpers
########################################
red()    { echo -e "\033[1;31m$*\033[0m"; }
green()  { echo -e "\033[1;32m$*\033[0m"; }
dryrun() { echo -e "\033[1;34m🔍 DRY RUN — would: $*\033[0m"; }


# Check for TWINE_PASSWORD if upload is requested (skipped in dry run)
if $UPLOAD && ! $DRY_RUN; then
  if [[ -z "${TWINE_PASSWORD:-}" ]]; then
    red "❌ TWINE_PASSWORD is not set. Export it before uploading."
    echo "  export TWINE_USERNAME=__token__"
    echo "  export TWINE_PASSWORD=<the token>"
    exit 1
  fi
fi




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

# 4) pinentry-tty must exist (gpg UX) — not needed for dry run
if ! $DRY_RUN && ! command -v pinentry-tty &> /dev/null; then
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
# Duplicate release guard
########################################
BUILD_HISTORY="./build-history.json"
if [[ -f "${BUILD_HISTORY}" ]]; then
    DUPLICATE=$(python3 - "${VERSION}" "${BUILD_HISTORY}" <<'PY'
import json, sys
from pathlib import Path
version, path = sys.argv[1], sys.argv[2]
data = json.loads(Path(path).read_text(encoding="utf-8"))
print("yes" if any(e.get("version") == version for e in data) else "no")
PY
)
    if [[ "${DUPLICATE}" == "yes" ]]; then
        red "❌ Version ${VERSION} already exists in build-history.json — release already done?"
        exit 1
    fi
fi

########################################
# Stamp release date in changelogs and update README version
########################################
if $DRY_RUN; then
    dryrun "stamp release date in CHANGELOG.md / Changelog.md / README.md for ${VERSION}"
else
    TODAY="$(date -u +%Y-%m-%d)"
    NOT_RELEASED_PATTERN="## v2-${VERSION}[[:space:]]+ -[[:space:]]+not released"
    RELEASED_LINE="## v2-${VERSION} - ${TODAY}"

    for _cl in "../CHANGELOG.md" "Changelog.md"; do
        if [[ -f "${_cl}" ]]; then
            sed -i -E "s|${NOT_RELEASED_PATTERN}|${RELEASED_LINE}|" "${_cl}"
            green "Stamped release date in ${_cl}"
        fi
    done

    _readme="../README.md"
    if [[ -f "${_readme}" ]]; then
        sed -i -E "s/Version[[:space:]]+\*\*[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?\*\*/Version **${VERSION}**/" "${_readme}"
        green "Updated current release version in ${_readme}"
    fi
fi

########################################
# Prepare README/Changelog copies for wheel inclusion
########################################
TEMP_README="src/dar_backup/README.md"
TEMP_CHANGELOG="src/dar_backup/Changelog.md"
trap 'rm -f "$TEMP_README" "$TEMP_CHANGELOG"' EXIT

if $DRY_RUN; then
    dryrun "copy README.md and Changelog.md into src/dar_backup/ for wheel inclusion"
else
    cp ../README.md "$TEMP_README"  ||
        { red "❌ Error: Failed to copy README.md to $TEMP_README"; exit 1; }

    cp Changelog.md "$TEMP_CHANGELOG"  ||
        { red "❌ Error: Failed to copy Changelog.md to $TEMP_CHANGELOG"; exit 1; }
fi


########################################
# Run FULL test suite and commit report output
########################################
REPO_ROOT="$(git rev-parse --show-toplevel)"
REPO_REL="$(realpath --relative-to="${REPO_ROOT}" "${PWD}")"
if [[ "${REPO_REL}" == "." ]]; then
    REPORT_PREFIX="doc/test-report/"
else
    REPORT_PREFIX="${REPO_REL}/doc/test-report/"
fi

if $DRY_RUN; then
    dryrun "run full pytest suite and commit test report + release metadata"
else
    green "Running full pytest suite with report generation..."
    mkdir -p doc/test-report

    export COVERAGE_PROCESS_START="$PWD/pyproject.toml"

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

    REPORT_STATUS="$(git -C "${REPO_ROOT}" status --porcelain -- "${REPORT_PREFIX}")"
    RELEASE_META_STATUS="$(git -C "${REPO_ROOT}" status --porcelain -- \
        "CHANGELOG.md" "${REPO_REL}/Changelog.md" "README.md" 2>/dev/null || true)"

    if [[ -n "${REPORT_STATUS}" || -n "${RELEASE_META_STATUS}" ]]; then
        TS="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
        git -C "${REPO_ROOT}" add "${REPORT_PREFIX}"
        # Stage changelog/README changes if present (paths relative to repo root)
        git -C "${REPO_ROOT}" add -- "CHANGELOG.md" "${REPO_REL}/Changelog.md" "README.md" 2>/dev/null || true
        git -C "${REPO_ROOT}" commit -m "release: dar-backup ${VERSION} — stamp date, update README, test-report ${TS}"
        green "Committed release metadata and test reports"
    else
        green "No changes to commit for release metadata or test reports"
    fi
fi

########################################
# Safety check: only allow tag move if the ONLY changes between
# the existing tag commit and current HEAD are release-managed files
# (doc/test-report/, CHANGELOG.md, v2/Changelog.md, README.md).
########################################
if $DRY_RUN; then
    dryrun "safety check: verify only release-managed files changed between ${TAG} and HEAD"
else
    # Enforce that invariant before moving the tag.
    OLD_TAG_COMMIT="$(git rev-list -n 1 "${TAG}")"
    NEW_HEAD_COMMIT="$(git rev-parse HEAD)"

    CHANGED_PATHS="$(
      git diff --name-only "${OLD_TAG_COMMIT}..${NEW_HEAD_COMMIT}" || true
    )"

    if [[ -z "${CHANGED_PATHS}" ]]; then
        red "❌ Safety check failed: expected changes between ${TAG} and HEAD, but diff is empty"
        exit 1
    fi

    VIOLATIONS="$(
      printf '%s\n' "${CHANGED_PATHS}" | awk \
        -v prefix="${REPORT_PREFIX}" \
        -v rel="${REPO_REL}" \
        'NF {
           allowed = (index($0, prefix) == 1) \
                  || ($0 == "CHANGELOG.md") \
                  || ($0 == "README.md") \
                  || (rel != "." && $0 == rel "/Changelog.md") \
                  || (rel == "." && $0 == "Changelog.md");
           if (!allowed) print $0
         }'
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
fi

########################################
# Now move the tag
########################################
if $DRY_RUN; then
    dryrun "move tag ${TAG} to include test-report commit"
else
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
fi


########################################
# Build
########################################
if $DRY_RUN; then
    dryrun "build wheel and sdist with python3 -m build"
else
    rm -rf "$DIST_DIR" || { red "❌ Error: Failed to remove $DIST_DIR"; exit 1; }
    python3 -m build

    # Verify that artifacts were created
    mapfile -t ARTIFACTS < <(ls "$DIST_DIR"/*.whl "$DIST_DIR"/*.tar.gz 2>/dev/null)
    if [[ ${#ARTIFACTS[@]} -eq 0 ]]; then
        red "❌ No artifacts found in $DIST_DIR"
        exit 1
    fi
fi

########################################
# Sign + verify
########################################
if $DRY_RUN; then
    dryrun "GPG sign and verify all dist artifacts with key ${SIGNING_SUBKEY}"
else
    echo ""
    echo "About to sign release artifacts with GPG."
    read -r -p "Press Enter to continue (or Ctrl+C to abort)..." _

    for f in "$DIST_DIR"/*.{whl,tar.gz}; do
        if gpg --batch --yes --detach-sign -a --local-user "$SIGNING_SUBKEY" "$f"; then
            green "✅ Signed: $f"
        else
            red "❌ GPG signing failed for $f"
            exit 1
        fi
    done

    for f in "$DIST_DIR"/*.{whl,tar.gz}; do
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
fi



########################################
# Upload / dry-run summary
########################################
if $DRY_RUN; then
    echo ""
    dryrun "upload to PyPI with twine"
    dryrun "append entry to build-history.json"
    dryrun "stamp clone annotation for ${VERSION}"
    dryrun "commit build-history.json, clone annotation, and release log"
    echo ""
    green "✅ DRY RUN complete — all pre-flight checks passed, no changes made"
    exit 0
elif $UPLOAD; then
    green "Uploading to PyPI..."
    if twine upload "$DIST_DIR"/*; then
        green "🎉 Done: Version $VERSION uploaded successfully"

        ########################################
        # Post-release: build history + clone annotation
        ########################################
        WHEEL_FILE="dar_backup-${VERSION}-py3-none-any.whl"
        SDIST_FILE="dar_backup-${VERSION}.tar.gz"
        WHEEL_SHA256="$(sha256sum "${DIST_DIR}/${WHEEL_FILE}" | awk '{print $1}')"
        SDIST_SHA256="$(sha256sum "${DIST_DIR}/${SDIST_FILE}" | awk '{print $1}')"
        RELEASE_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        RELEASE_REVISION="$(git rev-parse --short HEAD)"

        python3 - "${VERSION}" "${TAG}" "${RELEASE_REVISION}" "${RELEASE_TIMESTAMP}" \
                 "${WHEEL_FILE}" "${WHEEL_SHA256}" \
                 "${SDIST_FILE}" "${SDIST_SHA256}" \
                 "${SIGNING_SUBKEY}" "${BUILD_HISTORY}" <<'PY'
import json, sys
from pathlib import Path

(version, git_tag, git_rev, created,
 wheel_file, wheel_sha256,
 sdist_file, sdist_sha256,
 key_fpr, history_path) = sys.argv[1:]

path = Path(history_path)
data = json.loads(path.read_text(encoding="utf-8"))
next_num = max((e["release_number"] for e in data), default=-1) + 1
entry = {
    "release_number": next_num,
    "version": version,
    "git_tag": git_tag,
    "git_revision": git_rev,
    "created": created,
    "pypi_url": f"https://pypi.org/project/dar-backup/{version}/",
    "artifacts": {
        "wheel": {"file": wheel_file, "sha256": wheel_sha256},
        "sdist": {"file": sdist_file, "sha256": sdist_sha256},
    },
    "gpg": {
        "signed": True,
        "key_fingerprint": key_fpr,
    },
}
data.append(entry)
path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"Appended release_number {next_num} to {history_path}")
PY
        green "✅ Updated build-history.json"

        git -C "${REPO_ROOT}" add "${REPO_REL}/build-history.json" || {
            red "❌ Failed to stage build-history.json"
            red "   Recover manually:"
            red "   git add ${REPO_REL}/build-history.json"
            red "   git commit -m 'post-release: dar-backup ${VERSION} — build history'"
            exit 1
        }
        git -C "${REPO_ROOT}" commit \
            -m "post-release: dar-backup ${VERSION} — build history" || {
            red "❌ Failed to commit build-history.json"
            red "   Recover manually:"
            red "   git commit -m 'post-release: dar-backup ${VERSION} — build history'"
            exit 1
        }
        green "✅ Build history committed (intentionally beyond release tag)"

        python3 ../clonepulse/add_release_annotation.py "${VERSION}"
        green "✅ Stamped clone annotation for ${VERSION}"

        git -C "${REPO_ROOT}" add "clonepulse/fetch_clones.json" || {
            red "❌ Failed to stage fetch_clones.json"
            red "   Recover manually:"
            red "   git add clonepulse/fetch_clones.json"
            red "   git commit -m 'post-release: dar-backup ${VERSION} — clone annotation'"
            exit 1
        }
        git -C "${REPO_ROOT}" commit \
            -m "post-release: dar-backup ${VERSION} — clone annotation" || {
            red "❌ Failed to commit fetch_clones.json"
            red "   Recover manually:"
            red "   git commit -m 'post-release: dar-backup ${VERSION} — clone annotation'"
            exit 1
        }
        green "✅ Clone annotation committed"

        green "Committing release log..."
        git -C "${REPO_ROOT}" add "${REPO_REL}/doc/releases/release-${TAG}.log" || {
            red "❌ Failed to stage release log — commit manually:"
            red "   git add ${REPO_REL}/doc/releases/release-${TAG}.log"
            red "   git commit -m 'post-release: dar-backup ${VERSION} — release log'"
            exit 1
        }
        git -C "${REPO_ROOT}" commit \
            -m "post-release: dar-backup ${VERSION} — release log" || {
            red "❌ Failed to commit release log — commit manually:"
            red "   git commit -m 'post-release: dar-backup ${VERSION} — release log'"
            exit 1
        }
        green "✅ Release log committed: doc/releases/release-${TAG}.log"
    else
        red "❌ Upload failed: twine returned non-zero exit code"
        exit 1
    fi
else
    green "Artifacts built and signed. To upload to PyPI, run:"
    echo  "  ./release.sh --tag ${TAG} --upload-to-pypi"
fi
