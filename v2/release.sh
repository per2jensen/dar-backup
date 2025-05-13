#!/bin/bash

# Build, sign, verify and (optionally) upload the dar-backup package to PyPI
# Licensed under GNU GPL v3

set -euo pipefail

# === Environment ===
export GPG_TTY=$(tty)  # make gpg ask for passphrase in the terminal

# Check for pinentry-tty
if ! command -v pinentry-tty &> /dev/null; then
    echo "❌ Error: 'pinentry-tty' not found in PATH."
    echo "💡 You can install it with:"
    echo "    sudo apt install pinentry-tty"
    echo ""
    echo "Then configure GnuPG to use it:"
    echo "    echo 'pinentry-program /usr/bin/pinentry-tty' >> ~/.gnupg/gpg-agent.conf"
    echo "    gpgconf --kill gpg-agent"
    exit 1
fi

# === Configuration ===
VENV_DIR="./venv"
DIST_DIR="dist"
PACKAGE_NAME="dar_backup"
SIGNING_SUBKEY="B54F5682F28DBA3622D78E0458DBFADBBBAC1BB1"

UPLOAD=false

# === Parse arguments ===
for arg in "$@"; do
    case $arg in
        --upload-to-pypi)
            UPLOAD=true
            ;;
        *)
            echo "❌ Unknown option: $arg"
            echo "Usage: $0 [--upload-to-pypi]"
            exit 1
            ;;
    esac
done

# === Helpers ===
red()   { echo -e "\033[1;31m$*\033[0m"; }
green() { echo -e "\033[1;32m$*\033[0m"; }

# === Check virtual environment ===
if [ ! -e "$(realpath $VENV_DIR)" ]; then
    red "Virtual environment not found (no $VENV_DIR)"
    echo "See doc/dev.md for setup instructions"
    exit 1
fi

if [ -z "${VIRTUAL_ENV:-}" ] || [ "$VIRTUAL_ENV" != "$(realpath $VENV_DIR)" ]; then
    green "Activating virtual environment in $VENV_DIR"
    source "$VENV_DIR/bin/activate"
fi

# === Extract version from __about__.py ===
VERSION=$(grep -Eo '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?' src/dar_backup/__about__.py)


# the top level README.md is the maintained one. Copy it to this directory
cp ../README.md "${PWD}/README.md"

# === Temporary copy of README.md & Changelog.md into package for wheel inclusion ===
TEMP_README="src/dar_backup/README.md"
cp README.md "$TEMP_README"  ||
    { red "❌ Error: Failed to copy README.md to $TEMP_README"; exit 1; }

TEMP_CHANGELOG="src/dar_backup/Changelog.md"
cp Changelog.md "$TEMP_CHANGELOG"  ||
    { red "❌ Error: Failed to copy Changelog.md to $TEMP_CHANGELOG"; exit 1; }

trap 'rm -f "$TEMP_README" "$TEMP_CHANGELOG"' EXIT


# === Build the package ===
rm -rf "$DIST_DIR"  ||
    { red "❌ Error: Failed to remove $DIST_DIR"; exit 1; }
python3 -m build

# === Sign distributions using specific subkey ===
for f in $DIST_DIR/*.{whl,tar.gz}; do
    if gpg --batch --yes --detach-sign -a --local-user "$SIGNING_SUBKEY" "$f"; then
        green "✅ Signed: $f"
    else
        red "❌ GPG signing failed for $f"
        exit 1
    fi
done

# === Verify signatures ===
for f in $DIST_DIR/*.{whl,tar.gz}; do
    if gpg --verify "$f.asc" "$f"; then
        green "✅ Verified signature: $f.asc"
    else
        red "❌ Signature verification failed: $f.asc"
        exit 1
    fi

    # Print signing key fingerprint from packet
    SIGNER_FPR=$(gpg --list-packets "$f.asc" | awk '/signature packet/,/hashed subpkt/ { if ($1 == "issuer-fpr") print $2 }' | head -n1)
    if [ -n "$SIGNER_FPR" ]; then
        echo -e "\n📌 Signed by subkey fingerprint: $SIGNER_FPR\n"
    fi
done

# === Clean up temp README copy ===
rm -f "$TEMP_README"
rm -f "$TEMP_CHANGELOG"

# === Upload to PyPI if requested ===
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
    echo  "  ./release.sh --upload-to-pypi"
fi
