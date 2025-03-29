#!/bin/bash

# Build, sign, verify and upload the dar-backup package to PyPI
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
    echo "Once installed, make sure to configure GnuPG to use it by running:"
    echo "    echo 'pinentry-program /usr/bin/pinentry-tty' >> ~/.gnupg/gpg-agent.conf"
    echo "    gpgconf --kill gpg-agent"
    exit 1
fi

# === Configuration ===
VENV_DIR="./venv"
DIST_DIR="dist"
PACKAGE_NAME="dar_backup"
KEY_ID=dar-backup@pm.me

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
PACKAGE_FILE="$DIST_DIR/${PACKAGE_NAME}-${VERSION}-py3-none-any.whl"

# === Build the package ===
rm -rf "$DIST_DIR"
python3 -m build

# === Sign distributions ===
for f in $DIST_DIR/*.{whl,tar.gz}; do
    SIGN_CMD=(gpg --batch --yes --detach-sign -a)
    [ -n "$KEY_ID" ] && SIGN_CMD+=(--local-user "$KEY_ID")

    if "${SIGN_CMD[@]}" "$f"; then
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
done

# === Upload to PyPI ===
green "📦 Uploading to PyPI..."


#twine upload $DIST_DIR/*

#green "🎉 Done: Version $VERSION uploaded successfully"
