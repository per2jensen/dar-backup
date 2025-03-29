#!/bin/bash

# === Usage Help ===
if [ -z "$1" ]; then
    echo "Usage: $0 <package-file>"
    echo
    echo "Verifies the GPG signature for a dar-backup release file."
    echo "The script assumes that the signature file is named <package-file>.asc."
    echo
    echo "Example:"
    echo "  $0 dist/dar_backup-0.6.18.tar.gz"
    echo
    echo "This requires that you have imported the public GPG key:"
    echo "  gpg --keyserver keyserver.ubuntu.com --recv-keys 1020C4FB8B79F1E0E151746AC9AF0C1DD2BD1C62"
    exit 1
fi

PACKAGE="$1"
SIG_FILE="${PACKAGE}.asc"

# === Check if both files exist ===
if [ ! -f "$PACKAGE" ]; then
    echo "❌ Error: Package file '$PACKAGE' not found."
    exit 2
fi

if [ ! -f "$SIG_FILE" ]; then
    echo "❌ Error: Signature file '$SIG_FILE' not found."
    exit 3
fi

# === Run GPG Verification ===
echo "🔍 Verifying GPG signature..."
gpg --verify "$SIG_FILE" "$PACKAGE"
GPG_RESULT=$?

if [ $GPG_RESULT -eq 0 ]; then
    echo "✅ Signature is valid."
else
    echo "❌ Signature verification failed!"
fi

exit $GPG_RESULT
