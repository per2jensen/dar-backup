#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

if [ ! -d venv ]; then
    python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate

PIP="$(which pip)"

echo "🔧 Installing project in editable mode in venv: $VIRTUAL_ENV"
$PIP install --upgrade pip hatch
$PIP install -e .[dev]
echo "✅ Project installed in editable mode."

echo "🧹 Cleaning old build artifacts..."
rm -rf dist/* 2>/dev/null || true

echo "📄 Copying docs into package for wheel inclusion..."
trap 'rm -f src/dar_backup/README.md src/dar_backup/Changelog.md; rm -f src/dar_backup/doc/*.md 2>/dev/null; rmdir src/dar_backup/doc 2>/dev/null || true' EXIT
bash scripts/copy_docs.sh

echo "📦 Building installable packages (sdist + wheel)..."
hatch build --clean
echo "✅ Packages written to dist/:"
ls -1 dist
