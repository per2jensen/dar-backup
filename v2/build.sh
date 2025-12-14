#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

if [ ! -d venv ]; then
    python3 -m venv venv
fi
source venv/bin/activate

PYTHON="$(which python3)"
PIP="$(which pip)"

echo "🔧 Installing project in editable mode in venv: $VIRTUAL_ENV"
$PIP install --upgrade pip hatch
$PIP install -e .[dev]
echo "✅ Project installed in editable mode."

echo "🧹 Cleaning old build artifacts..."
rm -rf dist/* 2>/dev/null || true

echo "📦 Building installable packages (sdist + wheel)..."
hatch build --clean
echo "✅ Packages written to dist/:"
ls -1 dist
