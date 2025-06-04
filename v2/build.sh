#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

# Exit on error
set -e

python3 -m venv venv
# Activate the virtual environment
source venv/bin/activate

# Use the venv's Python
PYTHON="$(which python3)"
PIP="$(which pip)"

echo "🔧 Installing project using pyproject.toml in venv: $VIRTUAL_ENV"

$PIP install --upgrade pip build hatch

# Build and install the project using pyproject.toml
$PYTHON -m build
LATEST_WHEEL=$(ls -t dist/dar_backup-*.whl | head -n1)
$PIP install "$LATEST_WHEEL" --upgrade --force-reinstall


# Optionally, for editable install:
# hatch install

echo "✅ Project build and install complete."


