#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

set -e

python3 -m venv venv
source venv/bin/activate

PYTHON="$(which python3)"
PIP="$(which pip)"

echo "🔧 Installing project in editable mode in venv: $VIRTUAL_ENV"

$PIP install --upgrade pip hatch

# Editable install with dev dependencies
$PIP install -e .[dev]

echo "✅ Project installed in editable mode."
