#!/usr/bin/env bash

# Determine virtual environment directory
if [ -n "$VIRTUAL_ENV" ]; then
    # Already activated – use that!
    VENV_DIR="$VIRTUAL_ENV"
    echo "Detected active virtual environment: $VENV_DIR"
else
    # No venv activated – fallback to VENV_DIR variable or 'venv'
    VENV_DIR="${VENV_DIR:-venv}"
    echo "Using virtual environment directory: $VENV_DIR"

    if [ ! -d "$VENV_DIR" ]; then
        echo "Virtual environment not found ($VENV_DIR)"
        echo "See doc/dev.md for instructions on setting up the virtual environment"
        exit 1
    fi

    echo "Activating virtual environment: $VENV_DIR"
    source "$VENV_DIR/bin/activate"
fi

# Continue with your build...
VERSION=$(grep -E -o  '[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+(\.[[:digit:]]+)?' src/dar_backup/__about__.py)

cp ../README.md README.md
TEMP_README="src/dar_backup/README.md"
cp README.md "$TEMP_README"
TEMP_CHANGELOG="src/dar_backup/Changelog.md"
cp Changelog.md "$TEMP_CHANGELOG"

trap 'rm -f "$TEMP_README" "$TEMP_CHANGELOG"' EXIT

python3 -m build
pip install -e .

echo "✅ Build and install complete using virtual environment: $VENV_DIR"
