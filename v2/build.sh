#! /bin/bash

# Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

# THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
# not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See section 15 and section 16 in the supplied "LICENSE" file

#
# Build dar-backup and set version to contents of src/dar_backup/__about__.py
# Install in development virtual environment
#

if [ ! -e "$(realpath ./venv)" ]; then
    echo "Virtual environment not found (no ./venv)"
    echo "See doc/dev.md for instructions on setting up the virtual environment"
    exit 1
fi

if [ -z "$VIRTUAL_ENV" ] || [ "$VIRTUAL_ENV" != "$(realpath ./venv)" ]; then
    echo "Activating virtual environment in ./venv"
    source ./venv/bin/activate
fi

VERSION=$(cat src/dar_backup/__about__.py |grep -E -o  '[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+(\.[[:digit:]]+)?')

# the top level README.md is the maintained one. Copy it to this directory
cp ../README.md "${PWD}/README.md"

TEMP_README="src/dar_backup/README.md"
cp README.md "$TEMP_README"
TEMP_CHANGELOG="src/dar_backup/Changelog.md"
cp Changelog.md "$TEMP_CHANGELOG"


trap 'rm -f "$TEMP_README" "$TEMP_CHANGELOG"' EXIT

#python3 -m build && pip install --force-reinstall dist/dar_backup-"${VERSION}"-py3-none-any.whl

python3 -m build
pip install -e .

# cleanup
rm -f TEMP_README
rm -f TEMP_CHANGELOG

