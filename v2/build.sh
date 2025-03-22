#! /bin/bash

# Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

# THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
# not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See section 15 and section 16 in the supplied "LICENSE" file

#
# Build dar-backup and set version to contents of src/dar_backup/__about__.py
# Install in development virtual environment
#

if [ -z "$VIRTUAL_ENV" ] || [ "$VIRTUAL_ENV" != "$(realpath ./venv)" ]; then
    echo "Activating virtual environment in ./venv"
    source ./venv/bin/activate
fi

VERSION=$(cat src/dar_backup/__about__.py |grep -E -o  '[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+(\.[[:digit:]]+)?')


python3 -m build && pip install --force-reinstall dist/dar_backup-"${VERSION}"-py3-none-any.whl