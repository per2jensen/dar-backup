#! /bin/bash

# Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

# THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
# not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See section 15 and section 16 in the supplied "LICENSE" file

#
# Run all pytest tests in tests/ directory
#

if [ -z "$VIRTUAL_ENV" ] || [ "$VIRTUAL_ENV" != "$(realpath ./venv)" ]; then
    echo "Activating virtual environment in ./venv"
    source ./venv/bin/activate
fi

pytest -c pytest-minimal.ini tests/