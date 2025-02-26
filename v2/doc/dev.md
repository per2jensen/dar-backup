# Dev snippets

## Activate the venv

```` bash
cd <path/to/dar-backup/v2>
. venv/bin/activate
````

## Setup venv

```` bash
pip install build hatch hatchling pytest twine wheel
````

## build, deploy to dev venv

Make sure __about__.py has the correct version number

```` bash
VERSION=$(cat src/dar_backup/__about__.py |grep -E -o  '[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+(\.[[:digit:]]+)?')
python3 -m build && pip install --force-reinstall dist/dar_backup-${VERSION}-py3-none-any.whl
````

## use pytest in venv

A pytest.ini is located in the v2 directory, so that pytest writes out captures to  console.

That is useful when working with a single test and is the default

```` bash
pytest
````

If you do not want that a empty ini file is also there: pytest-minimal.ini.
Use use to get the minimal info on successful test cases

```` bash
pytest -c pytest-minimal.ini
````

or

```` bash
pytest -c pytest-minimal.ini tests/test_verbose.py
````

## Upload to PyPI

```` bash
twine upload dist/<wheel package>
````

## Git log

```` bash
git log --pretty=format:"%ad - %an: %s %d" --date=short
````
