

# First
````
cd <path/to/dar-backup/v2>
. venv/bin/activate
````


# build, deploy to dev venv

Update __about__.py first

````
python3 -m build

VERSION=$(cat src/dar_backup/__about__.py |grep -E -o  '[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+')
python3 -m build && pip install --force-reinstall dist/dar_backup-${VERSION}-py3-none-any.whl


````
Venv packages:
````
pip install  build hatch hatchling pytest twine wheel
````



# use pytest in venv
````
pytest

````


# how to run a single pytest test case
````
pytest tests/test_verbose.py
````




# Upload to PyPI
````
twine upload dist/<wheel package
````


# Git log

git log --pretty=format:"%ad - %an: %s %d" --date=short