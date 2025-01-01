

# First
````
cd <path/to/dar-backup/v2>
. venv/bin/activate
````


# build, deploy to dev venv

Update __about__.py first

````
python3 -m build

pip install --force-reinstall dist/<wheel package> 

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

