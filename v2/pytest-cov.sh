#! /bin/bash

#PYTHONPATH=src pytest --cov=src/dar_backup
PYTHONPATH=src pytest --rootdir=. 
coverage xml -o coverage.xml  --reporter lcovonly

