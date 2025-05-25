#!/usr/bin/env python3
# SPDF License: GPL-3.0 or later

"""
Create a Python virtual environment for the dar-backup project.
- If 'venv' exists, create 'venv-YYYYMMDD' or 'venv-YYYYMMDD-N' instead.
- Install required dependencies.
- Run build.sh so tests can be run immediately.
- Prints instructions for activating the venv and running tests.
"""

import os
import subprocess
from datetime import datetime

REQUIREMENTS = [
    "inputimeout",
    "build",
    "hatch",
    "hatchling",
    "pytest",
    "pytest-cov",
    "twine",
    "wheel",
    "psutil",
    "pytest-timeout",
    "argcomplete",
    "Jinja2",
    "black",
    "flake8",
    "isort"
]

def find_available_venv_name():
    base_name = "venv"
    if not os.path.exists(base_name):
        return base_name

    today = datetime.now().strftime("%Y%m%d")
    new_name = f"{base_name}-{today}"
    if not os.path.exists(new_name):
        return new_name

    counter = 1
    while True:
        numbered_name = f"{new_name}-{counter}"
        if not os.path.exists(numbered_name):
            return numbered_name
        counter += 1

def create_venv(venv_name):
    print(f"🔧 Creating virtual environment: {venv_name}")
    subprocess.run(["python3", "-m", "venv", venv_name], check=True)

def install_packages(venv_name):
    pip_path = os.path.join(venv_name, "bin", "pip")
    print("🔧 Installing required packages...")
    subprocess.run([pip_path, "install", "--upgrade", "pip"], check=True)
    subprocess.run([pip_path, "install"] + REQUIREMENTS, check=True)
    print("Installation complete.")

def run_build_script():
    print("🔧 Running build.sh to set up the project...")
    subprocess.run(["./build.sh"], check=True)
    print("build.sh completed.")

def main():
    venv_name = find_available_venv_name()
    create_venv(venv_name)
    install_packages(venv_name)
    run_build_script()

    print("\n\n✅ Virtual environment and project build complete")
    print(f"💡 To activate the virtual environment:\n  source {venv_name}/bin/activate")
    print("To run tests:\n  pytest")

if __name__ == "__main__":
    main()
