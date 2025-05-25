import glob
import os
import pathlib
import subprocess
import sys
import tempfile
import shutil
import re
from datetime import datetime
import pytest
from unittest.mock import patch

import importlib.util



print(f"DEBUG: os.getcwd() = {os.getcwd()}")
print(f"DEBUG: pytest __file__ = {__file__}")
print(f"DEBUG: setup_environment.py exists? {os.path.exists('setup_environment.py')}")



import os
import pathlib
import importlib.util
import pytest

@pytest.fixture
def setup_env_script():
    # Find setup_environment.py relative to this test file
    this_file = pathlib.Path(__file__).resolve()
    project_root = this_file.parent.parent
    target = project_root / "setup_environment.py"
    print(f"DEBUG: Looking for {target}")
    if not target.exists():
        pytest.skip(f"setup_environment.py not found at {target}")
    
    # Dynamically import the script
    spec = importlib.util.spec_from_file_location("setup_environment", str(target))
    setup_environment = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup_environment)
    return setup_environment


def test_find_available_venv_name_basic(tmp_path, setup_env_script):

    os.chdir(tmp_path)
    assert setup_env_script.find_available_venv_name() == "venv"

    # Create venv
    (tmp_path / "venv").mkdir()
    name = setup_env_script.find_available_venv_name()
    today = datetime.now().strftime("%Y%m%d")
    assert name == f"venv-{today}"

    # Create venv-YYYYMMDD
    (tmp_path / f"venv-{today}").mkdir()
    name = setup_env_script.find_available_venv_name()
    assert name == f"venv-{today}-1"

    # Create venv-YYYYMMDD-1
    (tmp_path / f"venv-{today}-1").mkdir()
    name = setup_env_script.find_available_venv_name()
    assert name == f"venv-{today}-2"


@patch("subprocess.run")
def test_create_venv(mock_run, tmp_path, setup_env_script):
    venv_name = tmp_path / "myvenv"
    setup_env_script.create_venv(str(venv_name))
    mock_run.assert_called_once_with(
        ["python3", "-m", "venv", str(venv_name)],
        check=True
    )


@patch("subprocess.run")
def test_install_packages(mock_run, tmp_path, setup_env_script):
    venv_dir = tmp_path / "venv"
    bin_dir = venv_dir / "bin"
    bin_dir.mkdir(parents=True)
    pip_path = bin_dir / "pip"
    pip_path.write_text("# mock pip")

    setup_env_script.install_packages(str(venv_dir))

    # First call upgrades pip
    assert mock_run.call_args_list[0][0][0] == [str(pip_path), "install", "--upgrade", "pip"]
    # Second call installs the required packages
    expected_packages = [str(pip_path), "install"] + setup_env_script.REQUIREMENTS
    assert mock_run.call_args_list[1][0][0] == expected_packages


@patch("subprocess.run")
def test_run_build_script(mock_run, setup_env_script):
    setup_env_script.run_build_script()
    mock_run.assert_called_once_with(["./build.sh"], check=True)


@patch("subprocess.run")
def test_main_flow(mock_run, tmp_path, setup_env_script):
    # Create a dummy build.sh to prevent error
    (tmp_path / "build.sh").write_text("#!/bin/bash\necho done\n")
    os.chmod(tmp_path / "build.sh", 0o755)
    os.chdir(tmp_path)

    with patch.object(setup_env_script, "create_venv") as mock_create, \
         patch.object(setup_env_script, "install_packages") as mock_install, \
         patch.object(setup_env_script, "run_build_script") as mock_build:
        setup_env_script.main()
        mock_create.assert_called_once()
        mock_install.assert_called_once()
        mock_build.assert_called_once()

