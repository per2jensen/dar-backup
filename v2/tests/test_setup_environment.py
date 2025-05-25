# SPDX-License-Identifier: GPL-3.0-or-later

"""
Tests for the setup_environment.py helper module in the dar-backup project.

This module verifies:
- Finding a unique virtual environment name
- Creating virtual environments
- Installing required Python packages
- Running a build script
- End-to-end execution of the main setup flow
- Ensuring build.sh runs in the new venv

All tests rely on a dynamically loaded setup_environment.py script.
"""

import glob
import os
import subprocess
import sys
import tempfile
import shutil
import re
from datetime import datetime
import pytest
from unittest.mock import patch
import importlib.util
import pathlib

@pytest.fixture
def setup_env_script():
    """
    Fixture to dynamically load the setup_environment.py module
    from the project root directory.

    It resolves the absolute path to ensure robustness regardless
    of the working directory during test execution.
    
    Skips the tests if the script is not found.
    """
    import pathlib

    # Determine project root
    this_file = pathlib.Path(__file__).resolve()
    project_root = this_file.parent.parent
    target = project_root / "setup_environment.py"
    print(f"DEBUG: Looking for {target}")
    if not target.exists():
        pytest.skip(f"setup_environment.py not found at {target}")

    # Load the module dynamically
    spec = importlib.util.spec_from_file_location("setup_environment", str(target))
    setup_environment = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup_environment)
    return setup_environment

def test_find_available_venv_name_basic(tmp_path, setup_env_script):
    """
    Test the logic for generating a unique virtual environment name.
    """
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
    """
    Test creating a virtual environment using setup_environment.create_venv.
    """
    venv_name = tmp_path / "myvenv"
    setup_env_script.create_venv(str(venv_name))
    mock_run.assert_called_once_with(
        ["python3", "-m", "venv", str(venv_name)],
        check=True
    )

@patch("subprocess.run")
def test_install_packages(mock_run, tmp_path, setup_env_script):
    """
    Test installing required packages into a virtual environment.
    """
    venv_dir = tmp_path / "venv"
    bin_dir = venv_dir / "bin"
    bin_dir.mkdir(parents=True)
    pip_path = bin_dir / "pip"
    pip_path.write_text("# mock pip")

    setup_env_script.install_packages(str(venv_dir))

    # First call upgrades pip
    assert mock_run.call_args_list[0][0][0] == [str(pip_path), "install", "--upgrade", "pip"]
    # Second call installs required packages
    expected_packages = [str(pip_path), "install"] + setup_env_script.REQUIREMENTS
    assert mock_run.call_args_list[1][0][0] == expected_packages


@patch("subprocess.run")
def test_run_build_script(mock_run, setup_env_script):
    """
    Test that the build script is invoked properly and uses the new venv's environment.
    """
    setup_env_script.run_build_script("venv-name")
    
    # Ensure subprocess.run was called once
    assert mock_run.call_count == 1

    # Grab the arguments used
    call_args = mock_run.call_args
    assert call_args[0][0] == ["./build.sh"]
    assert call_args[1]["check"] is True

    # Check that the environment contains VIRTUAL_ENV
    env = call_args[1]["env"]
    assert "VIRTUAL_ENV" in env


@patch("subprocess.run")
def test_main_flow(mock_run, tmp_path, setup_env_script):
    """
    End-to-end test of the main() method in setup_environment.py.
    """
    # Create a dummy build.sh script
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

def test_run_build_script_in_venv(tmp_path, setup_env_script):
    """
    Integration test: ensures build.sh runs in the newly created venv.
    """
    os.chdir(tmp_path)
    # Create a dummy build.sh that logs which Python is used
    (tmp_path / "build.sh").write_text(
        "#!/usr/bin/env bash\n"
        "echo \"Using Python: $(which python)\" > build.log\n"
    )
    os.chmod(tmp_path / "build.sh", 0o755)

    # Run the full flow
    setup_env_script.main()

    # Find the latest venv created
    venvs = sorted([d for d in os.listdir() if d.startswith("venv") and os.path.isdir(d)])
    latest_venv = venvs[-1]
    venv_python = os.path.abspath(os.path.join(latest_venv, "bin", "python"))

    # Check build.log
    log_content = (tmp_path / "build.log").read_text().strip()
    assert venv_python in log_content, f"build.sh did not use the venv's Python! Expected {venv_python}."
