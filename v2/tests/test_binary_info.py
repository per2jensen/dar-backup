import os
import pytest
from dar_backup.util import get_binary_info 
from tests.envdata import EnvData

@pytest.mark.parametrize("binary_name", ["dar", "dar_manager"])
def test_binary_path_exists_and_executable(binary_name):
    info = get_binary_info(binary_name)

    #print(f"DEBUG:  Binary info: {info}")

    # Check that the binary was found
    assert info["path"] != "Not found", f"{binary_name} not found in PATH"
    
    # Check that the path is a valid file and executable
    assert os.path.isfile(info["path"]), f"{binary_name} path is not a file: {info['path']}"
    assert os.access(info["path"], os.X_OK), f"{binary_name} is not executable: {info['path']}"


@pytest.mark.parametrize("binary_name", ["dar", "dar_manager"])
def test_binary_version_detected_and_valid(binary_name, env):
    info = get_binary_info(binary_name)
    
    # Ensure version info was extracted correctly
    assert info["version"] not in ("unknown", "error"), f"{binary_name} version extraction failed: {info['version']}"
    
    # Optionally ensure version contains numeric values
    assert any(char.isdigit() for char in info["version"]), f"{binary_name} version string looks invalid: {info['version']}"
