import os
import pytest
from dar_backup.util import get_binary_info
import dar_backup.util as util

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


def test_binary_info_not_found(monkeypatch):
    monkeypatch.setattr(util.shutil, "which", lambda _cmd: None)

    info = get_binary_info("missing-binary")

    assert info["path"] == "Not found"
    assert info["version"] == "unknown"
    assert info["full_output"] == ""


def test_binary_info_handles_run_exception(monkeypatch):
    monkeypatch.setattr(util.shutil, "which", lambda _cmd: "/bin/fake")

    def raise_oserror(*_args, **_kwargs):
        raise OSError("boom")

    monkeypatch.setattr(util.subprocess, "run", raise_oserror)

    info = get_binary_info("fake-binary")

    assert info["version"] == "error"
    assert "boom" in info["full_output"]
