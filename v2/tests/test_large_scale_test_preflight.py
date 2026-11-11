"""Integration tests for the large-scale test script preflight."""

# pytest assertions intentionally use assert for failure introspection.
# ruff: noqa: S101

from __future__ import annotations

import configparser
import os
import subprocess
from pathlib import Path

import pytest


PROJECT_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_DIR = PROJECT_DIR.parent
SCRIPT_PATH = PROJECT_DIR / "scripts" / "large_scale_test.sh"
VENV_DIR = PROJECT_DIR / "venv"


def _generated_config_template() -> configparser.ConfigParser:
    """Parse the configuration template emitted by ``write_config``.

    Returns:
        Parsed configuration containing the literal shell template values.

    Raises:
        ValueError: If the generated configuration heredoc cannot be located.
    """
    lines = SCRIPT_PATH.read_text(encoding="utf-8").splitlines()
    function_start = 'write_config() {'
    heredoc_start = '    cat > "$CONFIG_FILE" << EOF'

    try:
        function_index = lines.index(function_start)
        config_start = lines.index(heredoc_start, function_index) + 1
        config_end = lines.index("EOF", config_start)
    except ValueError as error:
        raise ValueError("write_config heredoc was not found") from error

    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string("\n".join(lines[config_start:config_end]))
    return parser


def _preflight_environment() -> dict[str, str]:
    """Return an environment selecting the project's real virtualenv.

    Returns:
        A fresh environment mapping with the project virtualenv activated.

    Raises:
        ValueError: If the project virtualenv is unavailable.
    """
    venv_bin = VENV_DIR / "bin"
    if not (venv_bin / "python3").is_file():
        raise ValueError(f"Project virtualenv is unavailable: {VENV_DIR}")

    environment = os.environ.copy()
    environment["VIRTUAL_ENV"] = str(VENV_DIR)
    environment["PATH"] = f"{venv_bin}{os.pathsep}{environment['PATH']}"
    return environment


def _run_preflight(environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run the real large-scale preflight from outside the v2 directory.

    Args:
        environment: Environment mapping passed to the subprocess.

    Returns:
        The completed script process.

    Raises:
        ValueError: If the environment mapping is empty.
    """
    if not environment:
        raise ValueError("environment must not be empty")

    # The executable and every argument are repository-controlled constants.
    return subprocess.run(  # noqa: S603
        [
            str(SCRIPT_PATH),
            "--preflight-only",
            "--definition",
            "-R /data\n-g test-data",
        ],
        cwd=REPOSITORY_DIR,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.component
def test_large_scale_generated_config_enables_three_percent_and_slice_coverage() -> None:
    """Verify the generated config selects 3% and covers all data slices.

    Returns:
        None.
    """
    config = _generated_config_template()

    assert config.getfloat("MISC", "RESTORETEST_PERCENT") == 3.0
    assert config.getboolean("MISC", "RESTORETEST_COVER_SLICES") is True


@pytest.mark.component
def test_large_scale_generated_config_does_not_use_default_sample_cap() -> None:
    """Verify the old 100-file cap cannot truncate the intended 3% sample.

    Returns:
        None.
    """
    config = _generated_config_template()
    maximum_files = config.getint("MISC", "RESTORETEST_MAX_FILES")

    assert maximum_files == 1000
    assert maximum_files != 100


@pytest.mark.component
def test_large_scale_help_from_repository_root_succeeds() -> None:
    """Verify help remains available after changing to the project directory.

    Returns:
        None.
    """
    result = subprocess.run(  # noqa: S603
        [str(SCRIPT_PATH), "--help"],
        cwd=REPOSITORY_DIR,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "large_scale_test.sh" in result.stdout


@pytest.mark.component
def test_large_scale_preflight_from_repository_root_succeeds() -> None:
    """Verify preflight resolves v2 paths from the repository root.

    Returns:
        None.
    """
    result = _run_preflight(_preflight_environment())

    assert result.returncode == 0, result.stderr
    assert "Preflight checks passed." in result.stdout


@pytest.mark.component
def test_large_scale_preflight_non_editable_install_reports_error(
    tmp_path: Path,
) -> None:
    """Verify preflight clearly rejects a non-editable installation.

    Args:
        tmp_path: Fresh directory used for the fake pip executable.

    Returns:
        None.
    """
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_pip = fake_bin / "pip"
    fake_pip.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf '%s\\n' 'Name: dar-backup' 'Version: 1.1.12' "
        "'Location: /tmp/site-packages'\n",
        encoding="utf-8",
    )
    fake_pip.chmod(0o755)

    environment = _preflight_environment()
    environment["PATH"] = (
        f"{fake_bin}{os.pathsep}{VENV_DIR / 'bin'}"
        f"{os.pathsep}{environment['PATH']}"
    )
    result = _run_preflight(environment)

    assert result.returncode == 1
    assert "ERROR: dar-backup is not installed in editable mode" in result.stdout
