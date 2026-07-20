"""Real DAR coverage for PITR multi-slice completeness validation."""

import logging
import os
import subprocess
from pathlib import Path

import pytest

from dar_backup.command_runner import CommandRunner
from dar_backup.manager import _pitr_archive_sequence_error
from dar_backup.manager import _pitr_archive_validation_error
from dar_backup.util import inspect_archive_slices


pytestmark = pytest.mark.integration


@pytest.fixture
def real_multislice_archive(tmp_path: Path) -> str:
    """Create a real DAR archive containing at least three slices.

    Args:
        tmp_path: Pytest-owned temporary directory.

    Returns:
        Archive base path without a slice suffix.
    """
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    payload = bytes(range(256)) * 200
    (source_dir / "payload.bin").write_bytes(payload)
    archive_base = str(tmp_path / "example_FULL_2026-01-01")

    result = subprocess.run(  # noqa: S603 — fixed local DAR command used by an integration test
        [
            "dar", "-c", archive_base, "-R", str(source_dir),
            "-q", "-Q", "-w", "-s", "10k", "-N",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert len(inspect_archive_slices(archive_base).slice_paths) >= 3
    return archive_base


def _command_runner() -> CommandRunner:
    """Create a quiet real CommandRunner for DAR catalogue probes.

    Returns:
        CommandRunner with in-memory null loggers and a short timeout.
    """
    test_logger = logging.getLogger("test_pitr_slice_validation")
    test_logger.handlers = [logging.NullHandler()]
    command_logger = logging.getLogger("test_pitr_slice_validation.command")
    command_logger.handlers = [logging.NullHandler()]
    return CommandRunner(
        logger=test_logger,
        command_logger=command_logger,
        default_timeout=30,
    )


def test_pitr_archive_validation_complete_multislice_returns_none(
    real_multislice_archive: str,
) -> None:
    """A complete real multi-slice archive passes PITR validation."""
    error = _pitr_archive_validation_error(
        real_multislice_archive,
        _command_runner(),
        30,
        None,
    )

    assert error is None


def test_pitr_archive_validation_missing_interior_slice_returns_error(
    real_multislice_archive: str,
) -> None:
    """Removing slice two is rejected before DAR extraction can run."""
    os.rename(
        f"{real_multislice_archive}.2.dar",
        f"{real_multislice_archive}.2.dar.hidden",
    )

    error = _pitr_archive_validation_error(
        real_multislice_archive,
        _command_runner(),
        30,
        None,
    )

    assert error is not None
    assert "missing slice number(s) 2" in error


def test_pitr_archive_validation_missing_final_slice_returns_error(
    real_multislice_archive: str,
) -> None:
    """DAR's catalogue probe rejects a contiguous set missing its final slice."""
    inventory = inspect_archive_slices(real_multislice_archive)
    final_slice = inventory.slice_paths[-1]
    os.rename(final_slice, f"{final_slice}.hidden")

    assert _pitr_archive_sequence_error(real_multislice_archive) is None
    error = _pitr_archive_validation_error(
        real_multislice_archive,
        _command_runner(),
        30,
        None,
    )

    assert error is not None
    assert "failed the DAR final-slice catalogue check" in error
    assert "dar -l rc=" in error
