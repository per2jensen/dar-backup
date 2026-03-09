#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Tests that restore verification actually validates file content, not just presence.

Two complementary tests:

1. test_restore_content_matches_source
   Runs a full backup, restores it, then calls verify_restored_matches_source()
   to do a byte-for-byte comparison between every original file in data_dir and
   its restored counterpart.  This confirms a healthy backup round-trip passes.

2. test_corrupt_restore_detected
   Same backup/restore, but then one restored file is silently overwritten with
   different content before the comparison runs.  The test asserts that
   verify_restored_matches_source() raises RuntimeError, proving the check
   would catch truncated or corrupted restored files that mere presence checks
   would miss.
"""

import os
import sys
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from tests.conftest import test_files
from tests.envdata import EnvData
from testdata_verification import (
    run_backup_script,
    verify_restore_contents,
    verify_restored_matches_source,
)


def test_restore_content_matches_source(setup_environment, env: EnvData):
    """A clean backup/restore round-trip passes byte-for-byte comparison."""
    run_backup_script("--full-backup", env)
    archive = f"example_FULL_{env.datestamp}"

    verify_restore_contents(test_files, archive, env)
    verify_restored_matches_source(list(test_files.keys()), env)


def test_corrupt_restore_detected(setup_environment, env: EnvData):
    """
    A restored file whose content differs from the source is caught by
    verify_restored_matches_source().

    This guards against silent truncation, zero-byte restores, or any other
    content-level failure that leaves the file present but wrong.
    """
    run_backup_script("--full-backup", env)
    archive = f"example_FULL_{env.datestamp}"

    verify_restore_contents(test_files, archive, env)

    # Silently overwrite one restored file with wrong content
    restored_dir = os.path.join(env.restore_dir, env.data_dir.lstrip("/"))
    corrupted_file = os.path.join(restored_dir, "file1.txt")
    with open(corrupted_file, "w") as f:
        f.write("THIS CONTENT WAS SILENTLY CORRUPTED")

    env.logger.info(f"Corrupted restored file: {corrupted_file}")

    with pytest.raises(RuntimeError, match="Content mismatch after restore"):
        verify_restored_matches_source(["file1.txt"], env)
