# SPDX-License-Identifier: GPL-3.0-or-later
"""
Verify that dar's inode-summary output is identical under LC_ALL=C and
LANG=en_US.UTF-8.  This guards against a future dar release switching to
locale-sensitive number formatting, which would silently break parse_dar_stats().
"""

import os
import re
import subprocess
import tempfile

import pytest

pytestmark = pytest.mark.component

_SUMMARY_RE = re.compile(
    r"-{20,}.*?Total number of inode\(s\) considered:.*?-{20,}",
    re.DOTALL,
)


def _run_dar_backup(src_dir: str, archive_base: str, env: dict) -> str:
    """
    Create a dar archive of *src_dir* and return the combined stdout+stderr.

    Args:
        src_dir: Directory to back up.
        archive_base: Base path for the archive (without .1.dar suffix).
        env: Environment variables for the subprocess.

    Returns:
        Combined stdout and stderr output from dar.

    Raises:
        pytest.skip: If dar is not found on PATH.
    """
    dar = "/usr/local/bin/dar"
    if not os.path.exists(dar):
        pytest.skip("dar not found at /usr/local/bin/dar")

    result = subprocess.run(
        [dar, "-c", archive_base, "-R", src_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=env,
        text=True,
    )
    return result.stdout + result.stderr


def _extract_summary(output: str) -> str:
    """
    Extract the inode summary block from dar output.

    Args:
        output: Raw dar output string.

    Returns:
        The matched summary block, or the full output if no block found.
    """
    m = _SUMMARY_RE.search(output)
    return m.group(0) if m else output


def test_dar_summary_identical_under_c_and_en_us_locale(tmp_path):
    """
    dar's inode summary must be byte-for-byte identical when run under
    LC_ALL=C and LANG=en_US.UTF-8.  A difference would mean dar switched
    to locale-sensitive number formatting, which would break parse_dar_stats().
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("hello")
    (src / "b.txt").write_text("world")

    base_env = {k: v for k, v in os.environ.items() if k not in ("LANG", "LC_ALL", "LC_NUMERIC")}

    env_c = {**base_env, "LC_ALL": "C"}
    env_us = {**base_env, "LANG": "en_US.UTF-8"}

    with tempfile.TemporaryDirectory() as td:
        out_c  = _run_dar_backup(str(src), os.path.join(td, "archive_c"),  env_c)
        out_us = _run_dar_backup(str(src), os.path.join(td, "archive_us"), env_us)

    summary_c  = _extract_summary(out_c)
    summary_us = _extract_summary(out_us)

    assert summary_c == summary_us, (
        "dar inode summary differs between LC_ALL=C and LANG=en_US.UTF-8.\n"
        f"LC_ALL=C output:\n{summary_c}\n\n"
        f"LANG=en_US.UTF-8 output:\n{summary_us}"
    )
