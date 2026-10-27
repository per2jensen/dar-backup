"""Shared helpers for constructing real-DAR test fixtures."""

from __future__ import annotations

import os
from pathlib import Path


def dar_root_relative_selection(absolute_path: str) -> str:
    """Convert an absolute path into a DAR selection below ``-R /``.

    Args:
        absolute_path: Absolute filesystem path selected by a real-DAR test.

    Returns:
        Normalized root-relative path accepted by DAR's ``-g`` option.

    Raises:
        ValueError: If the input is empty, relative, or names the root itself.
    """
    if not isinstance(absolute_path, str) or not absolute_path.strip():
        raise ValueError("DAR test selection path must be a non-empty string")

    path = Path(os.path.normpath(absolute_path))
    if not path.is_absolute():
        raise ValueError(f"DAR test selection path must be absolute: {absolute_path}")

    relative = path.relative_to("/")
    if relative == Path("."):
        raise ValueError("DAR test selection path must not name the root directory")
    return relative.as_posix()
