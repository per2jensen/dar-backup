"""Tests for shared real-DAR fixture helpers."""

from __future__ import annotations

from typing import cast

import pytest

from tests.dar_test_helpers import dar_root_relative_selection


@pytest.mark.parametrize(
    ("absolute_path", "expected"),
    [
        ("/tmp/pytest/data", "tmp/pytest/data"),
        ("/home/ubuntu/vm-work/data", "home/ubuntu/vm-work/data"),
        ("/var/lib/example/../payload", "var/lib/payload"),
    ],
)
def test_dar_root_relative_selection_absolute_path_returns_relative_selection(
    absolute_path: str,
    expected: str,
) -> None:
    """Absolute selections must work independently of their top-level directory.

    Args:
        absolute_path: Absolute test input.
        expected: Expected DAR root-relative selection.

    Returns:
        None.
    """
    assert dar_root_relative_selection(absolute_path) == expected


@pytest.mark.parametrize(
    "invalid_path",
    ["", "   ", "relative/data", "/", None, 42],
)
def test_dar_root_relative_selection_invalid_path_raises_value_error(
    invalid_path: object,
) -> None:
    """Empty, relative, and root-only selections must fail closed.

    Args:
        invalid_path: Invalid selection input.

    Returns:
        None.
    """
    with pytest.raises(ValueError, match="DAR test selection path"):
        dar_root_relative_selection(cast(str, invalid_path))
