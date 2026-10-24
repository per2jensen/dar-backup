"""Tests for opt-in percentage sampling and DAR slice coverage selection."""

from types import SimpleNamespace

import pytest

from dar_backup.dar_backup import build_restoretest_sampling_plan
from dar_backup.dar_backup import parse_slicing_listing_line
from dar_backup.dar_backup import select_slice_coverage_files


pytestmark = pytest.mark.unit


def _config(**overrides: object) -> SimpleNamespace:
    """Build the minimal configuration used by sampling helpers.

    Args:
        **overrides: Attribute values that replace the test defaults.

    Returns:
        A namespace containing restore-test configuration attributes.
    """
    values: dict[str, object] = {
        "min_size_verification_mb": 0,
        "max_size_verification_mb": 20,
        "no_files_verification": 5,
        "restoretest_exclude_prefixes": [],
        "restoretest_exclude_suffixes": [],
        "restoretest_exclude_regex": None,
        "restoretest_percent": 20.0,
        "restoretest_max_files": 100,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_build_restoretest_sampling_plan_percentage_exceeds_cap() -> None:
    """Round up the percentage target and apply the configured file cap."""
    backed_up_files = [
        (f"file-{index}.bin", "1 Mio")
        for index in range(1_001)
    ]

    plan = build_restoretest_sampling_plan(backed_up_files, _config())

    assert plan.eligible_files == 1_001
    assert plan.percentage_target == 201
    assert plan.capped_target == 100


def test_build_restoretest_sampling_plan_fixed_count_remains_minimum() -> None:
    """Retain NO_FILES_VERIFICATION when a small percentage rounds below it."""
    backed_up_files = [(f"file-{index}.bin", "1 Mio") for index in range(10)]

    plan = build_restoretest_sampling_plan(
        backed_up_files,
        _config(restoretest_percent=0.1),
    )

    assert plan.percentage_target == 1
    assert plan.capped_target == 5


def test_build_restoretest_sampling_plan_invalid_percentage_raises() -> None:
    """Reject invalid helper input even when configuration validation was bypassed."""
    with pytest.raises(ValueError, match="RESTORETEST_PERCENT"):
        build_restoretest_sampling_plan([], _config(restoretest_percent=0))


def test_parse_slicing_listing_line_saved_file_returns_path_and_range() -> None:
    """Parse a real-shaped DAR slicing row including spaces in the pathname."""
    line = "1-3\t [Saved][ ]       [-L-][     ][ ] -rw-rw-r-- dir/file with spaces.bin"

    parsed = parse_slicing_listing_line(line)

    assert parsed == ("dir/file with spaces.bin", frozenset({1, 2, 3}))


def test_parse_slicing_listing_line_directory_is_ignored() -> None:
    """Exclude directory metadata rows from restorable file-data coverage."""
    line = "1\t [Saved][-]       [-L-][   0%][ ] drwxr-xr-x dir"

    assert parse_slicing_listing_line(line) is None


def test_parse_slicing_listing_line_malformed_range_raises() -> None:
    """Fail closed when a saved regular-file row has an unknown slice field."""
    line = "unknown\t [Saved][ ]       [-L-][     ][ ] -rw-r--r-- file.bin"

    with pytest.raises(ValueError, match="Invalid DAR slice range"):
        parse_slicing_listing_line(line)


def test_select_slice_coverage_files_adds_minimum_covering_files() -> None:
    """Add files that cover remaining slices while preferring fewer files."""
    eligible = {
        "one.bin": ("/one.bin", 100),
        "two.bin": ("/two.bin", 200),
        "three.bin": ("/three.bin", 50),
    }
    slice_map = {
        "one.bin": frozenset({1, 2}),
        "two.bin": frozenset({2, 3}),
        "three.bin": frozenset({4}),
    }

    coverage = select_slice_coverage_files(eligible, ["/one.bin"], slice_map)

    assert set(coverage.additional_files) == {"/two.bin", "/three.bin"}
    assert coverage.data_slices == frozenset({1, 2, 3, 4})
    assert coverage.covered_slices == coverage.data_slices
    assert coverage.unavailable_slices == frozenset()


def test_select_slice_coverage_files_reports_filtered_slice_unavailable() -> None:
    """Report a data slice that can only be reached through an ineligible file."""
    eligible = {"eligible.bin": ("eligible.bin", 100)}
    slice_map = {
        "eligible.bin": frozenset({1}),
        "filtered.bin": frozenset({2}),
    }

    coverage = select_slice_coverage_files(eligible, [], slice_map)

    assert coverage.additional_files == ("eligible.bin",)
    assert coverage.covered_slices == frozenset({1})
    assert coverage.unavailable_slices == frozenset({2})
