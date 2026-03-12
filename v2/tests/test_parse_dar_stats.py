# SPDX-License-Identifier: GPL-3.0-or-later
"""
Unit tests for parse_dar_stats().

Covers:
  - Happy path: all 12 fields parsed from real dar output
  - Partial output: missing fields → None (dar changed output format)
  - Empty / None input → all fields None
  - Values are int, not str
  - Negative: malformed numbers never crash the parser
"""

import pytest

from dar_backup.util import parse_dar_stats

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_DAR_SUMMARY = """\
 6581 inode(s) saved
   including 0 hard link(s) treated
 0 inode(s) changed at the moment of the backup and could not be saved properly
 0 byte(s) have been wasted in the archive to resave changing files
 0 inode(s) with only metadata changed
 24695 inode(s) not saved (no inode/file change)
 13 inode(s) failed to be saved (filesystem error)
 9 inode(s) ignored (excluded by filters)
 0 inode(s) recorded as deleted from reference backup
 --------------------------------------------
 Total number of inode(s) considered: 31298
 --------------------------------------------
 EA saved for 0 inode(s)
 FSA saved for 0 inode(s)
"""

_ALL_KEYS = [
    "inodes_saved",
    "hard_links_treated",
    "inodes_changed_during_backup",
    "bytes_wasted",
    "inodes_metadata_only",
    "inodes_not_saved",
    "inodes_failed",
    "inodes_excluded",
    "inodes_deleted",
    "inodes_total",
    "ea_saved",
    "fsa_saved",
]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_parse_dar_stats_returns_all_keys():
    """All 12 expected keys must be present in the result dict."""
    result = parse_dar_stats(_DAR_SUMMARY)
    for key in _ALL_KEYS:
        assert key in result, f"Missing key: {key}"


def test_parse_dar_stats_correct_values():
    """Parsed values must match the numbers in the sample output."""
    result = parse_dar_stats(_DAR_SUMMARY)
    assert result["inodes_saved"]                 == 6581
    assert result["hard_links_treated"]           == 0
    assert result["inodes_changed_during_backup"] == 0
    assert result["bytes_wasted"]                 == 0
    assert result["inodes_metadata_only"]         == 0
    assert result["inodes_not_saved"]             == 24695
    assert result["inodes_failed"]                == 13
    assert result["inodes_excluded"]              == 9
    assert result["inodes_deleted"]               == 0
    assert result["inodes_total"]                 == 31298
    assert result["ea_saved"]                     == 0
    assert result["fsa_saved"]                    == 0


def test_parse_dar_stats_values_are_int():
    """Every non-None value must be an int, not a str."""
    result = parse_dar_stats(_DAR_SUMMARY)
    for key, value in result.items():
        if value is not None:
            assert isinstance(value, int), f"{key}: expected int, got {type(value)}"


def test_parse_dar_stats_large_numbers():
    """Parser must handle large inode counts correctly."""
    output = (
        " 1234567 inode(s) saved\n"
        "   including 99999 hard link(s) treated\n"
        " Total number of inode(s) considered: 9999999\n"
    )
    result = parse_dar_stats(output)
    assert result["inodes_saved"]       == 1234567
    assert result["hard_links_treated"] == 99999
    assert result["inodes_total"]       == 9999999


# ---------------------------------------------------------------------------
# Graceful degradation — missing / changed output
# ---------------------------------------------------------------------------

def test_parse_dar_stats_empty_string_returns_all_none():
    """Empty string input must return all keys mapped to None."""
    result = parse_dar_stats("")
    for key in _ALL_KEYS:
        assert key in result
        assert result[key] is None, f"{key} should be None for empty input"


def test_parse_dar_stats_none_input_returns_all_none():
    """None input (e.g. dar never ran) must return all keys mapped to None."""
    result = parse_dar_stats(None)
    for key in _ALL_KEYS:
        assert result[key] is None


def test_parse_dar_stats_partial_output_missing_fields_are_none():
    """When only some lines are present, missing fields must be None, present ones parsed."""
    partial = (
        " 500 inode(s) saved\n"
        " Total number of inode(s) considered: 500\n"
    )
    result = parse_dar_stats(partial)
    assert result["inodes_saved"]  == 500
    assert result["inodes_total"]  == 500
    assert result["inodes_failed"] is None
    assert result["ea_saved"]      is None


def test_parse_dar_stats_unrecognised_format_all_none():
    """Completely different output (future dar format change) must not raise."""
    result = parse_dar_stats("no recognisable statistics here at all\n")
    for key in _ALL_KEYS:
        assert result[key] is None


def test_parse_dar_stats_extra_whitespace_handled():
    """dar sometimes varies spacing; patterns must be whitespace-tolerant."""
    output = (
        "   42   inode(s)   saved\n"
        "  including   7   hard   link(s)   treated\n"
    )
    result = parse_dar_stats(output)
    assert result["inodes_saved"]       == 42
    assert result["hard_links_treated"] == 7
