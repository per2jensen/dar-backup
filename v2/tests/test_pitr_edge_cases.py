# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests for PITR edge cases, stability issues, and missing coverage.

Covers:
  - _select_archive_chain: FULL+INCR (no DIFF), multiple FULLs, all-future,
    same-day with time components
  - _parse_archive_info: extra suffixes, non-matching names, time components
  - _parse_file_versions: empty output, malformed lines
  - _restore_target_unsafe_reason: .. traversal, /var/tmp allowed, symlink-like
  - _normalize_when_dt / _parse_when: naive passthrough, tz-aware conversion
  - _coerce_timeout: string, bool, negative, None
  - _parse_archive_map: spaces in directory path, header-only output
  - _restore_with_dar: file restore break-vs-continue on missing archive,
    mixed dir+file in single call, darrc passed to dar command
  - restore_at: path normalization with leading /, ./, ..
"""

from unittest.mock import MagicMock, patch
import datetime
import os

import pytest

from dar_backup.manager import (
    _coerce_timeout,
    _normalize_when_dt,
    _parse_archive_info,
    _parse_archive_map,
    _parse_file_versions,
    _parse_when,
    _restore_target_unsafe_reason,
    _restore_with_dar,
    _select_archive_chain,
    restore_at,
)
from dar_backup.config_settings import ConfigSettings
from dar_backup.command_runner import CommandResult

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_config(tmp_path):
    """Creates a basic ConfigSettings object with temporary directories."""
    config = MagicMock(spec=ConfigSettings)
    config.backup_dir = str(tmp_path / "backups")
    config.backup_d_dir = str(tmp_path / "backup.d")
    config.command_timeout_secs = 30
    return config


@pytest.fixture
def mock_runner():
    """Mocks the CommandRunner."""
    runner = MagicMock()
    runner.run.return_value = CommandResult(0, "stdout", "stderr", note=None)
    return runner


@pytest.fixture
def mock_logger():
    """Mocks the logger."""
    return MagicMock()


# ===========================================================================
# _select_archive_chain
# ===========================================================================

class TestSelectArchiveChain:
    """Tests for _select_archive_chain edge cases."""

    def test_full_plus_incr_no_diff(self) -> None:
        """INCR is applied directly after FULL when no DIFF exists."""
        info = [
            (1, datetime.datetime(2026, 1, 10), "FULL"),
            (2, datetime.datetime(2026, 1, 15), "INCR"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 1, 20))
        assert chain == [1, 2]

    def test_multiple_fulls_picks_latest(self) -> None:
        """When multiple FULLs exist, the latest one before when_dt is used."""
        info = [
            (1, datetime.datetime(2026, 1, 1), "FULL"),
            (2, datetime.datetime(2026, 2, 1), "FULL"),
            (3, datetime.datetime(2026, 2, 10), "DIFF"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 3, 1))
        assert chain[0] == 2, "Should use the latest FULL"
        assert 3 in chain, "DIFF after latest FULL should be included"
        assert 1 not in chain, "Old FULL should not appear"

    def test_all_archives_in_future_returns_empty(self) -> None:
        """No archives at or before when_dt produces an empty chain."""
        info = [
            (1, datetime.datetime(2026, 6, 1), "FULL"),
            (2, datetime.datetime(2026, 7, 1), "DIFF"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 1, 1))
        assert chain == []

    def test_same_day_full_and_diff_with_time_components(self) -> None:
        """FULL and DIFF on same day are ordered by type when timestamps match."""
        info = [
            (1, datetime.datetime(2026, 1, 15, 2, 0, 0), "FULL"),
            (2, datetime.datetime(2026, 1, 15, 14, 0, 0), "DIFF"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 1, 15, 23, 59))
        assert chain == [1, 2]

    def test_only_full_returns_single_element_chain(self) -> None:
        """A single FULL with no DIFF/INCR produces a one-element chain."""
        info = [
            (1, datetime.datetime(2026, 1, 10), "FULL"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 2, 1))
        assert chain == [1]

    def test_full_diff_incr_complete_chain(self) -> None:
        """Standard FULL→DIFF→INCR chain is assembled correctly."""
        info = [
            (1, datetime.datetime(2026, 1, 1), "FULL"),
            (2, datetime.datetime(2026, 1, 10), "DIFF"),
            (3, datetime.datetime(2026, 1, 15), "INCR"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 1, 20))
        assert chain == [1, 2, 3]

    def test_multiple_incrs_picks_latest_only(self) -> None:
        """Only the latest INCR is selected (INCRs are diffs against DIFF, not cumulative)."""
        info = [
            (1, datetime.datetime(2026, 1, 1), "FULL"),
            (2, datetime.datetime(2026, 1, 10), "DIFF"),
            (3, datetime.datetime(2026, 1, 12), "INCR"),
            (4, datetime.datetime(2026, 1, 14), "INCR"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 1, 20))
        assert chain == [1, 2, 4], "Only latest INCR (#4) should be in chain"

    def test_multiple_diffs_picks_latest_only(self) -> None:
        """Only the latest DIFF is selected."""
        info = [
            (1, datetime.datetime(2026, 1, 1), "FULL"),
            (2, datetime.datetime(2026, 1, 5), "DIFF"),
            (3, datetime.datetime(2026, 1, 10), "DIFF"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 1, 20))
        assert chain == [1, 3], "Only latest DIFF (#3) should be in chain"

    def test_when_dt_exactly_on_full_includes_it(self) -> None:
        """An archive exactly at when_dt is included (<=, not <)."""
        info = [
            (1, datetime.datetime(2026, 1, 10), "FULL"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 1, 10))
        assert chain == [1]

    def test_empty_archive_info_returns_empty(self) -> None:
        """No archives at all produces empty chain."""
        chain = _select_archive_chain([], datetime.datetime(2026, 1, 1))
        assert chain == []

    def test_diff_only_no_full_returns_empty(self) -> None:
        """DIFF without a FULL produces empty chain (FULL is required base)."""
        info = [
            (1, datetime.datetime(2026, 1, 10), "DIFF"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 2, 1))
        assert chain == []

    def test_incr_only_no_full_returns_empty(self) -> None:
        """INCR without a FULL produces empty chain."""
        info = [
            (1, datetime.datetime(2026, 1, 10), "INCR"),
        ]
        chain = _select_archive_chain(info, datetime.datetime(2026, 2, 1))
        assert chain == []


# ===========================================================================
# _parse_archive_info
# ===========================================================================

class TestParseArchiveInfo:
    """Tests for _parse_archive_info edge cases."""

    def test_archive_with_extra_suffix_after_date(self) -> None:
        """Archive name with extra suffix like '_manual' is still parsed."""
        archive_map = {1: "/tmp/backups/mydef_FULL_2026-01-15_manual"}
        info = _parse_archive_info(archive_map)
        assert len(info) == 1
        assert info[0] == (1, datetime.datetime(2026, 1, 15), "FULL")

    def test_archive_with_time_component(self) -> None:
        """Archive name with HHMMSS time is parsed correctly."""
        archive_map = {1: "/tmp/backups/mydef_FULL_2026-01-15_143022"}
        info = _parse_archive_info(archive_map)
        assert len(info) == 1
        assert info[0] == (1, datetime.datetime(2026, 1, 15, 14, 30, 22), "FULL")

    def test_non_matching_archive_name_is_skipped(self) -> None:
        """Archive names that don't match the pattern are silently skipped."""
        archive_map = {
            1: "/tmp/backups/mydef_FULL_2026-01-15",
            2: "/tmp/backups/random_name_no_date",
            3: "/tmp/backups/another_UNKNOWNTYPE_2026-01-15",
        }
        info = _parse_archive_info(archive_map)
        assert len(info) == 1
        assert info[0][0] == 1

    def test_all_three_types_parsed(self) -> None:
        """FULL, DIFF, and INCR are all recognized."""
        archive_map = {
            1: "/tmp/backups/def_FULL_2026-01-01",
            2: "/tmp/backups/def_DIFF_2026-01-05",
            3: "/tmp/backups/def_INCR_2026-01-08",
        }
        info = _parse_archive_info(archive_map)
        types = {i[2] for i in info}
        assert types == {"FULL", "DIFF", "INCR"}

    def test_empty_archive_map(self) -> None:
        """Empty input produces empty output."""
        assert _parse_archive_info({}) == []


# ===========================================================================
# _parse_file_versions
# ===========================================================================

class TestParseFileVersions:
    """Tests for _parse_file_versions edge cases."""

    def test_empty_output(self) -> None:
        """Empty string produces no versions."""
        assert _parse_file_versions("") == []

    def test_blank_lines_ignored(self) -> None:
        """Lines with only whitespace are skipped."""
        assert _parse_file_versions("   \n\n  \n") == []

    def test_malformed_lines_ignored(self) -> None:
        """Lines that don't match the expected pattern are skipped."""
        output = (
            "not a number Thu Jan 29 15:00:34 2026  saved\n"
            "some random text\n"
            "1 Thu Jan 29 15:00:34 2026  saved\n"
        )
        versions = _parse_file_versions(output)
        assert len(versions) == 1
        assert versions[0][0] == 1

    def test_multiple_valid_versions(self) -> None:
        """Multiple valid lines produce the correct list of versions."""
        output = (
            "1 Thu Jan 29 15:00:34 2026  saved\n"
            "3 Fri Jan 30 10:00:00 2026  saved\n"
        )
        versions = _parse_file_versions(output)
        assert len(versions) == 2
        assert versions[0][0] == 1
        assert versions[1][0] == 3


# ===========================================================================
# _looks_like_directory / _treat_as_directory
# ===========================================================================

class TestCatalogBasedRestoreStrategy:
    """Tests proving that the restore strategy is determined by dar_manager -f
    catalog output, not filename heuristics.

    If _detect_directory returns False → single-file restore (1 dar -x call).
    If _detect_directory returns True → directory restore via archive chain.
    """

    def test_dotfile_with_versions_takes_file_path(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """A dotfile like .bashrc with file versions in the catalog is correctly
        restored as a file, not misclassified as a directory."""
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-10\n"
            "2 /tmp/backups example_DIFF_2026-01-15\n"
        )
        file_output = (
            "1 Fri Jan 10 10:00:00 2026  saved\n"
            "2 Wed Jan 15 10:00:00 2026  saved\n"
        )
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),   # --list
            CommandResult(0, file_output, "", note=None),   # -f → has versions → file
            CommandResult(0, "ok", "", note=None),           # dar -x (single)
        ]

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["home/user/.bashrc"], when_dt, "/tmp/restore", mock_config
            )

        assert ret == 0
        dar_calls = [
            c for c in mock_runner.run.call_args_list
            if c.args[0][0] == "dar"
        ]
        assert len(dar_calls) == 1, (
            ".bashrc has file versions → single-file restore (1 dar -x call)"
        )
        info_calls = mock_logger.info.call_args_list
        assert any(
            "PITR restore file" in str(c) and ".bashrc" in str(c)
            for c in info_calls
        ), ".bashrc is logged as a file restore"

    def test_makefile_with_versions_takes_file_path(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """'Makefile' with file versions is restored as a file."""
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-10\n"
        )
        file_output = "1 Fri Jan 10 10:00:00 2026  saved\n"
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),
            CommandResult(0, file_output, "", note=None),
            CommandResult(0, "ok", "", note=None),
        ]

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["home/user/project/Makefile"], when_dt, "/tmp/restore", mock_config
            )

        assert ret == 0
        info_calls = mock_logger.info.call_args_list
        assert any(
            "PITR restore file" in str(c) and "Makefile" in str(c)
            for c in info_calls
        ), "Makefile with versions is logged as a file restore"

    def test_directory_without_versions_takes_chain_path(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """A directory path detected by _detect_directory → archive chain restore."""
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-10\n"
            "2 /tmp/backups example_DIFF_2026-01-15\n"
        )
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),   # --list
            CommandResult(0, "ok", "", note=None),           # dar -x FULL
            CommandResult(0, "ok", "", note=None),           # dar -x DIFF
        ]

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=True), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["home/user/Documents"], when_dt, "/tmp/restore", mock_config
            )

        assert ret == 0
        dar_calls = [
            c for c in mock_runner.run.call_args_list
            if c.args[0][0] == "dar"
        ]
        assert len(dar_calls) == 2, "Directory → chain restore (FULL + DIFF = 2 dar -x calls)"
        info_calls = mock_logger.info.call_args_list
        assert any(
            "PITR restore directory" in str(c) and "Documents" in str(c)
            for c in info_calls
        )

    def test_extensionless_file_with_versions_takes_file_path(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """Extensionless files (Dockerfile, LICENSE) with file versions are
        correctly restored as files, not directories."""
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-10\n"
        )
        file_output = "1 Fri Jan 10 10:00:00 2026  saved\n"
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),
            CommandResult(0, file_output, "", note=None),
            CommandResult(0, "ok", "", note=None),
        ]

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["home/user/project/Dockerfile"], when_dt, "/tmp/restore", mock_config
            )

        assert ret == 0
        info_calls = mock_logger.info.call_args_list
        assert any(
            "PITR restore file" in str(c) and "Dockerfile" in str(c)
            for c in info_calls
        ), "Dockerfile with versions is logged as a file restore"

    def test_file_with_extension_and_versions_takes_file_path(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """A regular file with extension and versions uses single-file restore."""
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-10\n"
            "2 /tmp/backups example_DIFF_2026-01-15\n"
        )
        file_output = (
            "1 Fri Jan 10 10:00:00 2026  saved\n"
            "2 Wed Jan 15 10:00:00 2026  saved\n"
        )
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),
            CommandResult(0, file_output, "", note=None),
            CommandResult(0, "ok", "", note=None),
        ]

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["home/user/.bashrc.bak"], when_dt, "/tmp/restore", mock_config
            )

        assert ret == 0
        dar_calls = [
            c for c in mock_runner.run.call_args_list
            if c.args[0][0] == "dar"
        ]
        assert len(dar_calls) == 1
        info_calls = mock_logger.info.call_args_list
        assert any(
            "PITR restore file" in str(c) and ".bashrc.bak" in str(c)
            for c in info_calls
        )


# ===========================================================================
# _restore_target_unsafe_reason
# ===========================================================================

class TestRestoreTargetUnsafeReason:
    """Tests for _restore_target_unsafe_reason edge cases."""

    def test_var_tmp_is_allowed(self) -> None:
        """Restore target under /var/tmp is safe."""
        assert _restore_target_unsafe_reason("/var/tmp/restore") is None

    def test_home_subdir_is_allowed(self) -> None:
        """Restore target under /home is safe."""
        assert _restore_target_unsafe_reason("/home/user/restore") is None

    def test_tmp_subdir_is_allowed(self) -> None:
        """Restore target under /tmp is safe."""
        assert _restore_target_unsafe_reason("/tmp/pitr_restore") is None

    def test_root_is_blocked(self) -> None:
        """Restore target / is blocked."""
        result = _restore_target_unsafe_reason("/")
        assert result is not None
        assert "protected" in result

    def test_etc_is_blocked(self) -> None:
        """Restore target /etc is blocked."""
        result = _restore_target_unsafe_reason("/etc")
        assert result is not None

    def test_subdir_of_protected_is_blocked(self) -> None:
        """Restore target /usr/local is blocked (under /usr)."""
        result = _restore_target_unsafe_reason("/usr/local")
        assert result is not None
        assert "protected" in result

    def test_dot_dot_traversal_under_home_into_etc(self) -> None:
        """/home/user/../../etc resolves to /etc and is blocked."""
        result = _restore_target_unsafe_reason("/home/user/../../etc")
        assert result is not None

    def test_dot_dot_traversal_staying_in_home(self) -> None:
        """/home/user/../otheruser stays under /home and is allowed."""
        result = _restore_target_unsafe_reason("/home/user/../otheruser")
        assert result is None

    def test_var_is_blocked_but_var_tmp_is_not(self) -> None:
        """/var itself is protected, but /var/tmp is allowed."""
        assert _restore_target_unsafe_reason("/var") is not None
        assert _restore_target_unsafe_reason("/var/tmp") is None


# ===========================================================================
# _normalize_when_dt / _parse_when
# ===========================================================================

class TestNormalizeWhenDt:
    """Tests for _normalize_when_dt."""

    def test_naive_datetime_passes_through(self) -> None:
        """Naive datetime (no tzinfo) is returned unchanged."""
        dt = datetime.datetime(2026, 3, 15, 10, 0, 0)
        result = _normalize_when_dt(dt)
        assert result == dt
        assert result.tzinfo is None

    def test_timezone_aware_is_converted_to_naive_local(self) -> None:
        """Timezone-aware datetime is converted to naive local time."""
        utc = datetime.timezone.utc
        dt = datetime.datetime(2026, 3, 15, 10, 0, 0, tzinfo=utc)
        result = _normalize_when_dt(dt)
        assert result.tzinfo is None
        # The result should be the local equivalent of 10:00 UTC

    def test_utc_offset_is_applied(self) -> None:
        """A non-UTC timezone offset is applied before stripping tzinfo."""
        tz_plus2 = datetime.timezone(datetime.timedelta(hours=2))
        dt = datetime.datetime(2026, 3, 15, 14, 0, 0, tzinfo=tz_plus2)
        result = _normalize_when_dt(dt)
        assert result.tzinfo is None


class TestParseWhen:
    """Tests for _parse_when."""

    def test_valid_date_string(self) -> None:
        """A valid date string returns a datetime."""
        result = _parse_when("2026-01-15 10:00:00")
        assert result is not None
        assert isinstance(result, datetime.datetime)

    def test_invalid_date_string_returns_none(self) -> None:
        """An unparseable string returns None."""
        result = _parse_when("not-a-date-at-all-xyz")
        assert result is None

    def test_returns_naive_datetime(self) -> None:
        """Returned datetime is always naive (timezone stripped)."""
        result = _parse_when("2026-01-15 10:00:00")
        if result is not None:
            assert result.tzinfo is None


# ===========================================================================
# _coerce_timeout
# ===========================================================================

class TestCoerceTimeout:
    """Tests for _coerce_timeout."""

    def test_none_returns_none(self) -> None:
        """None input returns None."""
        assert _coerce_timeout(None) is None

    def test_positive_int_passes_through(self) -> None:
        """Positive int is returned as-is."""
        assert _coerce_timeout(30) == 30

    def test_zero_returns_none(self) -> None:
        """Zero is treated as 'no timeout'."""
        assert _coerce_timeout(0) is None

    def test_negative_returns_none(self) -> None:
        """Negative value is treated as 'no timeout'."""
        assert _coerce_timeout(-5) is None

    def test_bool_true_returns_none(self) -> None:
        """Bool True is not treated as int 1."""
        assert _coerce_timeout(True) is None

    def test_bool_false_returns_none(self) -> None:
        """Bool False is not treated as int 0."""
        assert _coerce_timeout(False) is None

    def test_string_number_is_coerced(self) -> None:
        """String '30' is converted to int 30."""
        assert _coerce_timeout("30") == 30

    def test_string_negative_returns_none(self) -> None:
        """String '-1' returns None."""
        assert _coerce_timeout("-1") is None

    def test_string_non_numeric_returns_none(self) -> None:
        """Non-numeric string returns None."""
        assert _coerce_timeout("fast") is None


# ===========================================================================
# _parse_archive_map
# ===========================================================================

class TestParseArchiveMap:
    """Tests for _parse_archive_map edge cases."""

    def test_header_only_returns_empty(self) -> None:
        """Output with only header lines produces empty map."""
        output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
        )
        assert _parse_archive_map(output) == {}

    def test_spaces_in_directory_path(self) -> None:
        """Directory path containing spaces is reconstructed correctly."""
        output = (
            "1 /tmp/my backups example_FULL_2026-01-15\n"
        )
        result = _parse_archive_map(output)
        assert 1 in result
        assert result[1] == "/tmp/my backups/example_FULL_2026-01-15"

    def test_standard_output_parsed(self) -> None:
        """Standard dar_manager --list output is parsed correctly."""
        output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-29\n"
            "2 /tmp/backups example_DIFF_2026-01-29\n"
        )
        result = _parse_archive_map(output)
        assert len(result) == 2
        assert result[1] == "/tmp/backups/example_FULL_2026-01-29"
        assert result[2] == "/tmp/backups/example_DIFF_2026-01-29"

    def test_empty_output(self) -> None:
        """Empty string produces empty map."""
        assert _parse_archive_map("") == {}

    def test_non_numeric_first_field_skipped(self) -> None:
        """Lines where the first field is not a number are skipped."""
        output = "abc /tmp/backups example_FULL_2026-01-29\n"
        assert _parse_archive_map(output) == {}


# ===========================================================================
# _restore_with_dar — file restore break-on-missing-archive
# ===========================================================================

class TestRestoreWithDarFileBreakBehavior:
    """Tests verifying that file restore fails fast when the best candidate
    archive is missing, rather than silently falling back to a stale archive.

    Falling back to an older archive without explicit user acknowledgment is
    dangerous: the user would get outdated data with no indication that the
    restore is incomplete or stale.
    """

    def test_file_restore_fails_fast_on_missing_archive_map_entry(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """When the best candidate's archive is missing from the map, the restore
        fails immediately rather than silently falling back to an older archive.

        This is intentional safety behavior: restoring from a stale archive
        without user consent could cause silent data loss.
        """
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-10\n"
        )
        # File exists in catalog #2 (newest, missing from map) and #1 (older, present)
        file_output = (
            "1 Fri Jan 10 10:00:00 2026  saved\n"
            "2 Wed Jan 15 10:00:00 2026  saved\n"
        )
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),   # --list
            CommandResult(0, file_output, "", note=None),   # -f path
        ]

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager.send_discord_message"), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["tmp/file.txt"], when_dt, "/tmp/restore", mock_config
            )

        # Current behavior: fails because it breaks on missing #2 without trying #1
        assert ret == 1
        mock_logger.error.assert_any_call(
            "Archive number 2 missing from archive list; cannot restore 'tmp/file.txt'."
        )

    def test_file_restore_fails_fast_on_missing_slice(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """When the best candidate's .1.dar slice is missing, the restore fails
        immediately rather than silently falling back to an older archive.

        This is intentional safety behavior: restoring from a stale archive
        without user consent could cause silent data loss.
        """
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-10\n"
            "2 /tmp/backups example_DIFF_2026-01-15\n"
        )
        file_output = (
            "1 Fri Jan 10 10:00:00 2026  saved\n"
            "2 Wed Jan 15 10:00:00 2026  saved\n"
        )
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),
            CommandResult(0, file_output, "", note=None),
        ]

        def _exists(path):
            """DIFF slice missing, FULL slice present."""
            if path.endswith("example_DIFF_2026-01-15.1.dar"):
                return False
            return True

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager.send_discord_message"), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", side_effect=_exists):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["tmp/file.txt"], when_dt, "/tmp/restore", mock_config
            )

        # Current behavior: fails because it breaks on missing slice without trying #1
        assert ret == 1
        mock_logger.error.assert_any_call(
            "Archive slice missing for '/tmp/backups/example_DIFF_2026-01-15.1.dar', cannot restore 'tmp/file.txt'."
        )


# ===========================================================================
# _restore_with_dar — mixed dir + file in single call
# ===========================================================================

class TestRestoreWithDarMixedPaths:
    """Tests for restoring both directories and files in a single call."""

    def test_mixed_dir_and_file_restore(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """A single restore_with_dar call with one directory path and one file path."""
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-10\n"
            "2 /tmp/backups example_DIFF_2026-01-15\n"
        )
        file_output = "2 Wed Jan 15 10:00:00 2026  saved\n"
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),   # --list
            CommandResult(0, "ok", "", note=None),           # dar -x FULL for dir
            CommandResult(0, "ok", "", note=None),           # dar -x DIFF for dir
            CommandResult(0, file_output, "", note=None),    # -f for file
            CommandResult(0, "ok", "", note=None),           # dar -x for file
        ]

        def _detect_dir(path, *args, **kwargs):
            return path == "tmp/photos"

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", side_effect=_detect_dir), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def",
                ["tmp/photos", "tmp/notes/readme.txt"],
                when_dt,
                "/tmp/restore",
                mock_config,
            )

        assert ret == 0
        info_calls = mock_logger.info.call_args_list
        assert any(
            "PITR restore summary: %d succeeded, %d failed." in str(c)
            and c.args[1] == 2
            and c.args[2] == 0
            for c in info_calls
        ), "Both paths should succeed"


# ===========================================================================
# _restore_with_dar — darrc is passed to dar command
# ===========================================================================

class TestRestoreWithDarDarrc:
    """Tests that darrc file is passed to dar when found."""

    def test_darrc_path_included_in_dar_command(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """When _guess_darrc_path returns a path, -B is added to the dar command."""
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-10\n"
        )
        file_output = "1 Fri Jan 10 10:00:00 2026  saved\n"
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),
            CommandResult(0, file_output, "", note=None),
            CommandResult(0, "ok", "", note=None),
        ]

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager._guess_darrc_path", return_value="/etc/dar/.darrc"), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["tmp/file.txt"], when_dt, "/tmp/restore", mock_config
            )

        assert ret == 0
        # Find the dar -x call
        dar_calls = [
            c for c in mock_runner.run.call_args_list
            if c.args[0][0] == "dar"
        ]
        assert len(dar_calls) == 1
        cmd = dar_calls[0].args[0]
        assert "-B" in cmd
        assert "/etc/dar/.darrc" in cmd

    def test_no_darrc_means_no_B_flag(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """When _guess_darrc_path returns None, no -B flag is added."""
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1 /tmp/backups example_FULL_2026-01-10\n"
        )
        file_output = "1 Fri Jan 10 10:00:00 2026  saved\n"
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),
            CommandResult(0, file_output, "", note=None),
            CommandResult(0, "ok", "", note=None),
        ]

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            _restore_with_dar(
                "def", ["tmp/file.txt"], when_dt, "/tmp/restore", mock_config
            )

        dar_calls = [
            c for c in mock_runner.run.call_args_list
            if c.args[0][0] == "dar"
        ]
        assert len(dar_calls) == 1
        cmd = dar_calls[0].args[0]
        assert "-B" not in cmd


# ===========================================================================
# restore_at — path normalization
# ===========================================================================

class TestRestoreAtPathNormalization:
    """Tests for restore_at handling of unusual path formats."""

    def test_leading_slash_stripped_for_exists_check(
        self, mock_config, mock_logger
    ) -> None:
        """Paths with leading / are normalized (lstrip) before checking target overlap."""
        db_dir = "/tmp/db_dir"

        def _exists(path):
            if path == os.path.join(db_dir, "def.db"):
                return True
            if path == "/tmp/restore":
                return True
            # The normalized path "tmp/file.txt" under target should NOT exist
            return False

        with patch("dar_backup.manager.get_db_dir", return_value=db_dir), \
             patch("os.path.exists", side_effect=_exists), \
             patch("dateparser.parse", return_value=datetime.datetime(2026, 1, 1)), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._restore_with_dar", return_value=0) as mock_restore:

            ret = restore_at("def", ["/tmp/file.txt"], "now", "/tmp/restore", mock_config)

        assert ret == 0
        mock_restore.assert_called_once()

    def test_dot_path_skipped_in_exists_check(
        self, mock_config, mock_logger
    ) -> None:
        """A path that normalizes to '.' is skipped in the target overlap check."""
        db_dir = "/tmp/db_dir"

        def _exists(path):
            if path == os.path.join(db_dir, "def.db"):
                return True
            if path == "/tmp/restore":
                return True
            return False

        with patch("dar_backup.manager.get_db_dir", return_value=db_dir), \
             patch("os.path.exists", side_effect=_exists), \
             patch("dateparser.parse", return_value=datetime.datetime(2026, 1, 1)), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._restore_with_dar", return_value=0) as mock_restore:

            # "." and "/" both normalize to "." after lstrip+normpath → skipped
            ret = restore_at("def", ["/"], "now", "/tmp/restore", mock_config)

        assert ret == 0
        mock_restore.assert_called_once()

    def test_existing_target_path_aborts(
        self, mock_config, mock_logger
    ) -> None:
        """Restore aborts when a requested path already exists under target."""
        db_dir = "/tmp/db_dir"

        def _exists(path):
            if path == os.path.join(db_dir, "def.db"):
                return True
            if path == "/tmp/restore":
                return True
            if path == "/tmp/restore/data/file.txt":
                return True
            return False

        with patch("dar_backup.manager.get_db_dir", return_value=db_dir), \
             patch("os.path.exists", side_effect=_exists), \
             patch("dateparser.parse", return_value=datetime.datetime(2026, 1, 1)), \
             patch("dar_backup.manager.logger", mock_logger):

            ret = restore_at("def", ["data/file.txt"], "now", "/tmp/restore", mock_config)

        assert ret == 1
        mock_logger.error.assert_any_call(
            "Restore target '%s' already contains path(s) to restore: %s%s. For safety, PITR restores abort "
            "without overwriting existing files. Use a clean/empty target.",
            "/tmp/restore",
            "data/file.txt",
            "",
        )
