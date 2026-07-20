# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests for PITR edge cases, stability issues, and missing coverage.

Covers:
  - _select_archive_chain: FULL+INCR (no DIFF), multiple FULLs, all-future,
    same-day with time components, when_dt between DIFF and INCR
  - _parse_archive_info: extra suffixes, non-matching names, time components
  - _parse_file_versions: empty output, malformed lines
  - _restore_target_unsafe_reason: .. traversal, /var/tmp allowed, symlink-like
  - _normalize_when_dt / _parse_when: naive passthrough, tz-aware conversion
  - _coerce_timeout: string, bool, negative, None
  - _parse_archive_map: tab-separated parsing, spaces in directory path AND in
    archive basename (space-containing definition names), leading pad, header-only
  - _restore_with_dar: file restore break-vs-continue on missing archive,
    mixed dir+file in single call, darrc passed to dar command
  - restore_at: path normalization with leading /, ./, ..
  - _missing_chain_elements: all present, some missing, all missing, empty chain
  - _is_directory_path: existing directory, non-existing path, file instead of dir
  - _is_directory_in_archive: directory found, file found, not found, dar error,
    sibling-prefix path not matched (component-boundary check)
  - _line_path_matches: boundary matching (start/slash/space/tab) vs sibling-prefix
    and partial-component substrings
  - _replace_path_prefix: exact match, nested path, trailing slash, sibling-prefix
    not matched, unrelated path
  - _resolve_pitr_path: shared detect/select decision used by BOTH the dry-run
    report and the real restore (directory chain, no-FULL error, missing slice,
    file candidates ordered latest-first, no-version error)
  - _format_chain_item: with info, without info
  - _describe_archive: with info, without info
"""

from unittest.mock import MagicMock, patch
import datetime
import os

import pytest

from dar_backup.manager import (
    _coerce_timeout,
    _describe_archive,
    _detect_directory,
    _format_chain_item,
    _is_directory_in_archive,
    _is_directory_path,
    _line_path_matches,
    _missing_chain_elements,
    _normalize_when_dt,
    _parse_archive_info,
    _parse_archive_map,
    _parse_file_versions,
    _parse_when,
    _replace_path_prefix,
    _resolve_backup_root,
    _resolve_pitr_path,
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
    config.config_file = str(tmp_path / "dar-backup.conf")
    return config


@pytest.fixture(autouse=True)
def isolate_archive_validation():
    """Keep catalog-selection edge tests independent from real slice checks.

    Real slice inventory and DAR final-slice behavior are covered separately.
    """
    with patch("dar_backup.manager._pitr_archive_validation_error", return_value=None), \
         patch("dar_backup.manager._pitr_archive_sequence_error", return_value=None):
        yield


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
        """Only the latest INCR is needed — each INCR is cumulative relative to DIFF."""
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

    def test_present_entries_are_excluded(self) -> None:
        """A DIFF/INCR that lists the file as 'present' (unchanged, data NOT
        re-saved) must not become a version candidate: restoring from it would
        extract nothing while dar still exits 0.

        Lines mirror real `dar_manager -f` output, where an unchanged file shows
        the same recorded date in the later archive but status 'present'.
        """
        output = (
            " \t1\tMon Jul 20 00:29:21 2026  saved                                 absent  \n"
            " \t2\tMon Jul 20 00:29:21 2026  present                               absent  \n"
        )
        versions = _parse_file_versions(output)
        assert [num for num, _dt in versions] == [1], (
            "'present' entry (#2) holds no data and must be excluded"
        )

    def test_saved_entries_in_real_format_are_kept(self) -> None:
        """Positive counterpart: real-format 'saved' lines from both archives
        are both returned (file changed between FULL and DIFF)."""
        output = (
            " \t1\tMon Jul 20 00:29:21 2026  saved                                 absent  \n"
            " \t2\tMon Jul 20 00:29:22 2026  saved                                 absent  \n"
        )
        versions = _parse_file_versions(output)
        assert [num for num, _dt in versions] == [1, 2]


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
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
            "2\t/tmp/backups\texample_DIFF_2026-01-15\n"
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
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
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
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
            "2\t/tmp/backups\texample_DIFF_2026-01-15\n"
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
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
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
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
            "2\t/tmp/backups\texample_DIFF_2026-01-15\n"
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

    def test_var_tmp_prefix_without_separator_is_blocked(self) -> None:
        """/var/tmpfoo must not be treated as a sub-directory of /var/tmp.

        Before the fix, startswith(("/var/tmp", …)) accepted /var/tmpfoo because
        it shares the same leading characters.  /var/tmpfoo is under /var (a
        protected system directory) and must be blocked.  The new check uses
        prefix + os.sep, so only paths genuinely beneath /var/tmp/ pass.
        """
        result = _restore_target_unsafe_reason("/var/tmpfoo")
        assert result is not None

    def test_var_tmp_with_separator_still_allowed(self) -> None:
        """/var/tmp/restore is genuinely under /var/tmp and must remain allowed."""
        assert _restore_target_unsafe_reason("/var/tmp/restore") is None

    def test_symlink_into_protected_dir_is_blocked(self, tmp_path) -> None:
        """A symlink under a safe prefix that resolves to a protected dir must be blocked.

        With the old abspath() implementation the symlink path itself (e.g.
        /tmp/.../link) appeared to be under /tmp and was allowed.  realpath()
        follows the symlink to its canonical target (/etc) so the protected-
        prefix check fires correctly.
        """
        link = tmp_path / "link_to_etc"
        link.symlink_to("/etc")
        result = _restore_target_unsafe_reason(str(link))
        assert result is not None, (
            "A symlink into /etc must be blocked; abspath() would have allowed it"
        )
        assert "protected" in result

    def test_symlink_to_safe_dir_is_allowed(self, tmp_path) -> None:
        """A symlink that resolves to a genuinely safe directory must remain allowed."""
        safe_target = tmp_path / "restore_target"
        safe_target.mkdir()
        link = tmp_path / "link_to_safe"
        link.symlink_to(safe_target)
        # tmp_path is under /tmp — realpath() resolves the link to the real
        # path under /tmp, which is in the allow-list.
        assert _restore_target_unsafe_reason(str(link)) is None


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
            "1\t/tmp/my backups\texample_FULL_2026-01-15\n"
        )
        result = _parse_archive_map(output)
        assert 1 in result
        assert result[1] == "/tmp/my backups/example_FULL_2026-01-15"

    def test_spaces_in_archive_basename(self) -> None:
        """A backup definition name containing spaces (allowed for years) yields a
        basename with a space, e.g. 'my backup_FULL_...'.  Tab-splitting must keep
        it whole so the resolved path points at the real archive.

        Regression: the previous whitespace split tore 'my backup_FULL_2026-01-15'
        into path '/tmp/backups my' + basename 'backup_FULL_2026-01-15', producing
        a non-existent path so PITR reported the slice as missing.
        """
        output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1\t/tmp/backups\tmy backup_FULL_2026-01-15\n"
        )
        result = _parse_archive_map(output)
        assert result == {1: "/tmp/backups/my backup_FULL_2026-01-15"}

    def test_leading_space_and_tab_before_number_handled(self) -> None:
        """Real dar_manager rows are padded with a leading space+tab; the catalog
        number must still be recognised once the row is stripped."""
        output = " \t3\t/tmp/backups\texample_INCR_2026-01-20\n"
        result = _parse_archive_map(output)
        assert result == {3: "/tmp/backups/example_INCR_2026-01-20"}

    def test_standard_output_parsed(self) -> None:
        """Standard dar_manager --list output is parsed correctly."""
        output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1\t/tmp/backups\texample_FULL_2026-01-29\n"
            "2\t/tmp/backups\texample_DIFF_2026-01-29\n"
        )
        result = _parse_archive_map(output)
        assert len(result) == 2
        assert result[1] == "/tmp/backups/example_FULL_2026-01-29"
        assert result[2] == "/tmp/backups/example_DIFF_2026-01-29"

    def test_empty_output(self) -> None:
        """Empty string produces empty map."""
        assert _parse_archive_map("") == {}

    def test_non_numeric_first_field_skipped(self) -> None:
        """A well-formed row whose first field is not a number is skipped."""
        output = "abc\t/tmp/backups\texample_FULL_2026-01-29\n"
        assert _parse_archive_map(output) == {}


# ===========================================================================
# _restore_with_dar — file restore break-on-missing-archive
# ===========================================================================

class TestRestoreWithDarFileBreakBehavior:
    """Tests verifying that file restore fails fast when the best candidate
    cannot be restored, rather than silently falling back to a stale archive.

    Falling back to an older archive without explicit user acknowledgment is
    dangerous: the user would get outdated data with no indication that the
    restore is incomplete or stale.  All three failure modes obey this policy:
    the candidate's catalog entry missing from the archive map, its .1.dar
    slice missing from disk, and dar itself failing to extract (e.g. a
    corrupt or truncated slice).
    """

    def test_file_restore_fails_fast_on_missing_archive_map_entry(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """When a catalog number that recorded the file cannot be resolved to a
        dated archive (missing from `dar_manager --list`), the restore fails
        immediately rather than silently falling back to an older archive.

        This is intentional safety behavior: without the archive date PITR
        cannot know whether the unresolvable version is the best candidate, so
        restoring any other version could silently deliver stale data.
        """
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
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

        # Fails fast: #2 recorded the file but has no dated entry in the
        # archive list, so no version (not even the resolvable #1) is restored.
        assert ret == 1
        mock_logger.error.assert_any_call(
            "Cannot restore 'tmp/file.txt': catalog number(s) #2 recorded versions of the "
            "path but could not be resolved to a dated archive from `dar_manager --list` "
            "output (missing entry or non-standard archive name). PITR cannot order these "
            "versions by archive date safely — fix the catalog or archive names first."
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
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
            "2\t/tmp/backups\texample_DIFF_2026-01-15\n"
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

        missing_error = "Archive '/tmp/backups/example_DIFF_2026-01-15' has no DAR slices"

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager.send_discord_message"), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("dar_backup.manager._pitr_archive_validation_error", return_value=missing_error), \
             patch("os.path.exists", side_effect=_exists):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["tmp/file.txt"], when_dt, "/tmp/restore", mock_config
            )

        # Current behavior: fails because it breaks on missing slice without trying #1
        assert ret == 1
        mock_logger.error.assert_any_call(
            "%s; cannot restore '%s'.",
            missing_error,
            "tmp/file.txt",
        )

    def test_file_restore_dar_failure_on_best_candidate_fails_without_fallback(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """When dar itself fails on the best candidate (slice present on disk but
        e.g. corrupt or truncated), the restore fails with exit code 1 instead of
        silently falling back to the older candidate #1.

        This is the most insidious failure mode: the archive *exists*, so only
        dar's non-zero exit reveals the damage.  Restoring the older version
        with a success exit code would hide the corruption entirely.
        """
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
            "2\t/tmp/backups\texample_DIFF_2026-01-15\n"
        )
        file_output = (
            "1 Fri Jan 10 10:00:00 2026  saved\n"
            "2 Wed Jan 15 10:00:00 2026  saved\n"
        )
        # Exactly three results: --list, -f, and ONE dar -x attempt (#2).
        # A fallback attempt on #1 would exhaust the side_effect list and error.
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),               # --list
            CommandResult(0, file_output, "", note=None),               # -f path
            CommandResult(1, "", "CRC error: data corruption", note=None),  # dar -x on #2
        ]

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager.send_discord_message") as mock_discord, \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["tmp/file.txt"], when_dt, "/tmp/restore", mock_config
            )

        assert ret == 1, "dar failure on the best candidate must fail the restore"
        dar_calls = [
            c for c in mock_runner.run.call_args_list if c.args[0][0] == "dar"
        ]
        assert len(dar_calls) == 1, (
            "Exactly one dar -x attempt: no fallback to the older candidate"
        )
        assert dar_calls[0].args[0][2] == "/tmp/backups/example_DIFF_2026-01-15", (
            "The single attempt must target the newest candidate (#2)"
        )
        mock_logger.error.assert_any_call(
            "dar restore failed for 'tmp/file.txt' from '/tmp/backups/example_DIFF_2026-01-15': "
            "CRC error: data corruption"
        )
        # The recovery guidance must be at ERROR level and name the older
        # versions with their timestamps — the rerun's --when must be set at
        # the older version's ARCHIVE date (before the damaged one's), and the
        # candidate list is otherwise only visible at DEBUG level.
        mock_logger.error.assert_any_call(
            "Not falling back to an older version of '%s'. Older versions in the catalog: %s. "
            "If the slice is damaged, try par2 repair first (see doc/par2.md), then rerun. "
            "To restore an older version instead, rerun with --when at that version's timestamp, "
            "into a clean target.",
            "tmp/file.txt",
            "#1@2026-01-10 00:00:00 (example_FULL_2026-01-10)",
        )
        mock_discord.assert_called()

    def test_file_restore_dar_success_on_best_candidate_restores_newest_version(
        self, mock_config, mock_runner, mock_logger
    ) -> None:
        """Positive counterpart: with two candidates and a healthy newest archive,
        the restore succeeds with exit code 0 via exactly one dar -x call on the
        newest candidate — the older candidate is never touched.
        """
        list_output = (
            "archive #   |    path      |    basename\n"
            "------------+--------------+---------------\n"
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
            "2\t/tmp/backups\texample_DIFF_2026-01-15\n"
        )
        file_output = (
            "1 Fri Jan 10 10:00:00 2026  saved\n"
            "2 Wed Jan 15 10:00:00 2026  saved\n"
        )
        mock_runner.run.side_effect = [
            CommandResult(0, list_output, "", note=None),   # --list
            CommandResult(0, file_output, "", note=None),   # -f path
            CommandResult(0, "ok", "", note=None),          # dar -x on #2
        ]

        with patch("dar_backup.manager.get_db_dir", return_value="/tmp/db_dir"), \
             patch("dar_backup.manager.runner", mock_runner), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager.send_discord_message") as mock_discord, \
             patch("dar_backup.manager._detect_directory", return_value=False), \
             patch("dar_backup.manager._guess_darrc_path", return_value=None), \
             patch("os.path.exists", return_value=True):

            when_dt = datetime.datetime(2026, 1, 20)
            ret = _restore_with_dar(
                "def", ["tmp/file.txt"], when_dt, "/tmp/restore", mock_config
            )

        assert ret == 0
        dar_calls = [
            c for c in mock_runner.run.call_args_list if c.args[0][0] == "dar"
        ]
        assert len(dar_calls) == 1, "Exactly one dar -x call for a healthy best candidate"
        assert dar_calls[0].args[0][2] == "/tmp/backups/example_DIFF_2026-01-15", (
            "The restore must use the newest candidate (#2), not the older FULL"
        )
        mock_discord.assert_not_called()


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
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
            "2\t/tmp/backups\texample_DIFF_2026-01-15\n"
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
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
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
            "1\t/tmp/backups\texample_FULL_2026-01-10\n"
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

    def test_leading_slash_now_rejected_as_absolute(
        self, tmp_path, mock_config, mock_logger
    ) -> None:
        """Paths with a leading / are now rejected outright by
        _restore_paths_invalid_reason, not silently normalized.

        Superseded behavior: this path used to be lstrip()-ped for the target
        overlap check only, while the raw (still-absolute-looking) string was
        passed unmodified to the actual `dar -g` call — an inconsistency
        between what was checked and what was executed. Rejecting it outright
        is both simpler and matches the documented contract (restoring.md:
        "--restore-path must be a relative path ... no leading slash").
        """
        db_dir = "/tmp/db_dir"
        target = str(tmp_path / "restore")
        os.makedirs(target)

        with patch("dar_backup.manager.get_db_dir", return_value=db_dir), \
             patch("dateparser.parse", return_value=datetime.datetime(2026, 1, 1)), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._restore_with_dar", return_value=0) as mock_restore:

            ret = restore_at("def", ["/tmp/file.txt"], "now", target, mock_config)

        assert ret == 1
        mock_restore.assert_not_called()

    def test_dot_path_skipped_in_exists_check(
        self, tmp_path, mock_config, mock_logger
    ) -> None:
        """A relative path that normalizes to '.' is skipped in the target
        overlap check (rather than being compared as an empty/'.' candidate)."""
        db_dir = "/tmp/db_dir"
        target = str(tmp_path / "restore")
        os.makedirs(target)

        def _exists(path):
            if path == os.path.join(db_dir, "def.db"):
                return True
            if path == target:
                return True
            return False

        with patch("dar_backup.manager.get_db_dir", return_value=db_dir), \
             patch("os.path.exists", side_effect=_exists), \
             patch("dateparser.parse", return_value=datetime.datetime(2026, 1, 1)), \
             patch("dar_backup.manager.logger", mock_logger), \
             patch("dar_backup.manager._restore_with_dar", return_value=0) as mock_restore:

            # "." normalizes to "." after lstrip+normpath → skipped in overlap check.
            ret = restore_at("def", ["."], "now", target, mock_config)

        assert ret == 0
        mock_restore.assert_called_once()

    def test_existing_target_path_aborts(
        self, tmp_path, mock_config, mock_logger
    ) -> None:
        """Restore aborts when a requested path already exists under target."""
        db_dir = "/tmp/db_dir"
        target = str(tmp_path / "restore")
        os.makedirs(target)

        def _exists(path):
            if path == os.path.join(db_dir, "def.db"):
                return True
            if path == target:
                return True
            if path == os.path.join(target, "data/file.txt"):
                return True
            return False

        with patch("dar_backup.manager.get_db_dir", return_value=db_dir), \
             patch("os.path.exists", side_effect=_exists), \
             patch("dateparser.parse", return_value=datetime.datetime(2026, 1, 1)), \
             patch("dar_backup.manager.logger", mock_logger):

            ret = restore_at("def", ["data/file.txt"], "now", target, mock_config)

        assert ret == 1
        mock_logger.error.assert_any_call(
            "Restore target '%s' already contains path(s) to restore: %s%s. For safety, PITR restores abort "
            "without overwriting existing files. Use a clean/empty target.",
            target,
            "data/file.txt",
            "",
        )


# ===========================================================================
# _missing_chain_elements
# ===========================================================================


class TestMissingChainElements:
    """Tests for _missing_chain_elements edge cases."""

    def test_empty_chain_returns_empty_list(self) -> None:
        """Empty chain produces no missing elements."""
        missing = _missing_chain_elements([], {})
        assert missing == []

    def test_all_archives_present_returns_empty(self, tmp_path) -> None:
        """All archive slices exist — no missing elements reported."""
        archive_map = {1: str(tmp_path / "full"), 2: str(tmp_path / "diff"), 3: str(tmp_path / "incr")}
        for path in archive_map.values():
            (tmp_path / f"{path}.1.dar").touch()

        missing = _missing_chain_elements([1, 2, 3], archive_map)
        assert missing == []

    def test_all_archives_missing_from_map(self, tmp_path, monkeypatch) -> None:
        """All catalog numbers missing from archive map are reported."""
        archive_map = {1: str(tmp_path / "full")}
        # Create the .1.dar file for catalog #1 so it doesn't show as filesystem-missing
        (tmp_path / "full.1.dar").touch()
        missing = _missing_chain_elements([1, 2, 3], archive_map)
        assert len(missing) == 2
        assert "catalog #2 missing from archive map" in missing
        assert "catalog #3 missing from archive map" in missing

    def test_all_slices_missing_from_filesystem(self, tmp_path) -> None:
        """All archive slice files missing from filesystem are reported."""
        archive_map = {1: str(tmp_path / "full"), 2: str(tmp_path / "diff")}
        missing = _missing_chain_elements([1, 2], archive_map)
        assert len(missing) == 2
        assert f"{tmp_path / 'full'}.1.dar" in missing
        assert f"{tmp_path / 'diff'}.1.dar" in missing

    def test_some_archives_missing(self, tmp_path) -> None:
        """Only missing archives are reported; present ones are not."""
        archive_map = {1: str(tmp_path / "full"), 2: str(tmp_path / "diff"), 3: str(tmp_path / "incr")}
        (tmp_path / "full.1.dar").touch()
        (tmp_path / "incr.1.dar").touch()

        missing = _missing_chain_elements([1, 2, 3], archive_map)
        assert len(missing) == 1
        assert f"{tmp_path / 'diff'}.1.dar" in missing


# ===========================================================================
# _is_directory_path
# ===========================================================================


class TestIsDirectoryPath:
    """Tests for _is_directory_path."""

    def test_existing_directory_returns_true(self, tmp_path) -> None:
        """Existing directory path returns True."""
        test_dir = tmp_path / "existing_dir"
        test_dir.mkdir()
        assert _is_directory_path(str(test_dir)) is True

    def test_existing_directory_with_trailing_slash(self, tmp_path) -> None:
        """Existing directory path with trailing slash returns True."""
        test_dir = tmp_path / "existing_dir"
        test_dir.mkdir()
        assert _is_directory_path(str(test_dir) + "/") is True

    def test_root_directory_returns_true(self) -> None:
        """Root directory '/' returns True."""
        assert _is_directory_path("/") is True

    def test_non_existing_path_returns_false(self, tmp_path) -> None:
        """Non-existing path returns False."""
        non_existent = tmp_path / "does_not_exist"
        assert _is_directory_path(str(non_existent)) is False

    def test_file_instead_of_directory_returns_false(self, tmp_path) -> None:
        """File path (not directory) returns False."""
        test_file = tmp_path / "file.txt"
        test_file.touch()
        assert _is_directory_path(str(test_file)) is False

    def test_relative_path_resolved_against_non_root(self, tmp_path) -> None:
        """A relative path (as stored in the catalog) must resolve against the
        backup definition's actual -R root, not a hardcoded '/'.

        This is the exact bug from v2/BUG.txt: a backup taken with -R other
        than '/' stores catalog paths relative to that root, e.g. 'subdir'
        for <root>/subdir. Without threading root through, this would check
        '/subdir' on the live filesystem instead of '<root>/subdir'.
        """
        root = tmp_path / "data"
        (root / "subdir").mkdir(parents=True)
        assert _is_directory_path("subdir", root=str(root)) is True

    def test_relative_path_not_confused_with_real_root(self, tmp_path) -> None:
        """A directory that exists under '/' but not under the real -R root
        must not produce a false positive — proving the old os.sep-hardcoded
        behavior is actually gone, not just coincidentally still working.
        """
        root = tmp_path / "data"
        root.mkdir()
        # "tmp" exists under the real filesystem root ('/tmp'), but not under
        # our fake root — must resolve against root, not '/'.
        assert _is_directory_path("tmp", root=str(root)) is False

    def test_root_with_spaces_and_non_ascii(self, tmp_path) -> None:
        """-R roots with spaces and UTF-8 characters must work end-to-end."""
        root = tmp_path / "backup source café ünïcödé 日本語"
        (root / "subdir").mkdir(parents=True)
        assert _is_directory_path("subdir", root=str(root)) is True
        assert _is_directory_path("does_not_exist", root=str(root)) is False


# ===========================================================================
# _detect_directory
# ===========================================================================


class TestDetectDirectoryRoot:
    """Tests proving _detect_directory threads root through to the fast path."""

    def test_root_threaded_to_fast_path(self, tmp_path, mock_runner) -> None:
        """A directory only present under a non-default root must be detected
        as a directory without needing the dar-catalog fallback at all."""
        root = tmp_path / "data"
        (root / "subdir").mkdir(parents=True)
        result = _detect_directory("subdir", {}, [], mock_runner, 30, root=str(root))
        assert result is True
        mock_runner.run.assert_not_called()

    def test_missing_root_falls_back_to_catalog(self, tmp_path, mock_runner) -> None:
        """When the path doesn't exist under the given root, it must still
        fall back to dar catalog inspection (unchanged fallback behavior)."""
        root = tmp_path / "data"
        root.mkdir()
        mock_runner.run.return_value = CommandResult(
            0, "drwxr-xr-x user group 4 kio some/path\n", "", note=None
        )
        archive_info = [(1, datetime.datetime(2026, 1, 1), "FULL")]
        archive_map = {1: "/backups/example_FULL_2026-01-01"}
        result = _detect_directory("some/path", archive_map, archive_info, mock_runner, 30, root=str(root))
        assert result is True
        mock_runner.run.assert_called_once()


class TestDetectDirectoryWhenAware:
    """Tests for _detect_directory's when_dt-aware catalog fallback.

    The fallback must inspect the archives of the chain selected for when_dt,
    not blindly the newest FULL in the catalog: a directory deleted before the
    newest FULL (disaster recovery to an older point in time) or created only
    in a DIFF exists in the when-selected chain but not in the newest FULL.
    """

    # Catalog: old chain (FULL Jan10 + DIFF Jan15) and a newer FULL Mar01
    # taken AFTER the directory was deleted.
    _MAP = {
        1: "/backups/example_FULL_2026-01-10",
        2: "/backups/example_DIFF_2026-01-15",
        3: "/backups/example_FULL_2026-03-01",
    }
    _INFO = [
        (1, datetime.datetime(2026, 1, 10), "FULL"),
        (2, datetime.datetime(2026, 1, 15), "DIFF"),
        (3, datetime.datetime(2026, 3, 1), "FULL"),
    ]

    @staticmethod
    def _runner_with_dir_in(archives_with_dir, mock_runner):
        """Make dar -l report 'old/dir' as a directory only for the given archive paths."""
        def _run(cmd, timeout=None):
            archive = cmd[2]  # ['dar', '-l', <archive>, '-g', ...]
            if archive in archives_with_dir:
                return CommandResult(0, "drwxr-xr-x user group 4 kio old/dir\n", "", note=None)
            return CommandResult(0, "", "", note=None)
        mock_runner.run.side_effect = _run
        return mock_runner

    def test_dir_deleted_before_newest_full_detected_via_when_chain(self, mock_runner) -> None:
        """A directory present only in the old FULL+DIFF chain is detected for a
        when_dt inside that chain — the newest FULL (Mar01) must not be the
        witness, and must not even be consulted."""
        runner = self._runner_with_dir_in({self._MAP[1], self._MAP[2]}, mock_runner)

        result = _detect_directory(
            "old/dir", self._MAP, self._INFO, runner, 30, root="/nonexistent-root",
            when_dt=datetime.datetime(2026, 1, 20),
        )

        assert result is True
        inspected = [c.args[0][2] for c in mock_runner.run.call_args_list]
        assert self._MAP[3] not in inspected, "newest FULL (after when) must not be inspected"

    def test_dir_created_only_in_diff_detected_via_chain(self, mock_runner) -> None:
        """A directory created between FULL and DIFF exists only in the DIFF —
        the chain-aware fallback must find it there."""
        runner = self._runner_with_dir_in({self._MAP[2]}, mock_runner)

        result = _detect_directory(
            "old/dir", self._MAP, self._INFO, runner, 30, root="/nonexistent-root",
            when_dt=datetime.datetime(2026, 1, 20),
        )

        assert result is True

    def test_dir_in_no_chain_archive_returns_false(self, mock_runner) -> None:
        """Negative: a path that no chain archive lists as a directory stays a
        file candidate."""
        runner = self._runner_with_dir_in(set(), mock_runner)

        result = _detect_directory(
            "old/dir", self._MAP, self._INFO, runner, 30, root="/nonexistent-root",
            when_dt=datetime.datetime(2026, 1, 20),
        )

        assert result is False

    def test_no_full_at_or_before_when_falls_back_to_newest_full(self, mock_runner) -> None:
        """when_dt before every FULL yields an empty chain; classification falls
        back to the newest FULL overall (selection later reports its own
        'no FULL archive' error)."""
        runner = self._runner_with_dir_in({self._MAP[3]}, mock_runner)

        result = _detect_directory(
            "old/dir", self._MAP, self._INFO, runner, 30, root="/nonexistent-root",
            when_dt=datetime.datetime(2025, 12, 1),
        )

        assert result is True
        inspected = [c.args[0][2] for c in mock_runner.run.call_args_list]
        assert inspected == [self._MAP[3]], "only the newest FULL is the classification fallback"


# ===========================================================================
# _resolve_backup_root
# ===========================================================================


class TestResolveBackupRoot:
    """Tests for _resolve_backup_root."""

    def test_resolves_configured_root(self, tmp_path, mock_config) -> None:
        os.makedirs(mock_config.backup_d_dir, exist_ok=True)
        with open(os.path.join(mock_config.backup_d_dir, "example"), "w") as f:
            f.write("-R /data\n-s 10G\n")
        assert _resolve_backup_root(mock_config, "example") == "/data"

    def test_falls_back_to_root_when_undeterminable(self, tmp_path, mock_config, mock_logger) -> None:
        """A missing/unreadable backup definition must fall back to '/' (the
        previously-assumed default) and log a warning, not raise."""
        with patch("dar_backup.manager.logger", mock_logger):
            result = _resolve_backup_root(mock_config, "does_not_exist")
        assert result == os.sep
        assert mock_logger.warning.called


# ===========================================================================
# _is_directory_in_archive
# ===========================================================================


class TestIsDirectoryInArchive:
    """Tests for _is_directory_in_archive."""

    def test_dar_output_with_directory_permissions_returns_true(self, mock_runner) -> None:
        """dar -l output with 'drwxr-xr-x' for path returns True."""
        dar_output = "drwxr-xr-x user group 4096 2026-01-01 path/to/dir\n-rw-r--r-- user group 123 2026-01-01 path/to/file"
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("path/to/dir", "/archive/path", mock_runner, 30)
        assert result is True

    def test_dar_output_with_file_permissions_returns_false(self, mock_runner) -> None:
        """dar -l output with '-rw-r--r--' for path returns False."""
        dar_output = "-rw-r--r-- user group 123 2026-01-01 path/to/file"
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("path/to/file", "/archive/path", mock_runner, 30)
        assert result is False

    def test_private_700_directory_returns_true(self, mock_runner) -> None:
        """A mode-700 directory ('drwx------') is detected as a directory.

        Regression test: the previous regex ended in \\b, and a permission
        string ending in '-' has no word boundary before the following
        whitespace — so exactly the private directories (700/750/770) were
        misclassified as files.  The line below is copied verbatim from real
        `dar -l` output (tab-separated fields).
        """
        dar_output = (
            "[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size |  Date  |  filename\n"
            "[Saved][-]       [-L-][   0%][ ]  drwx------   pj\tpj\t2 o\tSun Jul 19 23:53:14 2026\thome/pj/private"
        )
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("home/pj/private", "/archive/path", mock_runner, 30)
        assert result is True

    def test_group_750_directory_returns_true(self, mock_runner) -> None:
        """A mode-750 directory ('drwxr-x---') is detected as a directory."""
        dar_output = (
            "[Saved][-]       [-L-][     ][ ]  drwxr-x---   pj\tpj\t0\tSun Jul 19 23:53:14 2026\tdata/group"
        )
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("data/group", "/archive/path", mock_runner, 30)
        assert result is True

    def test_shared_770_directory_returns_true(self, mock_runner) -> None:
        """A mode-770 directory ('drwxrwx---') is detected as a directory."""
        dar_output = "drwxrwx--- user group 4096 2026-01-01 path/to/shared"
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("path/to/shared", "/archive/path", mock_runner, 30)
        assert result is True

    def test_acl_marker_directory_returns_true(self, mock_runner) -> None:
        """A directory permission string with a trailing ACL marker '+' is detected."""
        dar_output = "drwxr-xr-x+ user group 4096 2026-01-01 path/with/acl"
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("path/with/acl", "/archive/path", mock_runner, 30)
        assert result is True

    def test_private_600_file_returns_false(self, mock_runner) -> None:
        """Negative counterpart: a mode-600 *file* ('-rw-------') stays a file."""
        dar_output = "-rw------- user group 600 2026-01-01 path/private.key"
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("path/private.key", "/archive/path", mock_runner, 30)
        assert result is False

    def test_dar_output_with_multiple_entries_finds_directory(self, mock_runner) -> None:
        """Finds directory in output with multiple entries."""
        dar_output = (
            "-rw-r--r-- user group 123 2026-01-01 path/to/file1\n"
            "drwxr-xr-x user group 4096 2026-01-01 path/to/dir\n"
            "-rw-r--r-- user group 123 2026-01-01 path/to/file2"
        )
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("path/to/dir", "/archive/path", mock_runner, 30)
        assert result is True

    def test_dar_output_without_path_returns_false(self, mock_runner) -> None:
        """dar -l output without the path returns False."""
        dar_output = "drwxr-xr-x user group 4096 2026-01-01 path/to/other"
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("path/to/dir", "/archive/path", mock_runner, 30)
        assert result is False

    def test_dar_fails_nonzero_returncode_returns_false(self, mock_runner) -> None:
        """dar command failure (non-zero return code) returns False."""
        mock_runner.run.return_value = CommandResult(1, "error", "dar failed", note=None)

        result = _is_directory_in_archive("path/to/dir", "/archive/path", mock_runner, 30)
        assert result is False

    def test_empty_dar_output_returns_false(self, mock_runner) -> None:
        """Empty dar output returns False."""
        mock_runner.run.return_value = CommandResult(0, "", "", note=None)

        result = _is_directory_in_archive("path/to/dir", "/archive/path", mock_runner, 30)
        assert result is False

    def test_sibling_prefix_directory_not_matched(self, mock_runner) -> None:
        """A directory line ending in a sibling path (home/pj/MyDocuments/Taxes)
        must NOT satisfy a query of 'Documents/Taxes': str.endswith() alone would
        match, but the match is not on a path-component boundary."""
        dar_output = "drwxr-xr-x user group 4096 2026-01-01 home/pj/MyDocuments/Taxes"
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("Documents/Taxes", "/archive/path", mock_runner, 30)
        assert result is False

    def test_directory_on_slash_boundary_matched(self, mock_runner) -> None:
        """The same query matches when preceded by '/', a real component boundary."""
        dar_output = "drwxr-xr-x user group 4096 2026-01-01 home/pj/Documents/Taxes"
        mock_runner.run.return_value = CommandResult(0, dar_output, "", note=None)

        result = _is_directory_in_archive("Documents/Taxes", "/archive/path", mock_runner, 30)
        assert result is True


# ===========================================================================
# _format_chain_item
# ===========================================================================


class TestFormatChainItem:
    """Tests for _format_chain_item."""

    def test_with_archive_info_formats_correctly(self) -> None:
        """Formats chain item with datetime and archive type."""
        info_by_no = {1: (datetime.datetime(2026, 1, 15, 10, 30, 0), "FULL")}
        result = _format_chain_item(1, info_by_no, "ok")
        assert "#1 FULL@2026-01-15 10:30:00 [ok]" in result

    def test_without_archive_info_uses_unknown(self) -> None:
        """Formats chain item without info as 'unknown'."""
        info_by_no = {}
        result = _format_chain_item(1, info_by_no, "ok")
        assert "#1 [unknown] [ok]" == result

    def test_missing_status_formats_correctly(self) -> None:
        """Formats chain item with 'missing' status."""
        info_by_no = {1: (datetime.datetime(2026, 1, 15), "DIFF")}
        result = _format_chain_item(1, info_by_no, "missing")
        assert "[missing]" in result


# ===========================================================================
# _describe_archive
# ===========================================================================


class TestDescribeArchive:
    """Tests for _describe_archive."""

    def test_with_archive_info_includes_all_fields(self) -> None:
        """Describes archive with catalog number, type, datetime, and basename."""
        archive_map = {1: "/backup/path/to/backup-20260115-FULL.1.dar"}
        info_by_no = {1: (datetime.datetime(2026, 1, 15, 10, 30, 0), "FULL")}
        result = _describe_archive(1, archive_map, info_by_no)
        assert "#1" in result
        assert "FULL" in result
        assert "2026-01-15 10:30:00" in result
        assert "backup-20260115-FULL.1.dar" in result

    def test_without_archive_info_excludes_datetime(self) -> None:
        """Describes archive without info, omitting datetime and type."""
        archive_map = {1: "/backup/path/to/backup-20260115-FULL.1.dar"}
        info_by_no = {}
        result = _describe_archive(1, archive_map, info_by_no)
        assert "#1" in result
        assert "backup-20260115-FULL.1.dar" in result
        assert "FULL@" not in result

    def test_with_missing_archive_path_uses_unknown(self) -> None:
        """Describes archive with missing path as 'unknown'."""
        archive_map = {}
        info_by_no = {1: (datetime.datetime(2026, 1, 15), "FULL")}
        result = _describe_archive(1, archive_map, info_by_no)
        assert "#1" in result
        assert "unknown" in result

    def test_with_both_missing_returns_minimal(self) -> None:
        """Describes archive with both path and info missing."""
        archive_map = {}
        info_by_no = {}
        result = _describe_archive(999, archive_map, info_by_no)
        assert "#999" in result
        assert "unknown" in result


# ===========================================================================
# _select_archive_chain additional edge cases
# ===========================================================================


class TestSelectArchiveChainAdditional:
    """Additional edge cases for _select_archive_chain."""

    def test_when_dt_between_diff_and_incr_excludes_incr(self) -> None:
        """when_dt between DIFF and INCR selects FULL+DIFF but NOT INCR."""
        info = [
            (1, datetime.datetime(2026, 1, 15, 0, 0, 0), "FULL"),
            (2, datetime.datetime(2026, 1, 15, 6, 0, 0), "DIFF"),
            (3, datetime.datetime(2026, 1, 15, 18, 0, 0), "INCR"),
        ]
        when_dt = datetime.datetime(2026, 1, 15, 12, 0, 0)  # Between DIFF (06:00) and INCR (18:00)
        chain = _select_archive_chain(info, when_dt)
        assert chain == [1, 2], f"Expected [1, 2] (FULL+DIFF only), got {chain}"

    def test_when_dt_exactly_at_diff_includes_diff(self) -> None:
        """when_dt exactly matching DIFF timestamp includes DIFF in chain."""
        info = [
            (1, datetime.datetime(2026, 1, 15, 0, 0, 0), "FULL"),
            (2, datetime.datetime(2026, 1, 15, 6, 0, 0), "DIFF"),
            (3, datetime.datetime(2026, 1, 15, 12, 0, 0), "INCR"),
        ]
        when_dt = datetime.datetime(2026, 1, 15, 6, 0, 0)  # Exactly at DIFF
        chain = _select_archive_chain(info, when_dt)
        assert 2 in chain, "DIFF should be included when when_dt matches exactly"

    def test_when_dt_exactly_at_incr_includes_full_diff_incr(self) -> None:
        """when_dt exactly matching INCR timestamp includes FULL+DIFF+INCR."""
        info = [
            (1, datetime.datetime(2026, 1, 15, 0, 0, 0), "FULL"),
            (2, datetime.datetime(2026, 1, 15, 6, 0, 0), "DIFF"),
            (3, datetime.datetime(2026, 1, 15, 12, 0, 0), "INCR"),
        ]
        when_dt = datetime.datetime(2026, 1, 15, 12, 0, 0)  # Exactly at INCR
        chain = _select_archive_chain(info, when_dt)
        assert chain == [1, 2, 3], f"Expected [1, 2, 3], got {chain}"


# ===========================================================================
# _line_path_matches
# ===========================================================================


class TestLinePathMatches:
    """Tests for _line_path_matches path/field-boundary matching.

    Guards the fix that a plain str.endswith() must not match a query path
    across a component boundary (e.g. 'Documents/Taxes' vs 'MyDocuments/Taxes').
    """

    def test_whole_line_equals_path(self) -> None:
        """Path at the very start of the line (nothing preceding) matches."""
        assert _line_path_matches("Documents/Taxes", "Documents/Taxes") is True

    def test_preceded_by_slash_matches(self) -> None:
        """A '/' before the match is a real path-component boundary."""
        assert _line_path_matches("home/pj/Documents/Taxes", "Documents/Taxes") is True

    def test_preceded_by_space_matches(self) -> None:
        """dar prints the path as the final space-separated field."""
        line = "drwxr-xr-x user group 4 kio 2026-01-01 Documents/Taxes"
        assert _line_path_matches(line, "Documents/Taxes") is True

    def test_preceded_by_tab_matches(self) -> None:
        """A tab is treated as a field boundary too."""
        assert _line_path_matches("meta\tDocuments/Taxes", "Documents/Taxes") is True

    def test_sibling_prefix_not_matched(self) -> None:
        """'MyDocuments/Taxes' ends with 'Documents/Taxes' but is a different path."""
        assert _line_path_matches("home/pj/MyDocuments/Taxes", "Documents/Taxes") is False

    def test_partial_component_not_matched(self) -> None:
        """A suffix not on a component boundary ('axes' inside 'Taxes') is rejected."""
        assert _line_path_matches("archive/Taxes", "axes") is False

    def test_line_not_ending_with_path(self) -> None:
        """No trailing match at all returns False."""
        assert _line_path_matches("path/to/other", "path/to/dir") is False

    def test_empty_path_returns_false(self) -> None:
        """An empty path never matches (avoids a vacuous endswith('') == True)."""
        assert _line_path_matches("anything at all", "") is False

    def test_empty_line_returns_false(self) -> None:
        """An empty line cannot end with a non-empty path."""
        assert _line_path_matches("", "Documents/Taxes") is False


# ===========================================================================
# _replace_path_prefix
# ===========================================================================


class TestReplacePathPrefix:
    """Tests for _replace_path_prefix directory-prefix rewriting (relocate)."""

    def test_exact_match_replaced(self) -> None:
        """A path equal to old_prefix is rewritten to new_prefix."""
        assert _replace_path_prefix("/old/path", "/old/path", "/new/path") == "/new/path"

    def test_nested_path_replaced(self) -> None:
        """A path nested under old_prefix keeps its suffix under new_prefix."""
        assert _replace_path_prefix("/old/path/sub", "/old/path", "/new/path") == "/new/path/sub"

    def test_trailing_slash_in_old_prefix_normalized(self) -> None:
        """A trailing slash on old_prefix is normalised away before matching."""
        assert _replace_path_prefix("/old/path/sub", "/old/path/", "/new/path") == "/new/path/sub"

    def test_unrelated_path_returns_none(self) -> None:
        """A path that shares no prefix is left alone (None)."""
        assert _replace_path_prefix("/keep/path", "/old/path", "/new/path") is None

    def test_sibling_prefix_not_matched(self) -> None:
        """'/mnt/backups' must NOT be rewritten by old_prefix '/mnt/back' — the
        prefix has to fall on a directory boundary, not a bare substring."""
        assert _replace_path_prefix("/mnt/backups", "/mnt/back", "/new") is None

    def test_sibling_prefix_nested_not_matched(self) -> None:
        """'/mnt/backups/x' shares the string '/mnt/back' but is not under it."""
        assert _replace_path_prefix("/mnt/backups/x", "/mnt/back", "/new") is None


# ===========================================================================
# _resolve_pitr_path — the SHARED detect/select decision
# ===========================================================================

class TestResolvePitrPath:
    """Tests for _resolve_pitr_path, the single source of truth for PITR
    directory-vs-file detection and archive chain/version selection.

    Both _pitr_chain_report (dry run) and _restore_with_dar (real restore) route
    through this function, so pinning its behaviour here pins theirs: they can no
    longer drift on which archives a given (path, when) would/will restore.
    """

    def test_directory_returns_complete_chain_plan(self, tmp_path, mock_runner) -> None:
        """A directory whose whole chain is on disk yields a chain plan with no
        error and no missing slices."""
        full_path = str(tmp_path / "example_FULL_2026-01-29")
        open(full_path + ".1.dar", "w").close()
        archive_map = {1: full_path}
        archive_info = [(1, datetime.datetime(2026, 1, 29, 2, 0, 0), "FULL")]
        when_dt = datetime.datetime(2026, 1, 29, 16, 0, 0)

        with patch("dar_backup.manager._detect_directory", return_value=True):
            plan = _resolve_pitr_path(
                "some/dir", when_dt, "/db.db", archive_map, archive_info, mock_runner, 30, "/"
            )

        assert plan.is_directory is True
        assert plan.chain == [1]
        assert plan.chain_missing == []
        assert plan.candidates == []
        assert plan.error is None

    def test_directory_no_full_returns_error(self, mock_runner) -> None:
        """A directory with no FULL archive at/before when_dt yields an error plan."""
        archive_map = {2: "/backups/example_DIFF_2026-01-29"}
        archive_info = [(2, datetime.datetime(2026, 1, 29), "DIFF")]  # no FULL
        when_dt = datetime.datetime(2026, 1, 29, 16, 0, 0)

        with patch("dar_backup.manager._detect_directory", return_value=True):
            plan = _resolve_pitr_path(
                "some/dir", when_dt, "/db.db", archive_map, archive_info, mock_runner, 30, "/"
            )

        assert plan.is_directory is True
        assert plan.chain == []
        assert plan.error is not None
        assert "No FULL archive" in plan.error

    def test_directory_missing_slice_is_reported_in_chain_missing(self, mock_runner) -> None:
        """A directory whose chain is selected but whose slice is absent from disk
        yields chain_missing (not an error): the archive is known but unusable."""
        archive_map = {1: "/backups/example_FULL_2026-01-29"}  # no .1.dar on disk
        archive_info = [(1, datetime.datetime(2026, 1, 29, 2, 0, 0), "FULL")]
        when_dt = datetime.datetime(2026, 1, 29, 16, 0, 0)

        with patch("dar_backup.manager._detect_directory", return_value=True):
            plan = _resolve_pitr_path(
                "some/dir", when_dt, "/db.db", archive_map, archive_info, mock_runner, 30, "/"
            )

        assert plan.is_directory is True
        assert plan.chain == [1]
        assert plan.error is None
        assert plan.chain_missing == ["/backups/example_FULL_2026-01-29.1.dar"]

    # Shared file-branch fixtures: archives #1 FULL@Jan29, #3 DIFF@Jan30,
    # #5 DIFF@Feb01, dated via their names as in production.
    _FILE_ARCHIVE_MAP = {
        1: "/backups/example_FULL_2026-01-29",
        3: "/backups/example_DIFF_2026-01-30",
        5: "/backups/example_DIFF_2026-02-01",
    }
    _FILE_ARCHIVE_INFO = [
        (1, datetime.datetime(2026, 1, 29), "FULL"),
        (3, datetime.datetime(2026, 1, 30), "DIFF"),
        (5, datetime.datetime(2026, 2, 1), "DIFF"),
    ]

    def test_file_returns_candidates_sorted_latest_first(self, mock_runner) -> None:
        """A file yields (catalog_no, archive_date) candidates for archives
        created at/before when_dt, newest archive first; archives created after
        when_dt are excluded regardless of the mtimes dar_manager -f reports."""
        mock_runner.run.return_value = CommandResult(
            0,
            "1 Thu Jan 29 15:00:34 2026  saved\n"
            "3 Fri Jan 30 10:00:00 2026  saved\n"
            "5 Sun Feb 01 09:00:00 2026  saved\n",
            "",
            note=None,
        )
        when_dt = datetime.datetime(2026, 1, 31, 0, 0, 0)  # excludes #5 (archive Feb 01)

        with patch("dar_backup.manager._detect_directory", return_value=False):
            plan = _resolve_pitr_path(
                "some/file.txt", when_dt, "/db.db",
                self._FILE_ARCHIVE_MAP, self._FILE_ARCHIVE_INFO, mock_runner, 30, "/"
            )

        assert plan.is_directory is False
        assert [num for num, _dt in plan.candidates] == [3, 1], "newest archive first"
        # The dates carried in candidates are ARCHIVE dates, not -f mtimes.
        assert [dt for _num, dt in plan.candidates] == [
            datetime.datetime(2026, 1, 30),
            datetime.datetime(2026, 1, 29),
        ]
        assert plan.error is None

    def test_file_old_mtime_in_later_archive_is_excluded(self, mock_runner) -> None:
        """PITR contract: a version with an OLD mtime recorded in an archive
        created AFTER when_dt must be excluded.

        This is the rename/edit trap from doc/pitr-archive-date-vs-file-mtime.md:
        a rename keeps the original mtime, so mtime-based selection would
        resurrect content from an archive that did not exist at when_dt.
        Selection must use the archive date (#5 = Feb 01), not the mtime (Jan 28).
        """
        mock_runner.run.return_value = CommandResult(
            0,
            "1 Thu Jan 29 15:00:34 2026  saved\n"
            "5 Wed Jan 28 08:00:00 2026  saved\n",  # mtime BEFORE when — archive AFTER when
            "",
            note=None,
        )
        when_dt = datetime.datetime(2026, 1, 31, 0, 0, 0)

        with patch("dar_backup.manager._detect_directory", return_value=False):
            plan = _resolve_pitr_path(
                "some/file.txt", when_dt, "/db.db",
                self._FILE_ARCHIVE_MAP, self._FILE_ARCHIVE_INFO, mock_runner, 30, "/"
            )

        assert [num for num, _dt in plan.candidates] == [1], (
            "#5's archive postdates when_dt: its old-mtime version must not be a candidate"
        )
        assert plan.error is None

    def test_file_same_date_full_and_diff_prefers_diff(self, mock_runner) -> None:
        """Same-date FULL and DIFF (date-only names) tie-break by backup order:
        the DIFF is the newer capture and must rank first, matching
        _select_archive_chain's ordering for directories."""
        archive_map = {
            1: "/backups/example_FULL_2026-01-29",
            2: "/backups/example_DIFF_2026-01-29",
        }
        archive_info = [
            (1, datetime.datetime(2026, 1, 29), "FULL"),
            (2, datetime.datetime(2026, 1, 29), "DIFF"),
        ]
        mock_runner.run.return_value = CommandResult(
            0,
            "1 Thu Jan 29 10:00:00 2026  saved\n"
            "2 Thu Jan 29 12:00:00 2026  saved\n",
            "",
            note=None,
        )
        when_dt = datetime.datetime(2026, 1, 29, 18, 0, 0)

        with patch("dar_backup.manager._detect_directory", return_value=False):
            plan = _resolve_pitr_path(
                "some/file.txt", when_dt, "/db.db",
                archive_map, archive_info, mock_runner, 30, "/"
            )

        assert [num for num, _dt in plan.candidates] == [2, 1], (
            "same-date tie-break must prefer DIFF over FULL"
        )

    def test_file_unresolvable_catalog_number_returns_error(self, mock_runner) -> None:
        """A catalog number from dar_manager -f with no dated archive entry
        yields an error plan: without its archive date the versions cannot be
        ordered safely, so nothing is restored."""
        mock_runner.run.return_value = CommandResult(
            0,
            "1 Thu Jan 29 15:00:34 2026  saved\n"
            "9 Fri Jan 30 10:00:00 2026  saved\n",  # #9 not in archive_info
            "",
            note=None,
        )
        when_dt = datetime.datetime(2026, 1, 31, 0, 0, 0)

        with patch("dar_backup.manager._detect_directory", return_value=False):
            plan = _resolve_pitr_path(
                "some/file.txt", when_dt, "/db.db",
                self._FILE_ARCHIVE_MAP, self._FILE_ARCHIVE_INFO, mock_runner, 30, "/"
            )

        assert plan.candidates == []
        assert plan.error is not None
        assert "#9" in plan.error
        assert "could not be resolved to a dated archive" in plan.error

    def test_file_absent_from_catalog_rc2_is_benign(self, mock_runner) -> None:
        """dar_manager -f exits 2 with 'Non existent file in database' for a
        path the catalog never recorded — that is a benign 'no versions'
        answer, not a lookup failure (message must stay actionable)."""
        mock_runner.run.return_value = CommandResult(
            2, "", "FATAL error, aborting operation: Non existent file in database", note=None
        )
        when_dt = datetime.datetime(2026, 1, 31, 0, 0, 0)

        with patch("dar_backup.manager._detect_directory", return_value=False):
            plan = _resolve_pitr_path(
                "never/backed/up.txt", when_dt, "/db.db",
                self._FILE_ARCHIVE_MAP, self._FILE_ARCHIVE_INFO, mock_runner, 30, "/"
            )

        assert plan.candidates == []
        assert plan.error is not None
        assert "No archive version found" in plan.error
        assert "Version lookup failed" not in plan.error

    def test_file_lookup_corrupt_db_with_rc0_returns_lookup_error(self, mock_runner) -> None:
        """A corrupted database can make dar_manager -f exit 0 with 'Corrupted
        database' text and no version lines (verified empirically, no-tty
        case). This must surface as a failed lookup — not as the misleading
        'No archive version found'."""
        corrupt_text = "Corrupted database :Error reading database /db.db : Cannot open file"
        mock_runner.run.return_value = CommandResult(0, corrupt_text, corrupt_text, note=None)
        when_dt = datetime.datetime(2026, 1, 31, 0, 0, 0)

        with patch("dar_backup.manager._detect_directory", return_value=False):
            plan = _resolve_pitr_path(
                "some/file.txt", when_dt, "/db.db",
                self._FILE_ARCHIVE_MAP, self._FILE_ARCHIVE_INFO, mock_runner, 30, "/"
            )

        assert plan.candidates == []
        assert plan.error is not None
        assert "Version lookup failed" in plan.error
        assert "Corrupted database" in plan.error

    def test_file_lookup_nonzero_rc_returns_lookup_error(self, mock_runner) -> None:
        """Any other nonzero dar_manager -f exit fails the lookup: partial
        output must not silently become the version list."""
        mock_runner.run.return_value = CommandResult(
            5,
            "1 Thu Jan 29 15:00:34 2026  saved\n",  # partial but parseable
            "dar_manager: I/O error reading database",
            note=None,
        )
        when_dt = datetime.datetime(2026, 1, 31, 0, 0, 0)

        with patch("dar_backup.manager._detect_directory", return_value=False):
            plan = _resolve_pitr_path(
                "some/file.txt", when_dt, "/db.db",
                self._FILE_ARCHIVE_MAP, self._FILE_ARCHIVE_INFO, mock_runner, 30, "/"
            )

        assert plan.candidates == [], "partial output must not become candidates"
        assert plan.error is not None
        assert "Version lookup failed" in plan.error
        assert "rc=5" in plan.error

    def test_file_no_version_at_or_before_when_returns_error(self, mock_runner) -> None:
        """A file recorded only in archives created after when_dt yields an
        error plan."""
        mock_runner.run.return_value = CommandResult(
            0, "5 Sun Feb 01 09:00:00 2026  saved\n", "", note=None
        )
        when_dt = datetime.datetime(2026, 1, 15, 0, 0, 0)  # before archive #5 (Feb 01)

        with patch("dar_backup.manager._detect_directory", return_value=False):
            plan = _resolve_pitr_path(
                "some/file.txt", when_dt, "/db.db",
                self._FILE_ARCHIVE_MAP, self._FILE_ARCHIVE_INFO, mock_runner, 30, "/"
            )

        assert plan.is_directory is False
        assert plan.candidates == []
        assert plan.error is not None
        assert "No archive version found" in plan.error
