# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for dar_backup.dashboard module."""

import os
import socket
import subprocess
import sys
import textwrap
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from dar_backup.dashboard import (
    DEFAULT_CONFIG,
    DEFAULT_PORT,
    STARTUP_TIMEOUT,
    check_datasette_installed,
    find_free_port,
    get_dashboard_html_path,
    get_datasette_path,
    main,
    resolve_config_file,
    resolve_db_path,
    wait_for_datasette,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# find_free_port
# ---------------------------------------------------------------------------

class TestFindFreePort:
    """Tests for find_free_port()."""

    def test_find_free_port_returns_preferred_when_available(self) -> None:
        """Preferred port is returned when it is free."""
        port = find_free_port(0)  # port 0 is always bindable by the OS
        # The function tries port 0 first; if it binds, it returns 0.
        assert port == 0

    def test_find_free_port_skips_occupied_port(self) -> None:
        """If preferred port is occupied, the next free one is returned."""
        # Occupy a port so find_free_port must skip it.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            occupied_port = s.getsockname()[1]
            result = find_free_port(occupied_port)
            assert result != occupied_port
            assert occupied_port + 1 <= result < occupied_port + 20

    def test_find_free_port_raises_when_all_busy(self) -> None:
        """RuntimeError is raised when no port in the range is free."""
        def always_busy(addr: tuple) -> None:
            raise OSError("Address already in use")

        with patch("socket.socket") as mock_sock_cls:
            mock_ctx = MagicMock()
            mock_ctx.bind = always_busy
            mock_sock_cls.return_value.__enter__ = MagicMock(return_value=mock_ctx)
            mock_sock_cls.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(RuntimeError, match="Could not find a free port"):
                find_free_port(9000)


# ---------------------------------------------------------------------------
# wait_for_datasette
# ---------------------------------------------------------------------------

class TestWaitForDatasette:
    """Tests for wait_for_datasette()."""

    @patch("dar_backup.dashboard.time")
    @patch("dar_backup.dashboard.urllib.request.urlopen" if False else "urllib.request.urlopen")
    def test_wait_for_datasette_returns_true_when_ready(self, mock_urlopen: MagicMock, mock_time: MagicMock) -> None:
        """Returns True immediately when Datasette responds."""
        # time.time() returns an advancing clock; first call sets deadline,
        # second call is within deadline, urlopen succeeds immediately.
        mock_time.time = MagicMock(side_effect=[0, 0, 0])
        mock_time.sleep = MagicMock()
        mock_urlopen.return_value = MagicMock()

        with patch("builtins.print"):
            result = wait_for_datasette(8001, timeout=5)
        assert result is True

    @patch("dar_backup.dashboard.time")
    def test_wait_for_datasette_returns_false_on_timeout(self, mock_time: MagicMock) -> None:
        """Returns False when Datasette never responds within the timeout."""
        # First call: sets deadline (0 + 1 = 1).
        # Second call: check while condition -> 0 < 1 -> enter loop.
        # urlopen raises -> sleep -> time check for dot printing -> loop back.
        # Third call: check while condition -> 100 > 1 -> exit loop.
        # time.time() calls: deadline, last_dot, while-check, if-check, while-check(exit)
        mock_time.time = MagicMock(side_effect=[0, 0, 0, 0, 100])
        mock_time.sleep = MagicMock()

        with patch("builtins.print"), \
             patch("urllib.request.urlopen", side_effect=Exception("refused")):
            result = wait_for_datasette(8001, timeout=1)
        assert result is False


# ---------------------------------------------------------------------------
# resolve_config_file
# ---------------------------------------------------------------------------

class TestResolveConfigFile:
    """Tests for resolve_config_file()."""

    def test_resolve_config_file_cli_takes_precedence(self) -> None:
        """CLI argument wins over env var and default."""
        with patch.dict(os.environ, {"DAR_BACKUP_CONFIG_FILE": "/env/path.conf"}):
            result = resolve_config_file("/cli/path.conf")
        assert result == "/cli/path.conf"

    def test_resolve_config_file_env_var_used_when_no_cli(self) -> None:
        """Env var is used when CLI argument is None."""
        with patch.dict(os.environ, {"DAR_BACKUP_CONFIG_FILE": "/env/path.conf"}):
            result = resolve_config_file(None)
        assert result == "/env/path.conf"

    def test_resolve_config_file_default_when_nothing_set(self) -> None:
        """Default path is used when neither CLI nor env var is set."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove DAR_BACKUP_CONFIG_FILE if present
            os.environ.pop("DAR_BACKUP_CONFIG_FILE", None)
            result = resolve_config_file(None)
        expected = os.path.expanduser(DEFAULT_CONFIG)
        assert result == expected

    def test_resolve_config_file_strips_whitespace(self) -> None:
        """Leading/trailing whitespace is stripped from both CLI and env values."""
        result = resolve_config_file("  /cli/path.conf  ")
        assert result == "/cli/path.conf"

    def test_resolve_config_file_expands_tilde(self) -> None:
        """Tilde is expanded to the user's home directory."""
        result = resolve_config_file("~/my.conf")
        assert result == os.path.expanduser("~/my.conf")
        assert "~" not in result

    def test_resolve_config_file_env_var_whitespace_stripped(self) -> None:
        """Whitespace-only env var falls back to default."""
        with patch.dict(os.environ, {"DAR_BACKUP_CONFIG_FILE": "   "}):
            result = resolve_config_file(None)
        expected = os.path.expanduser(DEFAULT_CONFIG)
        assert result == expected


# ---------------------------------------------------------------------------
# resolve_db_path
# ---------------------------------------------------------------------------

class TestResolveDbPath:
    """Tests for resolve_db_path()."""

    def test_resolve_db_path_arg_takes_precedence(self, tmp_path: pytest.TempPathFactory) -> None:
        """--db argument wins over config file."""
        result = resolve_db_path("/explicit/db.sqlite", str(tmp_path / "nonexistent.conf"))
        assert result == "/explicit/db.sqlite"

    def test_resolve_db_path_expands_tilde_in_arg(self) -> None:
        """Tilde in --db argument is expanded."""
        result = resolve_db_path("~/metrics.db", "/nonexistent.conf")
        assert "~" not in result
        assert result.endswith("metrics.db")

    def test_resolve_db_path_returns_empty_when_no_config(self, tmp_path: pytest.TempPathFactory) -> None:
        """Returns empty string when no --db and config file does not exist."""
        result = resolve_db_path(None, str(tmp_path / "no-such-file.conf"))
        assert result == ""

    def test_resolve_db_path_reads_from_config(self, tmp_path: pytest.TempPathFactory) -> None:
        """Reads METRICS_DB_PATH from config file when --db is not given."""
        config_file = tmp_path / "dar-backup.conf"
        db_file = tmp_path / "metrics.db"

        mock_cfg = MagicMock()
        mock_cfg.metrics_db_path = str(db_file)

        with patch("dar_backup.config_settings.ConfigSettings", return_value=mock_cfg):
            # The config file must exist and be readable
            config_file.touch()
            result = resolve_db_path(None, str(config_file))
        assert result == str(db_file)

    def test_resolve_db_path_returns_empty_on_config_error(self, tmp_path: pytest.TempPathFactory) -> None:
        """Returns empty string when ConfigSettings raises an exception."""
        config_file = tmp_path / "dar-backup.conf"
        config_file.touch()

        with patch("dar_backup.config_settings.ConfigSettings", side_effect=Exception("bad config")):
            result = resolve_db_path(None, str(config_file))
        assert result == ""


# ---------------------------------------------------------------------------
# get_dashboard_html_path
# ---------------------------------------------------------------------------

class TestGetDashboardHtmlPath:
    """Tests for get_dashboard_html_path()."""

    def test_get_dashboard_html_path_returns_string(self) -> None:
        """Returns a non-empty string path."""
        path = get_dashboard_html_path()
        assert isinstance(path, str)
        assert len(path) > 0

    def test_get_dashboard_html_path_ends_with_dashboard_html(self) -> None:
        """Returned path ends with 'dashboard.html'."""
        path = get_dashboard_html_path()
        assert path.endswith("dashboard.html")


# ---------------------------------------------------------------------------
# get_datasette_path / check_datasette_installed
# ---------------------------------------------------------------------------

class TestGetDatasettePath:
    """Tests for get_datasette_path() and check_datasette_installed()."""

    def test_get_datasette_path_finds_venv_binary(self, tmp_path: pytest.TempPathFactory) -> None:
        """Returns the path next to sys.executable when it exists and is executable."""
        fake_datasette = tmp_path / "datasette"
        fake_datasette.touch()
        fake_datasette.chmod(0o755)

        with patch("dar_backup.dashboard.sys") as mock_sys:
            mock_sys.executable = str(tmp_path / "python3")
            result = get_datasette_path()
        assert result == str(fake_datasette)

    def test_get_datasette_path_falls_back_to_which(self) -> None:
        """Falls back to shutil.which when venv binary does not exist."""
        with patch("dar_backup.dashboard.sys") as mock_sys, \
             patch("shutil.which", return_value="/usr/bin/datasette"):
            mock_sys.executable = "/nonexistent/python3"
            result = get_datasette_path()
        assert result == "/usr/bin/datasette"

    def test_get_datasette_path_returns_empty_when_not_found(self) -> None:
        """Returns empty string when datasette is not found anywhere."""
        with patch("dar_backup.dashboard.sys") as mock_sys, \
             patch("shutil.which", return_value=None):
            mock_sys.executable = "/nonexistent/python3"
            result = get_datasette_path()
        assert result == ""

    def test_check_datasette_installed_true(self) -> None:
        """Returns True when get_datasette_path finds something."""
        with patch("dar_backup.dashboard.get_datasette_path", return_value="/usr/bin/datasette"):
            assert check_datasette_installed() is True

    def test_check_datasette_installed_false(self) -> None:
        """Returns False when get_datasette_path returns empty string."""
        with patch("dar_backup.dashboard.get_datasette_path", return_value=""):
            assert check_datasette_installed() is False


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

class TestMain:
    """Tests for the main() entry point."""

    def test_main_exits_when_datasette_not_installed(self) -> None:
        """Exits with code 1 and error message when datasette is not installed."""
        with patch("dar_backup.dashboard.check_datasette_installed", return_value=False), \
             patch("sys.argv", ["dar-backup-dashboard"]), \
             pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_main_exits_when_db_path_empty(self, tmp_path: pytest.TempPathFactory) -> None:
        """Exits with code 1 when no db path can be resolved."""
        with patch("dar_backup.dashboard.check_datasette_installed", return_value=True), \
             patch("dar_backup.dashboard.resolve_config_file", return_value=str(tmp_path / "c.conf")), \
             patch("dar_backup.dashboard.resolve_db_path", return_value=""), \
             patch("sys.argv", ["dar-backup-dashboard"]), \
             pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_main_exits_when_db_file_missing(self, tmp_path: pytest.TempPathFactory) -> None:
        """Exits with code 1 when resolved db file does not exist on disk."""
        with patch("dar_backup.dashboard.check_datasette_installed", return_value=True), \
             patch("dar_backup.dashboard.resolve_config_file", return_value=str(tmp_path / "c.conf")), \
             patch("dar_backup.dashboard.resolve_db_path", return_value=str(tmp_path / "no.db")), \
             patch("sys.argv", ["dar-backup-dashboard"]), \
             pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_main_exits_when_dashboard_html_not_found(self, tmp_path: pytest.TempPathFactory) -> None:
        """Exits with code 1 when dashboard.html cannot be located."""
        db_file = tmp_path / "metrics.db"
        db_file.touch()

        with patch("dar_backup.dashboard.check_datasette_installed", return_value=True), \
             patch("dar_backup.dashboard.resolve_config_file", return_value=str(tmp_path / "c.conf")), \
             patch("dar_backup.dashboard.resolve_db_path", return_value=str(db_file)), \
             patch("dar_backup.dashboard.get_dashboard_html_path", side_effect=Exception("not found")), \
             patch("sys.argv", ["dar-backup-dashboard"]), \
             pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_main_exits_when_no_free_port(self, tmp_path: pytest.TempPathFactory) -> None:
        """Exits with code 1 when find_free_port raises RuntimeError."""
        db_file = tmp_path / "metrics.db"
        db_file.touch()

        with patch("dar_backup.dashboard.check_datasette_installed", return_value=True), \
             patch("dar_backup.dashboard.resolve_config_file", return_value=str(tmp_path / "c.conf")), \
             patch("dar_backup.dashboard.resolve_db_path", return_value=str(db_file)), \
             patch("dar_backup.dashboard.get_dashboard_html_path", return_value="/fake/dashboard.html"), \
             patch("dar_backup.dashboard.find_free_port", side_effect=RuntimeError("no port")), \
             patch("sys.argv", ["dar-backup-dashboard"]), \
             pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_main_starts_datasette_and_opens_browser(self, tmp_path: pytest.TempPathFactory) -> None:
        """Happy path: Datasette starts, browser opens, then KeyboardInterrupt exits cleanly."""
        db_file = tmp_path / "metrics.db"
        db_file.touch()

        mock_proc = MagicMock()
        mock_proc.wait = MagicMock(side_effect=[KeyboardInterrupt, None])
        mock_proc.terminate = MagicMock()

        with patch("dar_backup.dashboard.check_datasette_installed", return_value=True), \
             patch("dar_backup.dashboard.resolve_config_file", return_value=str(tmp_path / "c.conf")), \
             patch("dar_backup.dashboard.resolve_db_path", return_value=str(db_file)), \
             patch("dar_backup.dashboard.get_dashboard_html_path", return_value=str(tmp_path / "dashboard.html")), \
             patch("dar_backup.dashboard.find_free_port", return_value=8001), \
             patch("dar_backup.dashboard.get_datasette_path", return_value="/usr/bin/datasette"), \
             patch("dar_backup.dashboard.subprocess.Popen", return_value=mock_proc), \
             patch("dar_backup.dashboard.wait_for_datasette", return_value=True), \
             patch("webbrowser.open") as mock_browser, \
             patch("sys.argv", ["dar-backup-dashboard"]), \
             patch("builtins.print"), \
             pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0
        mock_browser.assert_called_once()
        mock_proc.terminate.assert_called_once()

    def test_main_no_browser_flag_skips_browser(self, tmp_path: pytest.TempPathFactory) -> None:
        """--no-browser flag prevents webbrowser.open from being called."""
        db_file = tmp_path / "metrics.db"
        db_file.touch()

        mock_proc = MagicMock()
        mock_proc.wait = MagicMock(side_effect=[KeyboardInterrupt, None])
        mock_proc.terminate = MagicMock()

        with patch("dar_backup.dashboard.check_datasette_installed", return_value=True), \
             patch("dar_backup.dashboard.resolve_config_file", return_value=str(tmp_path / "c.conf")), \
             patch("dar_backup.dashboard.resolve_db_path", return_value=str(db_file)), \
             patch("dar_backup.dashboard.get_dashboard_html_path", return_value=str(tmp_path / "dashboard.html")), \
             patch("dar_backup.dashboard.find_free_port", return_value=8001), \
             patch("dar_backup.dashboard.get_datasette_path", return_value="/usr/bin/datasette"), \
             patch("dar_backup.dashboard.subprocess.Popen", return_value=mock_proc), \
             patch("dar_backup.dashboard.wait_for_datasette", return_value=True), \
             patch("webbrowser.open") as mock_browser, \
             patch("sys.argv", ["dar-backup-dashboard", "--no-browser"]), \
             patch("builtins.print"), \
             pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0
        mock_browser.assert_not_called()

    def test_main_port_fallback_prints_message(self, tmp_path: pytest.TempPathFactory) -> None:
        """When find_free_port returns a different port, an info message is printed."""
        db_file = tmp_path / "metrics.db"
        db_file.touch()

        mock_proc = MagicMock()
        mock_proc.wait = MagicMock(side_effect=[KeyboardInterrupt, None])
        mock_proc.terminate = MagicMock()

        printed: list[str] = []

        def capture_print(*args: object, **kwargs: object) -> None:
            printed.append(" ".join(str(a) for a in args))

        with patch("dar_backup.dashboard.check_datasette_installed", return_value=True), \
             patch("dar_backup.dashboard.resolve_config_file", return_value=str(tmp_path / "c.conf")), \
             patch("dar_backup.dashboard.resolve_db_path", return_value=str(db_file)), \
             patch("dar_backup.dashboard.get_dashboard_html_path", return_value=str(tmp_path / "dashboard.html")), \
             patch("dar_backup.dashboard.find_free_port", return_value=8002), \
             patch("dar_backup.dashboard.get_datasette_path", return_value="/usr/bin/datasette"), \
             patch("dar_backup.dashboard.subprocess.Popen", return_value=mock_proc), \
             patch("dar_backup.dashboard.wait_for_datasette", return_value=True), \
             patch("webbrowser.open"), \
             patch("sys.argv", ["dar-backup-dashboard", "--port", "8001"]), \
             patch("builtins.print", side_effect=capture_print), \
             pytest.raises(SystemExit):
            main()

        assert any("8001" in msg and "8002" in msg for msg in printed)

    def test_main_datasette_file_not_found(self, tmp_path: pytest.TempPathFactory) -> None:
        """Exits with code 1 when Popen raises FileNotFoundError."""
        db_file = tmp_path / "metrics.db"
        db_file.touch()

        with patch("dar_backup.dashboard.check_datasette_installed", return_value=True), \
             patch("dar_backup.dashboard.resolve_config_file", return_value=str(tmp_path / "c.conf")), \
             patch("dar_backup.dashboard.resolve_db_path", return_value=str(db_file)), \
             patch("dar_backup.dashboard.get_dashboard_html_path", return_value=str(tmp_path / "dashboard.html")), \
             patch("dar_backup.dashboard.find_free_port", return_value=8001), \
             patch("dar_backup.dashboard.get_datasette_path", return_value="/usr/bin/datasette"), \
             patch("dar_backup.dashboard.subprocess.Popen", side_effect=FileNotFoundError), \
             patch("sys.argv", ["dar-backup-dashboard"]), \
             patch("builtins.print"), \
             pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_main_datasette_timeout_still_opens_browser(self, tmp_path: pytest.TempPathFactory) -> None:
        """Browser is opened even when Datasette does not become ready in time."""
        db_file = tmp_path / "metrics.db"
        db_file.touch()

        mock_proc = MagicMock()
        mock_proc.wait = MagicMock(side_effect=[KeyboardInterrupt, None])
        mock_proc.terminate = MagicMock()

        with patch("dar_backup.dashboard.check_datasette_installed", return_value=True), \
             patch("dar_backup.dashboard.resolve_config_file", return_value=str(tmp_path / "c.conf")), \
             patch("dar_backup.dashboard.resolve_db_path", return_value=str(db_file)), \
             patch("dar_backup.dashboard.get_dashboard_html_path", return_value=str(tmp_path / "dashboard.html")), \
             patch("dar_backup.dashboard.find_free_port", return_value=8001), \
             patch("dar_backup.dashboard.get_datasette_path", return_value="/usr/bin/datasette"), \
             patch("dar_backup.dashboard.subprocess.Popen", return_value=mock_proc), \
             patch("dar_backup.dashboard.wait_for_datasette", return_value=False), \
             patch("webbrowser.open") as mock_browser, \
             patch("sys.argv", ["dar-backup-dashboard"]), \
             patch("builtins.print"), \
             pytest.raises(SystemExit):
            main()

        mock_browser.assert_called_once()

    def test_main_kills_datasette_on_terminate_timeout(self, tmp_path: pytest.TempPathFactory) -> None:
        """If Datasette does not terminate within 5s, it is killed."""
        db_file = tmp_path / "metrics.db"
        db_file.touch()

        mock_proc = MagicMock()
        mock_proc.wait = MagicMock(
            side_effect=[KeyboardInterrupt, subprocess.TimeoutExpired(cmd="datasette", timeout=5)]
        )
        mock_proc.terminate = MagicMock()
        mock_proc.kill = MagicMock()

        with patch("dar_backup.dashboard.check_datasette_installed", return_value=True), \
             patch("dar_backup.dashboard.resolve_config_file", return_value=str(tmp_path / "c.conf")), \
             patch("dar_backup.dashboard.resolve_db_path", return_value=str(db_file)), \
             patch("dar_backup.dashboard.get_dashboard_html_path", return_value=str(tmp_path / "dashboard.html")), \
             patch("dar_backup.dashboard.find_free_port", return_value=8001), \
             patch("dar_backup.dashboard.get_datasette_path", return_value="/usr/bin/datasette"), \
             patch("dar_backup.dashboard.subprocess.Popen", return_value=mock_proc), \
             patch("dar_backup.dashboard.wait_for_datasette", return_value=True), \
             patch("webbrowser.open"), \
             patch("sys.argv", ["dar-backup-dashboard"]), \
             patch("builtins.print"), \
             pytest.raises(SystemExit):
            main()

        mock_proc.terminate.assert_called_once()
        mock_proc.kill.assert_called_once()
