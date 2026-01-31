import os
from sys import path
from threading import Event
from unittest.mock import patch, MagicMock, mock_open
from dar_backup.rich_progress import show_log_driven_bar, is_terminal, tail_log_file, get_green_shade
import pytest

pytestmark = pytest.mark.unit




# Ensure the test directory is in the Python path
path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

@patch("dar_backup.rich_progress.Console")
@patch("dar_backup.rich_progress.Live")
@patch("dar_backup.rich_progress.os.path.exists", return_value=True)
@patch("dar_backup.rich_progress.os.path.getsize", return_value=100)
@patch("dar_backup.rich_progress.open", new_callable=mock_open, read_data="""\
Some unrelated log line
=== START BACKUP SESSION: 1234
Inspecting directory /home
Finished inspecting directory /home
Inspecting directory /etc
Finished inspecting directory /etc
""")
def test_show_log_driven_bar_updates_progress(
    mock_file,           # open
    mock_getsize,        # os.path.getsize
    mock_exists,         # os.path.exists
    mock_live_class,     # Live
    mock_console_class   # Console
):
    # Setup console mock
    mock_console = MagicMock()
    mock_console.is_terminal = True
    mock_console_class.return_value = mock_console

    # Setup Live mock
    mock_live = MagicMock()
    update_event = Event()

    def mark_update(*_args, **_kwargs):
        update_event.set()

    mock_live_class.return_value.__enter__.return_value = mock_live
    mock_live.update.side_effect = mark_update

    # Setup mocked file behavior
    mock_file_handle = mock_file.return_value.__enter__.return_value
    mock_file_handle.tell.return_value = 100
    mock_file_handle.seek.return_value = None

    stop_event = Event()

    import threading




    thread = threading.Thread(
        target=show_log_driven_bar,
        args=("/mock/path.log", stop_event, "=== START BACKUP SESSION: 1234", 10),
        daemon=True
    )
    thread.start()

    assert update_event.wait(timeout=1), "Progress bar update not observed"
    stop_event.set()
    thread.join()

    # ✅ Assert that progress bar updated at least once
    assert mock_live.update.call_count >= 1

    # ✅ Extract plain text from Rich objects
    updates = [call.args[0] for call in mock_live.update.call_args_list]

    def extract_plain_text(obj):
        if hasattr(obj, "plain"):
            return obj.plain
        elif hasattr(obj, "renderables"):  # Rich Group object
            return " ".join(
                r.plain if hasattr(r, "plain") else str(r)
                for r in obj.renderables
            )
        return str(obj)

    combined_text = " ".join(extract_plain_text(u) for u in updates)
    assert "📂 /etc" in combined_text or "📂 /home" in combined_text


def test_is_terminal_uses_console_flag():
    with patch("dar_backup.rich_progress.Console") as mock_console:
        mock_console.return_value.is_terminal = True
        assert is_terminal() is True

        mock_console.return_value.is_terminal = False
        assert is_terminal() is False


def test_get_green_shade_bounds():
    assert get_green_shade(0, 10) == "rgb(0,180,0)"
    assert get_green_shade(10, 10) == "rgb(0,20,0)"


def test_show_log_driven_bar_skips_when_not_terminal():
    stop_event = Event()
    mock_console = MagicMock()
    mock_console.is_terminal = False

    with patch("dar_backup.rich_progress.Console", return_value=mock_console):
        show_log_driven_bar("/tmp/missing.log", stop_event, "marker", 10)

    mock_console.log.assert_called_once()


def test_tail_log_file_yields_after_marker(tmp_path, monkeypatch):
    log_path = tmp_path / "log.txt"
    log_path.write_text(
        "before marker\n"
        "=== START SESSION ===\n"
        "line one\n"
        "line two\n",
        encoding="utf-8",
    )

    stop_event = Event()
    monkeypatch.setattr("dar_backup.rich_progress.time.sleep", lambda *_: None)

    gen = tail_log_file(str(log_path), stop_event, session_marker="=== START SESSION ===")
    first_line = next(gen)
    stop_event.set()

    assert first_line == "line one"
    with pytest.raises(StopIteration):
        next(gen)


def test_tail_log_file_missing_path_stops(monkeypatch):
    stop_event = Event()

    def fake_sleep(_):
        stop_event.set()

    monkeypatch.setattr("dar_backup.rich_progress.os.path.exists", lambda *_: False)
    monkeypatch.setattr("dar_backup.rich_progress.time.sleep", fake_sleep)

    gen = tail_log_file("/tmp/missing.log", stop_event, session_marker=None)
    with pytest.raises(StopIteration):
        next(gen)


def test_tail_log_file_logs_read_error(monkeypatch, capsys):
    stop_event = Event()

    def fake_sleep(_):
        stop_event.set()

    monkeypatch.setattr("dar_backup.rich_progress.os.path.exists", lambda *_: True)

    def boom(*args, **kwargs):
        raise OSError("boom")

    monkeypatch.setattr("builtins.open", boom)
    monkeypatch.setattr("dar_backup.rich_progress.time.sleep", fake_sleep)

    gen = tail_log_file("/tmp/log.txt", stop_event, session_marker=None)
    with pytest.raises(StopIteration):
        next(gen)

    out = capsys.readouterr().out
    assert "Error reading log" in out
