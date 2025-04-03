import pytest
import os
from sys import path
from threading import Event
from unittest.mock import patch, MagicMock, mock_open
from dar_backup.rich_progress import show_log_driven_bar

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
    mock_live_class.return_value.__enter__.return_value = mock_live

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

    import time
    time.sleep(1)
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
