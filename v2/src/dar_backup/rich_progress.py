import os
import time
from threading import Event
from rich.console import Console
from rich.live import Live
from rich.text import Text

def is_terminal():
    return Console().is_terminal

def tail_log_file(log_path, stop_event):
    """Yields new lines, safely handling missing/rotated logs."""
    last_size = 0
    while not stop_event.is_set():
        if not os.path.exists(log_path):
            time.sleep(0.5)
            continue

        try:
            with open(log_path, "r") as f:
                if last_size > os.path.getsize(log_path):
                    f.seek(0)
                else:
                    f.seek(last_size)

                while not stop_event.is_set():
                    line = f.readline()
                    if not line:
                        break
                    yield line.strip()

                last_size = f.tell()

        except Exception as e:
            print(f"[!] Error reading log: {e}")

        time.sleep(0.5)

def get_green_shade(step, max_width):
    """Returns a green color from light to dark across the bar."""
    start = 180
    end = 20
    value = int(start - ((start - end) * (step / max_width)))
    return f"rgb(0,{value},0)"

def show_log_driven_bar(log_path: str, stop_event: Event, max_width=50):
    console = Console()

    # Terminal check – skip if running in systemd etc.
    if not console.is_terminal:
        console.log("[~] Not a terminal — progress bar skipped.")
        return

    progress = 0

    with Live(console=console, refresh_per_second=5):
        for line in tail_log_file(log_path, stop_event):
            if "Inspecting directory" in line:
                progress = (progress + 1) % (max_width + 1)

                bar_text = ""
                for i in range(max_width):
                    if i < progress:
                        color = get_green_shade(i, max_width)
                        bar_text += f"[{color}]#[/{color}]"
                    else:
                        bar_text += "-"

                text = Text.from_markup(f"[white][{bar_text}][/white]")
                console.print(text, end="\r")

            if stop_event.is_set():
                break
