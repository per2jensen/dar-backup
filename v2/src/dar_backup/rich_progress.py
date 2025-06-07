#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import time
from threading import Event
from rich.console import Console, Group
from rich.live import Live
from rich.text import Text

def is_terminal():
    return Console().is_terminal

def tail_log_file(log_path, stop_event, session_marker=None):
    """Yields new lines from the log file, starting only after the session_marker is found."""
    last_size = 0
    marker_found = session_marker is None

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

                    line = line.strip()
                    last_size = f.tell()

                    if not marker_found:
                        if session_marker in line:
                            marker_found = True
                        continue

                    yield line

        except Exception as e:
            print(f"[!] Error reading log: {e}")

        time.sleep(0.5)

def get_green_shade(step, max_width):
    """Returns a green color from light to dark across the bar."""
    start = 180
    end = 20
    value = int(start - ((start - end) * (step / max_width)))
    return f"rgb(0,{value},0)"

def show_log_driven_bar(log_path: str, stop_event: Event, session_marker: str, max_width=50):
    console = Console()

    if not console.is_terminal:
        console.log("[~] Not a terminal — progress bar skipped.")
        return

    progress = 0
    dir_count = 0
    last_dir = "Waiting for directory..."



    with Live(console=console, refresh_per_second=5) as live:
        for line in tail_log_file(log_path, stop_event, session_marker):
            lowered = line.lower()

            updated = False

            # Update directory name on "Inspecting"
            if "inspecting directory" in lowered and "finished" not in lowered:
                last_dir = line.split("Inspecting directory")[-1].strip()
                updated = True

            # Advance progress on "Finished"
            if "finished inspecting directory" in lowered:
                dir_count += 1
                progress = (progress + 1) % (max_width + 1)
                updated = True

            if updated:
                bar_text = ""
                for i in range(max_width):
                    if i < progress:
                        color = get_green_shade(i, max_width)
                        bar_text += f"[{color}]#[/{color}]"
                    else:
                        bar_text += "-"

                bar = Text.from_markup(f"[white][{bar_text}][/white] [dim]Dirs: {dir_count}[/dim]")
                dir_display = Text(f"📂 {last_dir}", style="dim")

                live.update(Group(bar, dir_display))

            if stop_event.is_set():
                break

    # Rich prints a \n here, I will live with it