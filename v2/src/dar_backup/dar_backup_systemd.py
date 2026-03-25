#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import os
import subprocess
import argparse

REQUIRED_LANG = "en_US.UTF-8"

SERVICE_TEMPLATE = """[Unit]
Description=dar-backup {mode}
StartLimitIntervalSec=120
StartLimitBurst=1

[Service]
Type=oneshot
TimeoutSec=infinity
RemainAfterExit=no
Environment=LANG=en_US.UTF-8
ExecStart=/bin/bash -c '{exec_command}'
"""

TIMER_TEMPLATE = """[Unit]
Description=dar-backup {mode} timer

[Timer]
OnCalendar={calendar}
Persistent=true

[Install]
WantedBy=timers.target
"""

CLEANUP_SERVICE_TEMPLATE = """[Unit]
Description=cleanup up old DIFF & INCR backups
StartLimitIntervalSec=120
StartLimitBurst=1

[Service]
Type=oneshot
TimeoutSec=60
RemainAfterExit=no
Environment=LANG=en_US.UTF-8
ExecStart=/bin/bash -c '{exec_command}'
"""

CLEANUP_TIMER = """[Unit]
Description=dar-cleanup DIFF & INCR timer

[Timer]
OnCalendar=*-*-* 21:07:00

[Install]
WantedBy=timers.target
"""

TIMINGS = {
    "FULL": "*-12-30 10:03:00",
    "DIFF": "*-*-01 19:03:00",
    "INCR": "*-*-04/3 19:03:00"
}

FLAGS = {
    "FULL": "-F",
    "DIFF": "-D",
    "INCR": "-I"
}

def check_locale() -> None:
    """
    Warn if the current LANG is not en_US.UTF-8.

    dar emits backup metadata (inode counts, sizes) in a locale-sensitive
    format. Running dar-backup with a non-US locale can produce metadata that
    is unparseable or silently wrong. The generated service units set
    Environment=LANG=en_US.UTF-8 to prevent this, but this check catches
    cases where the unit generator itself is invoked from an unexpected locale.
    """
    lang = os.environ.get("LANG", "")
    if lang != REQUIRED_LANG:
        print(
            f"WARNING: LANG is {lang!r}, expected {REQUIRED_LANG!r}. "
            "dar metadata parsing may be unreliable. "
            "The generated service units set LANG=en_US.UTF-8 explicitly."
        )


def build_exec_command(venv, flag, dar_path=None, tool='dar-backup'):
    if dar_path:
        return f"PATH={dar_path}:$PATH && . {venv}/bin/activate && {tool} {flag} --verbose --log-stdout"
    return f". {venv}/bin/activate && {tool} {flag} --verbose --log-stdout"

def generate_service(mode, venv, dar_path):
    exec_command = build_exec_command(venv, FLAGS[mode], dar_path)
    return SERVICE_TEMPLATE.format(mode=mode, exec_command=exec_command)

def generate_timer(mode):
    return TIMER_TEMPLATE.format(mode=mode, calendar=TIMINGS[mode])

def generate_cleanup_service(venv, dar_path):
    exec_command = build_exec_command(venv, "", dar_path, tool='cleanup').strip()
    return CLEANUP_SERVICE_TEMPLATE.format(exec_command=exec_command)

def write_unit_file(path, filename, content):
    file_path = path / filename
    file_path.write_text(content)
    print(f"Generated {filename}")

def enable_and_start_unit(unit_name):
    subprocess.run(["systemctl", "--user", "enable", unit_name], check=False)
    subprocess.run(["systemctl", "--user", "start", unit_name], check=False)

def write_unit_files(venv, dar_path, install=False):
    output_path = Path.home() / ".config/systemd/user" if install else Path.cwd()
    output_path.mkdir(parents=True, exist_ok=True)

    for mode in FLAGS:
        service_name = f"dar-{mode.lower()}-backup.service"
        timer_name = f"dar-{mode.lower()}-backup.timer"
        write_unit_file(output_path, service_name, generate_service(mode, venv, dar_path))
        write_unit_file(output_path, timer_name, generate_timer(mode))
        print(f"  → Fires on: {TIMINGS[mode]}")

    write_unit_file(output_path, "dar-cleanup.service", generate_cleanup_service(venv, dar_path))
    write_unit_file(output_path, "dar-cleanup.timer", CLEANUP_TIMER)
    print("  → Fires on: *-*-* 21:07:00")

    if install:
        for mode in FLAGS:
            enable_and_start_unit(f"dar-{mode.lower()}-backup.timer")
        enable_and_start_unit("dar-cleanup.timer")
        subprocess.run(["systemctl", "--user", "daemon-reexec"], check=False)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        print("Systemd `dar-backup` units and timers installed and user daemon reloaded.")

def main():
    check_locale()
    parser = argparse.ArgumentParser(description="Generate systemd service and timer units for dar-backup.")
    parser.add_argument("--venv",     required=True,       help="Path to the Python venv with dar-backup")
    parser.add_argument("--dar-path",                      help="Optional path to dar binary's directory")
    parser.add_argument("--install",  action="store_true", help="Install the units to ~/.config/systemd/user")
    args = parser.parse_args()
    write_unit_files(args.venv, args.dar_path, install=args.install)

if __name__ == "__main__":
    main()
