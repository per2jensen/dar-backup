#!/usr/bin/env python3

"""
installer.py source code is here: https://github.com/per2jensen/dar-backup/tree/main/v2/src/dar_backup/installer.py
This script is part of dar-backup, a backup solution for Linux using dar and systemd.

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

This script can generate systemd service and timer units for dar-backup and cleanup.

"""

import os
from pathlib import Path
import argparse
import subprocess

SERVICE_TEMPLATE_1 = """[Unit]
Description=dar-backup {mode}
StartLimitIntervalSec=120
StartLimitBurst=1

[Service]
Type=oneshot
TimeoutSec=infinity
RemainAfterExit=no
"""

SERVICE_TEMPLATE_2_WITH_DAR = """
ExecStart=/bin/bash -c 'PATH={dar_path}:$PATH && . {venv}/bin/activate && dar-backup {flag} --verbose --log-stdout'
"""

SERVICE_TEMPLATE_2_WITHOUT_DAR = """
ExecStart=/bin/bash -c '. {venv}/bin/activate && dar-backup {flag} --verbose --log-stdout'
"""


TIMER_TEMPLATE = """[Unit]
Description=dar-backup {mode} timer

[Timer]
OnCalendar={calendar}
Persistent=true

[Install]
WantedBy=timers.target
"""

TIMINGS = {
    "FULL": "*-12-30 10:03:00",    # Every year on December 30th at 10:03 AM
    "DIFF": "*-*-01 19:03:00",     # Every month on the 1st at 19:03
    "INCR": "*-*-04/3 19:03:00"    # Every 3 days starting on the 4th of each month at 19:03
}

FLAGS = {
    "FULL": "-F",
    "DIFF": "-D",
    "INCR": "-I"
}

def write_unit_files(venv, dar_path, install=False):
    user_systemd_path = Path.home() / ".config/systemd/user"
    output_path = user_systemd_path if install else Path.cwd()
    output_path.mkdir(parents=True, exist_ok=True)

    for mode in ["FULL", "DIFF", "INCR"]:
        service_name = f"dar-{mode.lower()}-backup.service"
        timer_name = f"dar-{mode.lower()}-backup.timer"

        service_content_1 = SERVICE_TEMPLATE_1.format(mode=mode, flag=FLAGS[mode], venv=venv)
        if dar_path:
            service_content_2 = SERVICE_TEMPLATE_2_WITH_DAR.format(mode=mode, flag=FLAGS[mode], venv=venv, dar_path=dar_path)
        else:
            service_content_2 = SERVICE_TEMPLATE_2_WITHOUT_DAR.format(mode=mode, flag=FLAGS[mode], venv=venv)

        service_content = f"{service_content_1}\n{service_content_2}"    
        timer_content = TIMER_TEMPLATE.format(mode=mode, calendar=TIMINGS[mode])

        (output_path / service_name).write_text(service_content)
        (output_path / timer_name).write_text(timer_content)

        print(f"Generated {service_name} and {timer_name}")
        print(f"  → Fires on: {TIMINGS[mode]}")


    if dar_path:
        (output_path / "dar-cleanup.service").write_text(f"""[Unit]
    Description=cleanup up old DIFF & INCR backups
    StartLimitIntervalSec=120
    StartLimitBurst=1
    [Service]
    Type=oneshot
    TimeoutSec=60
    RemainAfterExit=no
    ExecStart=/bin/bash -c 'PATH={dar_path}:$PATH &&  . {venv}/bin/activate && cleanup'
    """)
    else:
        (output_path / "dar-cleanup.service").write_text(f"""[Unit]
    Description=cleanup up old DIFF & INCR backups
    StartLimitIntervalSec=120
    StartLimitBurst=1
    [Service]
    Type=oneshot
    TimeoutSec=60
    RemainAfterExit=no
    ExecStart=/bin/bash -c '. {venv}/bin/activate && cleanup'
    """)


    (output_path / "dar-cleanup.timer").write_text(f"""[Unit]
Description=dar-cleanup DIFF & INCR timer

[Timer]
OnCalendar=*-*-* 21:07:00

[Install]
WantedBy=timers.target
""")

    print(f"Generated dar-cleanup.service and dar-cleanup.timer")
    print(f"  → Fires on: *-*-* 21:07:00")


    if install:
        for mode in ["FULL", "DIFF", "INCR"]:
            subprocess.run(["systemctl", "--user", "enable", f"dar-{mode.lower()}-backup.timer"], check=False)
            subprocess.run(["systemctl", "--user", "start",  f"dar-{mode.lower()}-backup.timer"], check=False)

        subprocess.run(["systemctl", "--user", "enable", f"dar-cleanup.timer"], check=False)
        subprocess.run(["systemctl", "--user", "start",  f"dar-cleanup.timer"], check=False)


        subprocess.run(["systemctl", "--user", "daemon-reexec"], check=False)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        print("Systemd `dar-backup` units and timers installed and user daemon reloaded.")

def main():
    parser = argparse.ArgumentParser(description="Generate systemd service and timer units for dar-backup.")
    parser.add_argument("--venv",     required=True,       help="Path to the Python venv with dar-backup")
    parser.add_argument("--dar-path",                      help="Optional path to dar binary's directory")
    parser.add_argument("--install",  action="store_true", help="Install the units to ~/.config/systemd/user")

    args = parser.parse_args()
    write_unit_files(args.venv, args.dar_path, install=args.install)

if __name__ == "__main__":
    main()
