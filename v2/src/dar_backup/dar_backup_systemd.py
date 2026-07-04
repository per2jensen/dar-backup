#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import os
import subprocess
import argparse
import sys
from typing import Optional

SERVICE_TEMPLATE = """[Unit]
Description=dar-backup {mode}
StartLimitIntervalSec=120
StartLimitBurst=1

[Service]
Type=oneshot
TimeoutSec=infinity
RemainAfterExit=no
# LC_MESSAGES=C keeps dar's diagnostic output in English so dar-backup can
# parse inode counts reliably.  Your LANG (any *.UTF-8 locale) is inherited
# from the session and controls file-name encoding — leave it unchanged.
Environment=LC_MESSAGES=C
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
# See SERVICE_TEMPLATE comment above for locale rationale.
Environment=LC_MESSAGES=C
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
    Warn if the current locale is not a UTF-8 locale.

    dar-backup sets LC_MESSAGES=C in generated service units so dar's
    diagnostic output is always in English (required for inode-count parsing).
    File-name encoding is governed by the user's LANG; any *.UTF-8 locale is
    fine.  This check catches cases where the generator or the backup service
    runs with a non-UTF-8 encoding, which could mangle non-ASCII file paths.
    """
    lang = os.environ.get("LANG", "")
    # Normalise away the hyphen so both "UTF-8" and "utf8" spellings match.
    if "UTF8" not in lang.upper().replace("-", ""):
        print(
            f"WARNING: LANG is {lang!r}, which is not a UTF-8 locale. "
            "Non-ASCII file paths may be mangled. "
            "Any *.UTF-8 locale (e.g. en_US.UTF-8, de_DE.UTF-8) is fine."
        )


def build_exec_command(venv: str, flag: str, dar_path: Optional[str] = None, tool: str = 'dar-backup') -> str:
    """Build the shell command embedded in a generated unit's ExecStart= line.

    Args:
        venv: Path to the Python venv containing tool.
        flag: CLI flag to pass to tool (e.g. '-F' for a full backup).
        dar_path: Optional directory to prepend to PATH so a specific dar
            binary is found first.
        tool: Console-script name to run (e.g. 'dar-backup' or 'cleanup').

    Returns:
        A shell command string that activates the venv and execs into tool.
        `exec` replaces the bash process with the tool process so systemd's
        SIGTERM reaches it directly.
    """
    if dar_path:
        return f"PATH={dar_path}:$PATH && . {venv}/bin/activate && exec {tool} {flag} --verbose --log-stdout"
    return f". {venv}/bin/activate && exec {tool} {flag} --verbose --log-stdout"

def generate_service(mode: str, venv: str, dar_path: Optional[str]) -> str:
    """Render the dar-backup service unit content for one backup mode.

    Args:
        mode: One of "FULL", "DIFF", "INCR" (a key of FLAGS/TIMINGS).
        venv: Path to the Python venv containing dar-backup.
        dar_path: Optional directory to prepend to PATH for the dar binary.

    Returns:
        The unit file content (SERVICE_TEMPLATE filled in).
    """
    exec_command = build_exec_command(venv, FLAGS[mode], dar_path)
    return SERVICE_TEMPLATE.format(mode=mode, exec_command=exec_command)

def generate_timer(mode: str) -> str:
    """Render the systemd timer unit content for one backup mode.

    Args:
        mode: One of "FULL", "DIFF", "INCR" (a key of TIMINGS).

    Returns:
        The unit file content (TIMER_TEMPLATE filled in with the mode's
        OnCalendar schedule from TIMINGS).
    """
    return TIMER_TEMPLATE.format(mode=mode, calendar=TIMINGS[mode])

def generate_cleanup_service(venv: str, dar_path: Optional[str]) -> str:
    """Render the dar-backup cleanup service unit content.

    Args:
        venv: Path to the Python venv containing the cleanup console script.
        dar_path: Optional directory to prepend to PATH for the dar binary.

    Returns:
        The unit file content (CLEANUP_SERVICE_TEMPLATE filled in).
    """
    exec_command = build_exec_command(venv, "", dar_path, tool='cleanup').strip()
    return CLEANUP_SERVICE_TEMPLATE.format(exec_command=exec_command)

def write_unit_file(path: Path, filename: str, content: str) -> None:
    """Write one unit file's content to disk and print a confirmation line.

    Args:
        path: Directory to write into.
        filename: Unit file name, e.g. "dar-full-backup.service".
        content: Full unit file content to write.
    """
    file_path = path / filename
    file_path.write_text(content)
    print(f"Generated {filename}")

def _run_systemctl(args: list[str]) -> None:
    """Run a systemctl command; print a clear error and exit if it fails.

    Args:
        args: Full argument list, e.g. ["systemctl", "--user", "enable", unit].

    Raises:
        SystemExit: If the command returns a non-zero exit code.
    """
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        cmd = " ".join(args)
        print(f"ERROR: '{cmd}' failed (returncode={result.returncode})", file=sys.stderr)
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        sys.exit(1)


def enable_and_start_unit(unit_name: str) -> None:
    """Enable and start a systemd user unit, exiting on failure.

    Args:
        unit_name: Name of the systemd unit (e.g. 'dar-full-backup.timer').
    """
    _run_systemctl(["systemctl", "--user", "enable", unit_name])
    _run_systemctl(["systemctl", "--user", "start", unit_name])

def write_unit_files(venv: str, dar_path: Optional[str], install: bool = False) -> None:
    """Generate all dar-backup systemd unit files and optionally install them.

    Writes a service+timer pair for each of FULL/DIFF/INCR plus the cleanup
    service+timer, to ~/.config/systemd/user (if install) or the current
    directory otherwise.

    Args:
        venv: Path to the Python venv containing dar-backup/cleanup.
        dar_path: Optional directory to prepend to PATH for the dar binary.
        install: If True, also enable+start every generated timer and reload
            the systemd user daemon (daemon-reexec + daemon-reload).
    """
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
        _run_systemctl(["systemctl", "--user", "daemon-reexec"])
        _run_systemctl(["systemctl", "--user", "daemon-reload"])
        print("Systemd `dar-backup` units and timers installed and user daemon reloaded.")

def _reject_if_shell_unsafe(name: str, value: str) -> None:
    """Reject a value that would break out of the single-quoted ExecStart= shell string.

    build_exec_command() embeds this value inside `ExecStart=/bin/bash -c '...'`. Inside
    single quotes, POSIX shells treat every character literally except a literal single
    quote, which terminates the quoting early. A path containing one would silently
    produce a broken systemd unit, so this is rejected up front rather than written to disk.

    Args:
        name: Human-readable label for the value, used in the error message (e.g. "--venv").
        value: The path value to check.

    Raises:
        ValueError: If `value` contains a single-quote character.
    """
    if "'" in value:
        raise ValueError(
            f"{name} must not contain a single quote (') — it is embedded in a "
            f"single-quoted shell string in the generated systemd unit: {value!r}"
        )


def main() -> None:
    """CLI entrypoint: generate (and optionally install) dar-backup systemd units.

    Warns if the current locale is not UTF-8, parses --venv/--dar-path/--install,
    rejects shell-unsafe values for --venv/--dar-path (see
    _reject_if_shell_unsafe), then writes the unit files via write_unit_files().

    Exits 1 if --venv or --dar-path contains a single quote; never returns a
    value on success.
    """
    check_locale()
    parser = argparse.ArgumentParser(description="Generate systemd service and timer units for dar-backup.")
    parser.add_argument("--venv",     required=True,       help="Path to the Python venv with dar-backup")
    parser.add_argument("--dar-path",                      help="Optional path to dar binary's directory")
    parser.add_argument("--install",  action="store_true", help="Install the units to ~/.config/systemd/user")
    args = parser.parse_args()
    try:
        _reject_if_shell_unsafe("--venv", args.venv)
        if args.dar_path:
            _reject_if_shell_unsafe("--dar-path", args.dar_path)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    write_unit_files(args.venv, args.dar_path, install=args.install)

if __name__ == "__main__":
    main()
