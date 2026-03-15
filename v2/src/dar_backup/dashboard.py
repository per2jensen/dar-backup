#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
dar-backup-dashboard  —  start Datasette and open the metrics dashboard.

Usage:
    dar-backup-dashboard
    dar-backup-dashboard --db ~/dar-backup/dar-backup-metrics.db
    dar-backup-dashboard --db ~/dar-backup/dar-backup-metrics.db --port 8002

Config file resolution (same precedence as dar-backup):
    1. -c / --config-file CLI option
    2. DAR_BACKUP_CONFIG_FILE environment variable
    3. Default: ~/.config/dar-backup/dar-backup.conf

The metrics db path is read from METRICS_DB_PATH in the [MISC] section of
the config file, unless --db is given explicitly.

Datasette is an optional dependency. Install it with:
    pip install dar-backup[dashboard]
"""

import argparse
import importlib.resources
import os
import socket
import subprocess
import sys
import time
import webbrowser


DEFAULT_PORT    = 8001
DEFAULT_CONFIG  = "~/.config/dar-backup/dar-backup.conf"
STARTUP_TIMEOUT = 30   # seconds to wait for Datasette to become ready


def find_free_port(preferred: int) -> int:
    """Return preferred port if free, otherwise find a nearby free one."""
    for port in [preferred] + list(range(preferred + 1, preferred + 20)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("Could not find a free port near %d" % preferred)


def wait_for_datasette(port: int, timeout: int = STARTUP_TIMEOUT) -> bool:
    """Poll until Datasette responds on /-/versions or timeout."""
    import urllib.request
    deadline = time.time() + timeout
    last_dot = time.time()
    print("Waiting for Datasette", end="", flush=True)
    while time.time() < deadline:
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/-/versions", timeout=1
            )
            print(" ready.", flush=True)
            return True
        except Exception:
            time.sleep(0.3)
            if time.time() - last_dot >= 1.0:
                print(".", end="", flush=True)
                last_dot = time.time()
    print(" timed out.", flush=True)
    return False


def resolve_config_file(cli_config: str | None) -> str:
    """
    Resolve config file path using the same precedence as dar-backup:
      1. -c / --config-file CLI option
      2. DAR_BACKUP_CONFIG_FILE environment variable
      3. Default: ~/.config/dar-backup/dar-backup.conf
    """
    env_cf = os.getenv("DAR_BACKUP_CONFIG_FILE")
    env_cf = env_cf.strip() if env_cf else None
    cli_cf = cli_config.strip() if cli_config else None
    raw    = cli_cf or env_cf or DEFAULT_CONFIG
    return os.path.expandvars(os.path.expanduser(raw))


def resolve_db_path(arg_db: str | None, config_file: str) -> str:
    """
    Return db path from --db arg (highest priority), or read
    METRICS_DB_PATH from the dar-backup config file.
    """
    if arg_db:
        return os.path.expandvars(os.path.expanduser(arg_db))

    if os.path.isfile(config_file) and os.access(config_file, os.R_OK):
        try:
            from dar_backup.config_settings import ConfigSettings  # type: ignore
            cfg = ConfigSettings(config_file)
            db = cfg.metrics_db_path   # already expanded by ConfigSettings.__post_init__
            if db:
                return db
        except Exception:
            pass

    return ""


def get_dashboard_html_path() -> str:
    """Return the absolute path to the bundled dashboard.html."""
    ref = importlib.resources.files("dar_backup.data").joinpath("dashboard.html")
    with importlib.resources.as_file(ref) as p:
        return str(p)


def get_datasette_path() -> str:
    """Return full path to datasette in the same venv as this script."""
    import shutil
    # Prefer the datasette sitting next to the current Python interpreter
    # so we use the venv installation rather than any system one.
    candidate = os.path.join(os.path.dirname(sys.executable), "datasette")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    # Fall back to PATH resolution
    found = shutil.which("datasette")
    return found or ""


def check_datasette_installed() -> bool:
    return bool(get_datasette_path())


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dar-backup-dashboard",
        description="Start Datasette and open the dar-backup metrics dashboard.",
    )
    parser.add_argument(
        "--db",
        default=None,
        metavar="PATH",
        help="Path to the metrics SQLite database. "
             "Overrides METRICS_DB_PATH from the config file.",
    )
    parser.add_argument(
        "-c", "--config-file",
        default=None,
        metavar="PATH",
        help=f"Path to dar-backup.conf "
             f"(default: $DAR_BACKUP_CONFIG_FILE or {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--port",
        default=DEFAULT_PORT,
        type=int,
        metavar="PORT",
        help=f"Preferred Datasette port (default: {DEFAULT_PORT}). "
             "A nearby free port is used automatically if this one is taken.",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Start Datasette but do not open a browser window.",
    )
    args = parser.parse_args()

    # Check datasette is available
    if not check_datasette_installed():
        print(
            "Error: datasette is not installed.\n"
            "Install it with:  pip install dar-backup[dashboard]",
            file=sys.stderr,
        )
        sys.exit(1)

    # Resolve config file  (CLI > env var > default)
    config_file = resolve_config_file(args.config_file)

    # Resolve db path  (--db > METRICS_DB_PATH in config)
    db_path = resolve_db_path(args.db, config_file)
    if not db_path:
        print(
            "Error: metrics database path not found.\n"
            f"  Config file checked: {config_file}\n"
            "  Either set METRICS_DB_PATH in [MISC] in your dar-backup config,\n"
            "  or pass the path explicitly:  dar-backup-dashboard --db /path/to/metrics.db",
            file=sys.stderr,
        )
        sys.exit(1)

    if not os.path.exists(db_path):
        print(
            f"Error: database file not found: {db_path}\n"
            "Run at least one backup with METRICS_DB_PATH configured to create it.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Resolve the bundled HTML file
    try:
        html_path = get_dashboard_html_path()
    except Exception as e:
        print(f"Error: could not locate dashboard.html: {e}", file=sys.stderr)
        sys.exit(1)

    # Find a free port
    try:
        port = find_free_port(args.port)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if port != args.port:
        print(f"Port {args.port} is in use — using port {port} instead.")

    # Start Datasette, serving the dashboard HTML via --static so we can
    # open it as a plain http:// URL - avoiding all file:// browser quirks.
    html_dir = os.path.dirname(html_path)
    print(f"Starting Datasette on http://127.0.0.1:{port} \u2026")
    datasette_bin = get_datasette_path()
    try:
        ds = subprocess.Popen(
            [datasette_bin, db_path, "--cors", "-p", str(port),
             "--static", f"dashboard:{html_dir}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        print("Error: datasette binary not found.", file=sys.stderr)
        sys.exit(1)

    # Wait for Datasette to be ready
    ready = wait_for_datasette(port)
    if not ready:
        print(
            f"Warning: Datasette did not respond within {STARTUP_TIMEOUT}s "
            "\u2014 opening browser anyway.",
            file=sys.stderr,
        )

    ds_base       = f"http://127.0.0.1:{port}"
    dashboard_url = f"{ds_base}/dashboard/dashboard.html?datasette={ds_base}"

    if not args.no_browser:
        print("Opening dashboard …")
        webbrowser.open(dashboard_url)
    else:
        print(f"Dashboard: {dashboard_url}")
        print(f"Datasette: {ds_base}")

    print("Press Ctrl+C to stop Datasette.")

    try:
        ds.wait()
    except KeyboardInterrupt:
        print("\nShutting down Datasette …")
        ds.terminate()
        try:
            ds.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ds.kill()
    sys.exit(0)


if __name__ == "__main__":
    main()
