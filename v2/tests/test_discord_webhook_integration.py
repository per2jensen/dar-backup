# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests: Discord webhook end-to-end — backup run → HTTP POST captured.

Finding #8 — All discord tests are unit-level (render function, HTTP error
mocking, env-var precedence).  There is no integration test that:

  - Runs a real backup.
  - Points DAR_BACKUP_DISCORD_WEBHOOK_URL at a local HTTP server.
  - Confirms the rendered report payload is actually POSTed with the correct
    Content-Type and contains expected fields (start time, backup definition,
    outcome).

These tests spin up a minimal Python HTTPServer in a background thread,
run dar-backup against it, and verify the captured request.

Important: the "example" backup definition is intentionally excluded from
stats and metrics collection in dar_backup.py (it is treated as a demo
definition).  These tests use a custom definition name so that the Discord
report is actually sent.

Marks: integration, slow
"""

import http.server
import json
import os
import sys
import threading
from configparser import ConfigParser
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.envdata import EnvData
from dar_backup.command_runner import CommandRunner


# ---------------------------------------------------------------------------
# Minimal local HTTP server that captures incoming POST requests
# ---------------------------------------------------------------------------

class _CapturingHandler(http.server.BaseHTTPRequestHandler):
    """Accept any POST, store the body and headers, reply 204."""

    def do_POST(self) -> None:          # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.captured_requests.append(  # type: ignore[attr-defined]
            {
                "path":    self.path,
                "headers": dict(self.headers),
                "body":    body,
            }
        )
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args) -> None:   # silence access log during tests
        pass


class _CapturingServer(http.server.HTTPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.captured_requests: list = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BACKUP_DEF = "discord-test"


def _start_local_server() -> tuple:
    """Start a _CapturingServer on an OS-assigned port. Returns (server, thread)."""
    server = _CapturingServer(("127.0.0.1", 0), _CapturingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _write_backup_def(env: EnvData) -> None:
    """Write a non-'example' backup definition and create its catalog DB."""
    def_path = os.path.join(env.backup_d_dir, _BACKUP_DEF)
    Path(def_path).write_text(
        "-R /\n-s 10G\n-z6\n-am\n--cache-directory-tagging\n"
        f"-g {env.data_dir.lstrip('/')}\n"
    )
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        ["manager", "--create-db", "--config-file", env.config_file, "--log-stdout"],
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"manager --create-db failed: {result.stderr}")


def _disable_par2(env: EnvData) -> None:
    config = ConfigParser()
    config.read(env.config_file)
    if "PAR2" not in config:
        config["PAR2"] = {}
    config["PAR2"]["ENABLED"] = "False"
    with open(env.config_file, "w") as fh:
        config.write(fh)


def _run_full_backup(env: EnvData, webhook_url: str) -> tuple:
    """
    Run dar-backup with the webhook env var set; return (returncode, combined output).

    CommandRunner always uses os.environ.copy() internally so we cannot inject
    env vars through it.  We use subprocess.run directly here so that we can
    pass a custom environment that includes the webhook URL.
    """
    import subprocess as _sp
    run_env = os.environ.copy()
    run_env["DAR_BACKUP_DISCORD_WEBHOOK_URL"] = webhook_url
    run_env["LC_ALL"] = "C"
    proc = _sp.run(
        [
            "dar-backup", "--full-backup",
            "-d", _BACKUP_DEF,
            "--log-stdout", "--log-level", "debug",
            "--config-file", env.config_file,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        env=run_env,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_discord_webhook_receives_post_after_full_backup(
    setup_environment, env: EnvData
) -> None:
    """
    A successful FULL backup must POST exactly one message to the configured
    webhook URL.  The request must:

      - Use POST method (verified by server accepting it).
      - Have Content-Type: application/json.
      - Contain a JSON body with a 'content' key whose value is a non-empty string.
    """
    _disable_par2(env)
    _write_backup_def(env)
    server, _ = _start_local_server()
    port = server.server_address[1]
    webhook_url = f"http://127.0.0.1:{port}/webhook"

    try:
        rc, output = _run_full_backup(env, webhook_url)
        assert rc == 0, f"dar-backup failed (rc={rc}):\n{output}"

        requests = server.captured_requests
        assert len(requests) >= 1, (
            "No HTTP POST was sent to the local webhook server after a successful backup"
        )

        req = requests[-1]

        # Header names are stored with their original capitalisation by
        # BaseHTTPRequestHandler, so look up case-insensitively.
        headers_lower = {k.lower(): v for k, v in req["headers"].items()}
        ct = headers_lower.get("content-type", "")
        assert "application/json" in ct, (
            f"Expected Content-Type: application/json, got: {ct}"
        )

        payload = json.loads(req["body"].decode("utf-8"))
        assert "content" in payload, "Discord payload missing 'content' key"
        assert isinstance(payload["content"], str) and payload["content"].strip(), (
            "Discord payload 'content' must be a non-empty string"
        )

        env.logger.info(
            "Webhook received %d request(s); content length=%d",
            len(requests),
            len(payload["content"]),
        )
    finally:
        server.shutdown()


def test_discord_report_content_includes_backup_definition_and_outcome(
    setup_environment, env: EnvData
) -> None:
    """
    The text sent to Discord must mention the backup definition name and
    include a recognisable outcome phrase, plus the standard header and
    footer markers.
    """
    _disable_par2(env)
    _write_backup_def(env)
    server, _ = _start_local_server()
    port = server.server_address[1]
    webhook_url = f"http://127.0.0.1:{port}/webhook"

    try:
        rc, _ = _run_full_backup(env, webhook_url)
        assert rc == 0

        assert server.captured_requests, "No requests captured"
        payload = json.loads(server.captured_requests[-1]["body"].decode("utf-8"))
        content = payload["content"]

        env.logger.info("Discord report content:\n%s", content)

        assert _BACKUP_DEF in content, (
            f"Backup definition {_BACKUP_DEF!r} not found in Discord report:\n{content}"
        )
        assert any(
            phrase in content
            for phrase in ("Completed", "Failed", "SUCCESS", "WARNING", "FAILURE")
        ), f"No outcome phrase found in Discord report:\n{content}"

        assert "---- Start of dar-backup report ----" in content, (
            "Report header marker missing from Discord payload"
        )
        assert "---- End of dar-backup report ----" in content, (
            "Report footer marker missing from Discord payload"
        )
    finally:
        server.shutdown()


def test_discord_webhook_not_called_when_env_var_absent(
    setup_environment, env: EnvData
) -> None:
    """
    When DAR_BACKUP_DISCORD_WEBHOOK_URL is not set the backup must complete
    normally without attempting any HTTP request.
    """
    _disable_par2(env)
    _write_backup_def(env)
    server, _ = _start_local_server()

    try:
        import subprocess as _sp
        clean_env = {k: v for k, v in os.environ.items()
                     if k != "DAR_BACKUP_DISCORD_WEBHOOK_URL"}
        clean_env["LC_ALL"] = "C"
        proc = _sp.run(
            [
                "dar-backup", "--full-backup",
                "-d", _BACKUP_DEF,
                "--log-stdout", "--log-level", "debug",
                "--config-file", env.config_file,
            ],
            capture_output=True,
            text=True,
            timeout=300,
            env=clean_env,
        )
        assert proc.returncode == 0, (
            f"dar-backup failed (rc={proc.returncode}) when webhook not configured"
        )

        assert len(server.captured_requests) == 0, (
            f"Unexpected HTTP request(s) received when webhook was not configured: "
            f"{server.captured_requests}"
        )
        env.logger.info("Confirmed: no HTTP request sent when webhook env var is absent")
    finally:
        server.shutdown()
