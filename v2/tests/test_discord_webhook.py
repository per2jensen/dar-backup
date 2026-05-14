import json
import os
from types import SimpleNamespace


import dar_backup.util as util
import pytest

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# render_discord_report
# ---------------------------------------------------------------------------

def _make_backup(definition, status, end_time="2026-05-14T09:35:22+00:00", warnings=0, errors=0):
    return {
        "definition": definition,
        "status": status,
        "type": "FULL",
        "end_time": end_time,
        "warning_count": warnings,
        "error_count": errors,
    }


def test_render_discord_report_success_no_prereqs():
    """
    A clean run with one successful backup and no PREREQ/POSTREQ configured.
    """
    backups = [_make_backup("home-docs", "SUCCESS")]
    prereqs = {"status": "none", "failures": []}
    postreqs = {"status": "none", "failures": []}

    result = util.render_discord_report(
        start_time="2026-05-14T09:00:00+00:00",
        end_time="2026-05-14T09:45:00+00:00",
        backups=backups,
        prereqs=prereqs,
        postreqs=postreqs,
    )

    assert "---- Start of dar-backup report ----" in result
    assert "Start time: 2026-05-14T09:00:00+00:00" in result
    assert "home-docs" in result
    assert "Completed (warnings: 0, errors: 0)" in result
    assert "PREREQs: none" in result
    assert "POSTREQs: none" in result
    assert "End time: 2026-05-14T09:45:00+00:00" in result
    assert "---- End of dar-backup report ----" in result


def test_render_discord_report_failure_backup():
    """
    A backup that failed shows 'Failed' in the report.
    """
    backups = [_make_backup("photos", "FAILURE", errors=2)]
    prereqs = {"status": "success", "failures": []}
    postreqs = {"status": "success", "failures": []}

    result = util.render_discord_report(
        start_time="2026-05-14T09:00:00+00:00",
        end_time="2026-05-14T09:45:00+00:00",
        backups=backups,
        prereqs=prereqs,
        postreqs=postreqs,
    )

    assert "Failed (warnings: 0, errors: 2)" in result
    assert "PREREQs: success" in result
    assert "POSTREQs: success" in result


def test_render_discord_report_warning_backup_shows_completed():
    """
    A backup with warnings (exit code 5) still shows as 'Completed'.
    """
    backups = [_make_backup("data", "WARNING", warnings=3)]
    prereqs = {"status": "none", "failures": []}
    postreqs = {"status": "none", "failures": []}

    result = util.render_discord_report(
        start_time="2026-05-14T09:00:00+00:00",
        end_time="2026-05-14T09:45:00+00:00",
        backups=backups,
        prereqs=prereqs,
        postreqs=postreqs,
    )

    assert "Completed (warnings: 3, errors: 0)" in result


def test_render_discord_report_postreq_failure_shows_details():
    """
    A POSTREQ failure includes the failing script key and message.
    """
    backups = [_make_backup("home-docs", "SUCCESS")]
    prereqs = {"status": "success", "failures": []}
    postreqs = {
        "status": "failure",
        "failures": [{"script": "001", "message": "mount point not found"}],
    }

    result = util.render_discord_report(
        start_time="2026-05-14T09:00:00+00:00",
        end_time="2026-05-14T09:45:00+00:00",
        backups=backups,
        prereqs=prereqs,
        postreqs=postreqs,
    )

    assert "POSTREQs: failure" in result
    assert "001" in result
    assert "mount point not found" in result


def test_render_discord_report_empty_backups_shows_none():
    """
    When no backups were performed the Backups section shows '(none)'.
    """
    prereqs = {"status": "none", "failures": []}
    postreqs = {"status": "none", "failures": []}

    result = util.render_discord_report(
        start_time="2026-05-14T09:00:00+00:00",
        end_time="2026-05-14T09:45:00+00:00",
        backups=[],
        prereqs=prereqs,
        postreqs=postreqs,
    )

    assert "(none)" in result


def test_render_discord_report_backups_sorted_alphabetically():
    """
    Backups are rendered in the order they are passed; caller is responsible for sorting.
    """
    backups = sorted(
        [
            _make_backup("zebra", "SUCCESS"),
            _make_backup("alpha", "SUCCESS"),
            _make_backup("mango", "SUCCESS"),
        ],
        key=lambda s: s["definition"],
    )

    result = util.render_discord_report(
        start_time="2026-05-14T09:00:00+00:00",
        end_time="2026-05-14T09:45:00+00:00",
        backups=backups,
        prereqs={"status": "none", "failures": []},
        postreqs={"status": "none", "failures": []},
    )

    alpha_pos = result.index("alpha")
    mango_pos = result.index("mango")
    zebra_pos = result.index("zebra")
    assert alpha_pos < mango_pos < zebra_pos


# ---------------------------------------------------------------------------
# requirements() report_out population
# ---------------------------------------------------------------------------

def test_requirements_report_out_set_to_success_when_scripts_pass(monkeypatch):
    """
    report_out["status"] is set to "success" when all PREREQ scripts succeed.
    """
    import configparser
    config = configparser.ConfigParser()
    config["PREREQ"] = {"001": "echo ok"}
    config_setting = SimpleNamespace(config=config)
    monkeypatch.setattr(util, "logger", __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock())

    report_out = {"status": "none", "failures": []}
    util.requirements("PREREQ", config_setting, report_out=report_out)

    assert report_out["status"] == "success"
    assert report_out["failures"] == []


def test_requirements_report_out_set_to_failure_on_script_error(monkeypatch):
    """
    report_out["status"] is "failure" and failures list is populated when a script fails.
    """
    import configparser
    config = configparser.ConfigParser()
    config["PREREQ"] = {"001": "false"}
    config_setting = SimpleNamespace(config=config)
    monkeypatch.setattr(util, "logger", __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock())

    report_out = {"status": "none", "failures": []}
    with pytest.raises((RuntimeError, Exception)):
        util.requirements("PREREQ", config_setting, report_out=report_out)

    assert report_out["status"] == "failure"
    assert len(report_out["failures"]) == 1
    assert report_out["failures"][0]["script"] == "001"


def test_requirements_report_out_stays_none_when_no_scripts_configured(monkeypatch):
    """
    report_out["status"] remains "none" when no PREREQ section is configured.
    """
    import configparser
    config = configparser.ConfigParser()
    config_setting = SimpleNamespace(config=config)
    monkeypatch.setattr(util, "logger", __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock())

    report_out = {"status": "none", "failures": []}
    util.requirements("PREREQ", config_setting, report_out=report_out)

    assert report_out["status"] == "none"









class DummyResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


def test_send_discord_message_prefers_env_over_config(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["payload"] = request.data
        captured["headers"] = {k.lower(): v for k, v in request.headers.items()}
        captured["timeout"] = timeout
        return DummyResponse()

    monkeypatch.setattr(util.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", "https://env.example/webhook")
    config = SimpleNamespace(dar_backup_discord_webhook_url="https://config.example/webhook")

    assert util.send_discord_message("hello", config_settings=config, timeout_seconds=3) is True
    assert captured["url"] == "https://env.example/webhook"
    assert json.loads(captured["payload"].decode())["content"] == "hello"
    assert captured["headers"]["user-agent"].startswith("dar-backup/")
    assert captured["timeout"] == 3


def test_send_discord_message_uses_env_when_no_config(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        return DummyResponse()

    monkeypatch.setattr(util.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", "https://env-only.example/webhook")

    assert util.send_discord_message("hi there", config_settings=None) is True
    assert captured["url"] == "https://env-only.example/webhook"


@pytest.mark.live_discord
def test_send_discord_message_live(monkeypatch):
    webhook = os.environ.get("DAR_BACKUP_DISCORD_WEBHOOK_URL")
    if not webhook:
        pytest.skip("DAR_BACKUP_DISCORD_WEBHOOK_URL not set for live Discord test")

    # Avoid leaking any monkeypatch from other tests
    monkeypatch.delenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", webhook)

    assert util.send_discord_message("dar-backup live webhook test") is True


@pytest.mark.live_discord
def test_render_and_send_discord_report_live(monkeypatch):
    """
    Renders a realistic backup report and sends it to a real Discord webhook.
    Requires DAR_BACKUP_DISCORD_WEBHOOK_URL to be set in the environment.
    """
    webhook = os.environ.get("DAR_BACKUP_DISCORD_WEBHOOK_URL")
    if not webhook:
        pytest.skip("DAR_BACKUP_DISCORD_WEBHOOK_URL not set for live Discord test")

    monkeypatch.delenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", webhook)

    from datetime import datetime

    def local_ts() -> str:
        return datetime.now().astimezone().isoformat(timespec='seconds')

    backups = sorted(
        [
            _make_backup("home-documents", "SUCCESS", end_time=local_ts()),
            _make_backup("photos",         "WARNING", end_time=local_ts(), warnings=2),
            _make_backup("system-config",  "FAILURE", end_time=local_ts(), errors=1),
        ],
        key=lambda s: s["definition"],
    )
    prereqs  = {"status": "success", "failures": []}
    postreqs = {
        "status": "failure",
        "failures": [{"script": "001", "message": "mount point /mnt/nas not found"}],
    }

    msg = util.render_discord_report(
        start_time=local_ts(),
        end_time=local_ts(),
        backups=backups,
        prereqs=prereqs,
        postreqs=postreqs,
    )
    assert util.send_discord_message(msg) is True
