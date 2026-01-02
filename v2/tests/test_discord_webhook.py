import json
import os
from types import SimpleNamespace

import pytest

import dar_backup.util as util


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
