# SPDX-License-Identifier: GPL-3.0-or-later
"""Licence, integrity, and offline checks for packaged dashboard JavaScript."""

import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest


pytestmark = pytest.mark.unit
DATA_ROOT = Path(__file__).parent.parent / "src" / "dar_backup" / "data"
MANIFEST_PATH = DATA_ROOT / "vendor" / "vendor-manifest.json"


class _ScriptCollector(HTMLParser):
    """Collect script source attributes from dashboard HTML."""

    def __init__(self) -> None:
        """Initialize an empty script-source list."""
        super().__init__()
        self.sources: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        """Record the source of each external script tag.

        Args:
            tag: Parsed HTML tag name.
            attrs: Parsed attribute name/value pairs.

        Returns:
            None.
        """
        if tag != "script":
            return
        attributes = dict(attrs)
        source = attributes.get("src")
        if source is not None:
            self.sources.append(source)


def _load_manifest() -> dict[str, Any]:
    """Load the committed vendor manifest.

    Returns:
        Parsed vendor manifest.
    """
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_every_javascript_asset_has_exact_manifest_entry() -> None:
    """No packaged JavaScript may bypass the licence and checksum inventory."""
    manifest_paths = {
        artifact["path"] for artifact in _load_manifest()["artifacts"]
    }
    javascript_paths = {
        path.relative_to(DATA_ROOT).as_posix() for path in DATA_ROOT.rglob("*.js")
    }
    assert javascript_paths == manifest_paths


def test_vendor_checksums_and_licence_files_are_current() -> None:
    """Manifest checksums and every declared licence must match package contents."""
    for artifact in _load_manifest()["artifacts"]:
        asset_path = DATA_ROOT / artifact["path"]
        assert asset_path.is_file()
        assert hashlib.sha256(asset_path.read_bytes()).hexdigest() == artifact["sha256"]
        assert artifact["license"] == "MIT"
        assert artifact["source_url"].startswith("https://registry.npmjs.org/")
        assert len(artifact["source_tarball_sha256"]) == 64
        for licence_path in artifact["license_files"]:
            licence = DATA_ROOT / licence_path
            assert licence.is_file()
            assert "MIT License" in licence.read_text(encoding="utf-8")


def test_chart_bundles_identify_pinned_version_and_embedded_dependency() -> None:
    """Both runtime and readable source identify audited component versions."""
    for filename in ("chart.umd.js", "chart.umd.min.js"):
        contents = (DATA_ROOT / "vendor" / filename).read_text(encoding="utf-8")
        assert "Chart.js v4.6.1" in contents
        assert "Released under the MIT License" in contents
        assert "@kurkle/color v0.3.2" in contents


def test_dashboard_uses_only_local_script_and_system_fonts() -> None:
    """Dashboard rendering must not require a CDN or remote font request."""
    html = (DATA_ROOT / "dashboard.html").read_text(encoding="utf-8")
    collector = _ScriptCollector()
    collector.feed(html)
    assert collector.sources == ["vendor/chart.umd.min.js"]
    assert all(not source.startswith(("http://", "https://")) for source in collector.sources)
    assert "@import url(" not in html
    assert "fonts.googleapis.com" not in html
    assert "cdn.jsdelivr.net" not in html
    assert "system-ui" in html
    assert "ui-monospace" in html
    assert "IBM Plex" not in html
    assert html.count("family: 'ui-monospace") >= 4
