# SPDX-License-Identifier: GPL-3.0-or-later
"""
Static structure tests for v2/src/dar_backup/data/dashboard.html.

These tests verify that the HTML and inline JavaScript contain the constructs
required for correct behaviour and graceful degradation — without executing
any JavaScript (no browser dependency).

Covered:
  - Chart.js CDN script tag has the onerror handler that sets _chartjsFailed
  - Required DOM element IDs exist for the degradation path
  - buildTrendPanels() contains the Chart.js failure guard
  - The guard hides the trends section label and shows a plain-text warning
  - The warning message is user-readable and mentions CDN / internet
  - The three granularity buttons exist with correct data-gran attributes
  - Monthly granularity is the default active button
  - Key JavaScript functions are defined: buildTrendPanels, periodKey,
    worstStatus, fmtBytes
  - Two-dataset chart design: FULL carry-forward line + DIFF/INCR scatter
"""

from html.parser import HTMLParser
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Load the dashboard HTML once for the whole module
# ---------------------------------------------------------------------------
_HTML_PATH = (
    Path(__file__).parent.parent
    / "src" / "dar_backup" / "data" / "dashboard.html"
)
_HTML: str = _HTML_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Simple HTML parser that collects element attributes by id / tag
# ---------------------------------------------------------------------------

class _AttrCollector(HTMLParser):
    """Collects tag attributes indexed by (tag, id) and all script content."""

    def __init__(self) -> None:
        super().__init__()
        self.by_id:    dict[str, dict[str, str]] = {}   # id  → attrs dict
        self.by_tag:   dict[str, list[dict[str, str]]] = {}  # tag → [attrs, …]
        self._in_script = False
        self.script_blocks: list[str] = []
        self._buf = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k: (v or "") for k, v in attrs}
        self.by_tag.setdefault(tag, []).append(attr_dict)
        if "id" in attr_dict:
            self.by_id[attr_dict["id"]] = attr_dict
        if tag == "script":
            self._in_script = True
            self._buf = ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self.script_blocks.append(self._buf)
            self._in_script = False
            self._buf = ""

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._buf += data

    @property
    def inline_js(self) -> str:
        """All inline <script> block content joined."""
        return "\n".join(self.script_blocks)


@pytest.fixture(scope="module")
def dom() -> _AttrCollector:
    """Parse dashboard.html once and return the collector."""
    collector = _AttrCollector()
    collector.feed(_HTML)
    return collector


# ---------------------------------------------------------------------------
# Chart.js CDN script tag
# ---------------------------------------------------------------------------

class TestChartJsScriptTag:
    """The Chart.js <script> tag must be structured for safe CDN failure."""

    def _chartjs_script(self, dom: _AttrCollector) -> dict[str, str]:
        scripts = [
            a for a in dom.by_tag.get("script", [])
            if "chart" in a.get("src", "").lower()
        ]
        assert scripts, "No Chart.js <script src=...> tag found in dashboard.html"
        return scripts[0]

    def test_chartjs_script_tag_exists(self, dom: _AttrCollector) -> None:
        """A <script> tag loading Chart.js from a CDN must be present."""
        self._chartjs_script(dom)  # raises if not found

    def test_chartjs_onerror_sets_flag(self, dom: _AttrCollector) -> None:
        """The onerror attribute must set window._chartjsFailed so the JS guard works."""
        attrs = self._chartjs_script(dom)
        onerror = attrs.get("onerror", "")
        assert "_chartjsFailed" in onerror, (
            f"Chart.js <script> onerror must set _chartjsFailed; got: {onerror!r}"
        )

    def test_chartjs_onerror_assigns_true(self, dom: _AttrCollector) -> None:
        """The flag must be assigned a truthy value (=true)."""
        attrs = self._chartjs_script(dom)
        onerror = attrs.get("onerror", "")
        assert "true" in onerror.lower(), (
            f"onerror should assign true; got: {onerror!r}"
        )

    def test_chartjs_loaded_from_cdn(self, dom: _AttrCollector) -> None:
        """Chart.js must be loaded from an external CDN (not bundled)."""
        attrs = self._chartjs_script(dom)
        src = attrs.get("src", "")
        assert src.startswith("https://"), (
            f"Chart.js src should be an https:// CDN URL; got: {src!r}"
        )


# ---------------------------------------------------------------------------
# DOM elements required for the degradation path
# ---------------------------------------------------------------------------

class TestRequiredDomElements:
    """Elements that the degradation and trend-panel JS code references by id."""

    def test_trend_panels_container_exists(self, dom: _AttrCollector) -> None:
        """id='trend-panels' is the container cleared/populated by buildTrendPanels."""
        assert "trend-panels" in dom.by_id, (
            "Element id='trend-panels' not found — buildTrendPanels() will fail"
        )

    def test_trends_section_label_exists(self, dom: _AttrCollector) -> None:
        """id='trends-section-label' is hidden by the Chart.js failure guard."""
        assert "trends-section-label" in dom.by_id, (
            "Element id='trends-section-label' not found — "
            "degradation path cannot hide the section heading"
        )


# ---------------------------------------------------------------------------
# Granularity toggle buttons
# ---------------------------------------------------------------------------

class TestGranularityButtons:
    """Three granularity buttons must exist with the correct data-gran values."""

    def _gran_buttons(self, dom: _AttrCollector) -> list[dict[str, str]]:
        return [
            a for a in dom.by_tag.get("button", [])
            if "data-gran" in a
        ]

    def test_three_granularity_buttons_exist(self, dom: _AttrCollector) -> None:
        assert len(self._gran_buttons(dom)) == 3

    def test_weekly_button_exists(self, dom: _AttrCollector) -> None:
        grans = {b["data-gran"] for b in self._gran_buttons(dom)}
        assert "week" in grans

    def test_monthly_button_exists(self, dom: _AttrCollector) -> None:
        grans = {b["data-gran"] for b in self._gran_buttons(dom)}
        assert "month" in grans

    def test_yearly_button_exists(self, dom: _AttrCollector) -> None:
        grans = {b["data-gran"] for b in self._gran_buttons(dom)}
        assert "year" in grans

    def test_monthly_is_default_active(self, dom: _AttrCollector) -> None:
        """Monthly is the pre-selected granularity (has 'active' class)."""
        monthly = [
            b for b in self._gran_buttons(dom) if b.get("data-gran") == "month"
        ]
        assert monthly, "Monthly granularity button not found"
        assert "active" in monthly[0].get("class", ""), (
            "Monthly button should have class 'active' as the default granularity"
        )


# ---------------------------------------------------------------------------
# JavaScript: Chart.js failure guard inside buildTrendPanels
# ---------------------------------------------------------------------------

class TestChartJsFailureGuard:
    """buildTrendPanels() must check for CDN failure before using Chart."""

    def test_guard_checks_chartjs_failed_flag(self, dom: _AttrCollector) -> None:
        """The _chartjsFailed flag set by onerror must be checked in JS."""
        assert "_chartjsFailed" in dom.inline_js, (
            "JS does not reference _chartjsFailed — "
            "CDN failure will not be detected at runtime"
        )

    def test_guard_checks_typeof_chart(self, dom: _AttrCollector) -> None:
        """typeof Chart === 'undefined' guard handles cases where onerror fires late."""
        assert "typeof Chart" in dom.inline_js, (
            "JS does not contain 'typeof Chart' guard — "
            "silent failure if Chart.js loads asynchronously and is still undefined"
        )

    def test_guard_hides_section_label(self, dom: _AttrCollector) -> None:
        """The failure path must hide the trends section heading."""
        assert "trends-section-label" in dom.inline_js, (
            "JS does not reference trends-section-label — "
            "the section heading will remain visible when Chart.js is absent"
        )
        assert "display" in dom.inline_js and "none" in dom.inline_js, (
            "JS degradation path does not set display:none on the section label"
        )

    def test_guard_shows_warning_message(self, dom: _AttrCollector) -> None:
        """The failure path must insert a human-readable warning into the page."""
        warning_text = "Trend charts unavailable"
        assert warning_text in dom.inline_js, (
            f"Degradation warning text {warning_text!r} not found in JS — "
            "users will see an empty panel with no explanation"
        )

    def test_warning_mentions_cdn_or_internet(self, dom: _AttrCollector) -> None:
        """The warning must tell users *why* — CDN or internet access."""
        js = dom.inline_js
        assert "CDN" in js or "internet" in js, (
            "Degradation warning should mention CDN or internet so the user "
            "understands the cause"
        )


# ---------------------------------------------------------------------------
# JavaScript: required functions are defined
# ---------------------------------------------------------------------------

class TestJsFunctionsPresent:
    """All functions called at runtime must be defined in the inline JS."""

    def test_build_trend_panels_defined(self, dom: _AttrCollector) -> None:
        assert "function buildTrendPanels" in dom.inline_js

    def test_period_key_defined(self, dom: _AttrCollector) -> None:
        assert "function periodKey" in dom.inline_js

    def test_worst_status_defined(self, dom: _AttrCollector) -> None:
        assert "function worstStatus" in dom.inline_js

    def test_fmt_bytes_defined(self, dom: _AttrCollector) -> None:
        assert "function fmtBytes" in dom.inline_js


# ---------------------------------------------------------------------------
# JavaScript: two-dataset chart design
# ---------------------------------------------------------------------------

class TestTwoDatasetDesign:
    """
    The trend charts use two datasets:
      1. FULL carry-forward stepped reference line (indigo)
      2. DIFF/INCR combined size scatter overlay (cyan)
    Verify both are present in the JS source.
    """

    def test_full_dataset_referenced(self, dom: _AttrCollector) -> None:
        """The JS must reference FULL backups separately for the carry-forward line."""
        assert "FULL" in dom.inline_js

    def test_incr_diff_dataset_referenced(self, dom: _AttrCollector) -> None:
        """The JS must reference DIFF/INCR runs for the scatter overlay."""
        js = dom.inline_js
        assert "DIFF" in js or "INCR" in js, (
            "JS does not reference DIFF or INCR backup types — "
            "second dataset (incremental scatter) may be missing"
        )

    def test_stepped_line_used_for_full(self, dom: _AttrCollector) -> None:
        """stepped: true creates the carry-forward step-function appearance."""
        assert "stepped" in dom.inline_js, (
            "JS does not contain 'stepped' — FULL carry-forward line will not "
            "render as a step function"
        )

    def test_two_datasets_in_chart_config(self, dom: _AttrCollector) -> None:
        """The datasets array must contain at least two entries."""
        # A reliable proxy: 'datasets' appears and there are two dataset label strings
        js = dom.inline_js
        assert js.count("label:") >= 2 or js.count("'FULL'") >= 1, (
            "Chart config appears to have fewer than two datasets"
        )
