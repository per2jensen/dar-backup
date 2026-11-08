# SPDX-License-Identifier: GPL-3.0-or-later
"""
Static structure tests for v2/src/dar_backup/data/dashboard.html.

These tests verify that the HTML and inline JavaScript contain the constructs
required for correct behaviour and graceful degradation — without executing
any JavaScript (no browser dependency).

Covered:
  - Local Chart.js script tag has the onerror handler that sets _chartjsFailed
  - Required DOM element IDs exist for the degradation path
  - buildTrendPanels() contains the Chart.js failure guard
  - The guard hides the trends section label and shows a plain-text warning
  - The warning message identifies the packaged Chart.js asset
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
# Chart.js local script tag
# ---------------------------------------------------------------------------

class TestChartJsScriptTag:
    """The Chart.js script must be local and retain graceful failure handling."""

    def _chartjs_script(self, dom: _AttrCollector) -> dict[str, str]:
        scripts = [
            a for a in dom.by_tag.get("script", [])
            if "chart" in a.get("src", "").lower()
        ]
        assert scripts, "No Chart.js <script src=...> tag found in dashboard.html"
        return scripts[0]

    def test_chartjs_script_tag_exists(self, dom: _AttrCollector) -> None:
        """A script tag loading the packaged Chart.js runtime must be present."""
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

    def test_chartjs_loaded_from_local_vendor_directory(self, dom: _AttrCollector) -> None:
        """Chart.js must load from the packaged vendor directory without a CDN."""
        attrs = self._chartjs_script(dom)
        src = attrs.get("src", "")
        assert src == "vendor/chart.umd.min.js"


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
    """buildTrendPanels() must check for local asset failure before using Chart."""

    def test_guard_checks_chartjs_failed_flag(self, dom: _AttrCollector) -> None:
        """The _chartjsFailed flag set by onerror must be checked in JS."""
        assert "_chartjsFailed" in dom.inline_js, (
            "JS does not reference _chartjsFailed — "
            "Chart.js load failure will not be detected at runtime"
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

    def test_warning_identifies_packaged_asset(self, dom: _AttrCollector) -> None:
        """The warning must identify the local packaged asset as the cause."""
        js = dom.inline_js
        assert "packaged Chart.js asset" in js, (
            "Degradation warning should identify the packaged Chart.js asset so "
            "the user understands the cause"
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

    def test_database_query_parameter_populates_datasette_database(
        self,
        dom: _AttrCollector,
    ) -> None:
        """A custom SQLite filename must select its Datasette database automatically."""
        js = dom.inline_js
        assert "const database = params.get('database')" in js
        assert "getElementById('ds-db').value = database" in js


class TestHtmlEscaping:
    """Database diagnostics must remain text when rendered through innerHTML."""

    def test_escape_html_encodes_xml_and_attribute_delimiters(
        self,
        dom: _AttrCollector,
    ) -> None:
        """The renderer encodes XML brackets, ampersands, and both quote types."""
        js = dom.inline_js
        assert "function escapeHtml(value)" in js
        for entity in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
            assert entity in js

    def test_error_summary_is_escaped_for_text_and_title_attribute(
        self,
        dom: _AttrCollector,
    ) -> None:
        """A DAR XML excerpt cannot become markup or escape its tooltip attribute."""
        js = dom.inline_js
        assert "const safeErrorSummary = escapeHtml(r.error_summary)" in js
        assert 'title="${safeErrorSummary}">${safeErrorSummary}</div>' in js

    def test_error_summary_is_never_interpolated_directly(
        self,
        dom: _AttrCollector,
    ) -> None:
        """Ordinary and hostile diagnostics share the escaped rendering path."""
        assert 'title="${r.error_summary}"' not in dom.inline_js
        assert '>${r.error_summary}</div>' not in dom.inline_js

    def test_definition_names_are_escaped_in_cards_and_trends(
        self,
        dom: _AttrCollector,
    ) -> None:
        """Definition names from SQLite cannot inject markup in either view."""
        assert dom.inline_js.count("${escapeHtml(defName)}") >= 2


class TestRunTableContainment:
    """Wide run tables must remain contained by their definition cards."""

    def test_run_table_has_local_scroll_wrapper(self) -> None:
        """Definition cards provide a dedicated horizontal scrolling region."""
        assert '<div class="run-table-scroll">' in _HTML
        assert '<table class="run-table">' in _HTML
        assert ".run-table-scroll" in _HTML
        assert "overflow-x: auto" in _HTML


class TestPhasePresentation:
    """Phase indicators must follow actual pipeline order and null semantics."""

    def test_phase_labels_follow_execution_order(self, dom: _AttrCollector) -> None:
        """Verification and restore must appear before catalogue registration."""
        js = dom.inline_js
        positions = [
            js.index("<span>pre</span>"),
            js.index("<span>verify</span>"),
            js.index("<span>restore</span>"),
            js.index("<span>catalog</span>"),
            js.index("<span>par2</span>"),
            js.index("<span>post</span>"),
        ]
        assert positions == sorted(positions)

    def test_failed_inode_border_applies_only_to_first_cell(self) -> None:
        """A failed-inode row has one left edge, not a border on every cell."""
        assert "tr.has-failures td:first-child { border-left:" in _HTML
        assert "tr.has-failures td { border-left:" not in _HTML


class TestSkippedOutcome:
    """SKIPPED must be distinct and excluded from backup-rate calculations."""

    def test_skipped_status_has_blue_pill_and_dot(self) -> None:
        """The dashboard must render SKIPPED with its own blue styling."""
        assert ".status-pill.SKIPPED" in _HTML
        assert ".dot.SKIPPED" in _HTML
        assert "var(--skipped)" in _HTML

    def test_summary_rate_excludes_skipped_runs(self, dom: _AttrCollector) -> None:
        """Skipped invocations must not enter the non-failure-rate denominator."""
        js = dom.inline_js
        assert "const attemptedCount = total - skippedCount" in js
        assert "(successCount + warnCount) * 100 / attemptedCount" in js
        assert "attemptedCount > 0" in js
        assert "rate == null ? 'N/A'" in js

    def test_period_health_ignores_skips_unless_all_runs_skipped(
        self,
        dom: _AttrCollector,
    ) -> None:
        """A skip cannot mask an attempted result; an all-skip period stays blue."""
        js = dom.inline_js
        assert "runs.filter(r => r.status !== 'SKIPPED')" in js
        assert "attemptedRuns.length === 0" in js
        assert "return 'SKIPPED'" in js

    def test_skip_reason_uses_neutral_details_column(self) -> None:
        """Skip reasons must not be presented under a red Error heading."""
        assert "<th>Details</th>" in _HTML
        assert ".detail-summary.SKIPPED" in _HTML


class TestLatestBackupSummaryCards:
    """History cards must not depend on grouped recent-row ordering."""

    def test_latest_matching_run_compares_timestamps_and_ids(
        self,
        dom: _AttrCollector,
    ) -> None:
        """Latest selection must compare timestamps with IDs as a tie-breaker."""
        js = dom.inline_js
        assert "function latestMatchingRun(rows, predicate)" in js
        assert "candidateTime > latestTime" in js
        assert "candidateTime === latestTime && candidateId > latestId" in js
        assert "const last = rows[0]" not in js

    def test_last_invocation_uses_all_history_statuses(
        self,
        dom: _AttrCollector,
    ) -> None:
        """The invocation card must accept SUCCESS, WARNING, SKIPPED, or FAILURE."""
        js = dom.inline_js
        assert "latestMatchingRun(historyRows, () => true)" in js
        assert '<div class="label">Last invocation</div>' in js

    def test_last_success_requires_strict_success_status(
        self,
        dom: _AttrCollector,
    ) -> None:
        """Warnings, failures, and skips must not qualify as successful backups."""
        js = dom.inline_js
        assert "row => row.status === 'SUCCESS'" in js
        assert '<div class="label">Last successful backup</div>' in js
        assert "No matching successful backup" in js

    def test_counts_use_recent_rows_but_history_cards_use_full_rows(
        self,
        dom: _AttrCollector,
    ) -> None:
        """Runs limits affect counts while full history feeds both latest cards."""
        js = dom.inline_js
        assert "function buildSummaryCards(recentRows, historyRows)" in js
        assert "const total = recentRows.length" in js
        assert "recentRows.filter(r => r.status === 'SUCCESS')" in js
        assert "buildSummaryCards(recentRows, trendRows)" in js

    def test_full_history_query_has_no_recent_limit(
        self,
        dom: _AttrCollector,
    ) -> None:
        """History-card input must not contain the recent-run limit clause."""
        js = dom.inline_js
        query_start = js.index("const trendSql")
        query_end = js.index("const [recentRows, trendRows]", query_start)
        history_query = js[query_start:query_end]
        assert "${limitClause}" not in history_query
        assert "SELECT id, run_started_at" in history_query


# ---------------------------------------------------------------------------
# JavaScript: cleaned archive filtering
# ---------------------------------------------------------------------------

class TestCleanedArchiveFiltering:
    """Cleaned archives must be retained in SQLite but excluded from the UI."""

    def test_all_dashboard_queries_require_active_archive(self, dom: _AttrCollector) -> None:
        """Definition, recent, limit, and trend queries must exclude deleted rows."""
        assert dom.inline_js.count("archive_deleted_at IS NULL") >= 4

    def test_recent_limit_ignores_deleted_newer_rows(self, dom: _AttrCollector) -> None:
        """Deleted rows must not consume one of the configured recent-run slots."""
        js = dom.inline_js
        limit_start = js.index("SELECT COUNT(*) FROM backup_runs b2")
        limit_end = js.index(") < ${limit}", limit_start)
        limit_query = js[limit_start:limit_end]
        assert "b2.archive_deleted_at IS NULL" in limit_query


# ---------------------------------------------------------------------------
# Backup-type filtering
# ---------------------------------------------------------------------------

class TestBackupTypeFiltering:
    """Backup type must filter every dashboard data set consistently."""

    def test_backup_type_dropdown_exists(self, dom: _AttrCollector) -> None:
        """The filter bar must expose a select control for backup type."""
        attrs = dom.by_id.get("filter-type")
        assert attrs is not None, "Element id='filter-type' not found"

    def test_backup_type_dropdown_lists_supported_types(self) -> None:
        """The dropdown must offer all valid backup types and an all-types choice."""
        for value in ('', "FULL", "DIFF", "INCR"):
            assert f'<option value="{value}">' in _HTML

    def test_backup_type_helper_reads_dropdown(self, dom: _AttrCollector) -> None:
        """JavaScript must read and normalize the selected backup type."""
        assert "function filterBackupType()" in dom.inline_js
        assert "getElementById('filter-type').value.trim()" in dom.inline_js

    def test_recent_query_applies_backup_type_clause(self, dom: _AttrCollector) -> None:
        """The recent-run table and summary query must include the type clause."""
        js = dom.inline_js
        query_start = js.index("const recentSql")
        query_end = js.index("const trendWhere", query_start)
        assert "${typeClause}" in js[query_start:query_end]

    def test_trend_query_applies_backup_type_clause(self, dom: _AttrCollector) -> None:
        """Trend history must use the same selected backup type."""
        assert "backupType   ? `backup_type =" in dom.inline_js

    def test_run_limit_counts_only_selected_backup_type(self, dom: _AttrCollector) -> None:
        """Last-N filtering must not count runs of other backup types."""
        js = dom.inline_js
        limit_start = js.index("SELECT COUNT(*) FROM backup_runs b2")
        limit_end = js.index(") < ${limit}", limit_start)
        assert "${limitTypeClause}" in js[limit_start:limit_end]

    def test_all_types_choice_produces_empty_sql_clauses(self, dom: _AttrCollector) -> None:
        """An empty selection must retain the existing all-types behavior."""
        js = dom.inline_js
        assert "const typeClause = backupType ?" in js
        assert "const limitTypeClause = backupType" in js


class TestRecentRunLimitFiltering:
    """The per-definition limit must count only rows matching every filter."""

    def test_limit_applies_date_range_to_counted_rows(self, dom: _AttrCollector) -> None:
        """Rows outside the selected date range cannot consume recent positions."""
        js = dom.inline_js
        assert "datetime(b2.run_started_at) >= datetime('${timeRange.from}')" in js
        assert "datetime(b2.run_started_at) <= datetime('${timeRange.to}')" in js
        assert "${limitFromClause}" in js
        assert "${limitToClause}" in js

    def test_limit_applies_prereq_and_postreq_filters(self, dom: _AttrCollector) -> None:
        """Excluded hook failures cannot consume recent positions."""
        js = dom.inline_js
        assert "b2.prereq_status IS NULL" in js
        assert "b2.postreq_status IS NULL" in js
        assert "${limitPhaseClauses}" in js

    def test_limit_uses_row_id_to_break_equal_timestamp_ties(
        self,
        dom: _AttrCollector,
    ) -> None:
        """Equal timestamps still produce an exact deterministic limit."""
        assert "b2.run_started_at = b.run_started_at AND b2.id > b.id" in dom.inline_js
        assert "b.run_started_at DESC, b.id DESC" in dom.inline_js


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


# ---------------------------------------------------------------------------
# Timezone-aware timestamp display
# ---------------------------------------------------------------------------

class TestTimezoneDisplay:
    """
    Timestamps stored as UTC ISO 8601 must be converted to the browser's local
    timezone before display, and the active timezone must be shown in the UI.
    """

    def test_fmt_ts_uses_date_constructor(self, dom: _AttrCollector) -> None:
        """fmtTs must parse timestamps via new Date() for correct UTC→local conversion."""
        assert "new Date(ts)" in dom.inline_js, (
            "fmtTs does not use new Date(ts) — UTC timestamps will display as-is "
            "instead of being converted to the browser's local timezone"
        )

    def test_fmt_ts_does_not_use_naive_slice_as_primary_path(self, dom: _AttrCollector) -> None:
        """The naive .replace('T',' ').substring(0,16) must be a fallback, not the main path."""
        js = dom.inline_js
        # The naive slice is still present as an isNaN() fallback — acceptable.
        # What must NOT happen is fmtTs returning it unconditionally (i.e. without
        # an isNaN guard).  Verify the guard exists alongside the slice.
        assert "isNaN(d)" in js, (
            "fmtTs has no isNaN guard — naive string slice may execute on valid "
            "UTC timestamps, bypassing timezone conversion"
        )

    def test_local_tz_abbr_function_defined(self, dom: _AttrCollector) -> None:
        """localTzAbbr() must be defined so callers can obtain the short tz name."""
        assert "function localTzAbbr" in dom.inline_js, (
            "function localTzAbbr not found — timezone label cannot be shown in the UI"
        )

    def test_local_tz_abbr_uses_intl(self, dom: _AttrCollector) -> None:
        """localTzAbbr must use Intl.DateTimeFormat for standards-compliant tz names."""
        assert "Intl.DateTimeFormat" in dom.inline_js, (
            "Intl.DateTimeFormat not found in JS — localTzAbbr cannot resolve "
            "the browser timezone abbreviation"
        )

    def test_started_header_shows_timezone(self, dom: _AttrCollector) -> None:
        """The 'Started' column header must call localTzAbbr() to display the active zone."""
        assert "localTzAbbr()" in dom.inline_js, (
            "localTzAbbr() is never called — timezone abbreviation will not appear "
            "in the 'Started' column header or the last-updated timestamp"
        )

    def test_last_updated_includes_timezone(self, dom: _AttrCollector) -> None:
        """The last-updated header must append the timezone abbreviation."""
        js = dom.inline_js
        # Both toLocaleTimeString() and localTzAbbr() must appear near last-updated
        assert "toLocaleTimeString()" in js and "localTzAbbr()" in js, (
            "last-updated display does not include both toLocaleTimeString() and "
            "localTzAbbr() — the active timezone will not be shown"
        )
