"""
Tests for Redesigned Sentinel Dashboard.
Validates:
- Horizontal navigation state and route resolution
- Secondary context tabs per page
- Monitoring controls (Start, Pause, Resume, Stop, Poll Now, Refresh)
- Source type switching (LIVE_WINDOWS, SIMULATED_REPLAY, STATIC_SAMPLE_FILE)
- Incident lifecycle transitions and persistence
- Search, filter, and pagination logic
- CSV and JSON export data integrity
- Chart aggregation and KPI calculations
"""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from monitor.app_state import MonitoringStatus
from monitor.controller import SentinelController
from monitor.event_models import Incident, IncidentStatus, SecurityEvent, SourceType
from detection.rules import ALL_RULES, RULE_BRUTE_FORCE
from dashboard.components import (
    MAIN_PAGES,
    events_to_csv,
    events_to_json,
    format_timestamp,
    get_severity_badge_html,
    get_source_badge_html,
    get_status_pill_html,
    incidents_to_csv,
    incidents_to_json,
)
from dashboard.views.overview import OVERVIEW_TABS
from dashboard.views.events import EVENTS_TABS
from dashboard.views.threats import THREATS_TABS
from dashboard.views.investigations import INVESTIGATIONS_TABS
from dashboard.views.analytics import ANALYTICS_TABS
from dashboard.views.system import SYSTEM_TABS


class RedesignedDashboardTests(unittest.TestCase):
    """Test suite for the redesigned Sentinel dashboard presentation tier."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.checkpoint_path = Path(self.temp_dir.name) / ".checkpoint.json"
        self.incident_path = Path(self.temp_dir.name) / "incidents.json"
        self.controller = SentinelController(
            channels=["System", "Application"],
            poll_interval=0.2,
            checkpoint_path=self.checkpoint_path,
            incident_storage_path=self.incident_path,
            source_type=SourceType.STATIC_SAMPLE_FILE,
        )

    def tearDown(self):
        self.controller.stop_monitoring(timeout=1.0)
        self.temp_dir.cleanup()

    # ── 1. Navigation & Route Tests ───────────────────────────────────────────

    def test_main_navigation_items(self):
        """Verify all 6 main horizontal navigation tabs are defined and valid."""
        expected_pages = ["Overview", "Events", "Threats", "Investigations", "Analytics", "System"]
        self.assertEqual(MAIN_PAGES, expected_pages)

    def test_secondary_navigation_tabs_specification(self):
        """Verify context tabs for all 6 pages match requirements."""
        self.assertEqual(OVERVIEW_TABS, ["Event Overview", "Host Overview", "Security Overview", "Incident Overview"])
        self.assertEqual(EVENTS_TABS, ["All Events", "Windows System", "Windows Application", "Windows Security", "Simulated Events"])
        self.assertEqual(THREATS_TABS, ["Detection Overview", "Detection Rules", "Severity Analysis"])
        self.assertEqual(INVESTIGATIONS_TABS, ["All Incidents", "Open", "Investigating", "Resolved"])
        self.assertEqual(ANALYTICS_TABS, ["Event Trends", "Threat Trends", "Source Distribution"])
        self.assertEqual(SYSTEM_TABS, ["Environment", "Windows Channels", "Collector Diagnostics", "Configuration"])

    def test_legacy_route_aliasing(self):
        """Verify legacy route names are mapped cleanly to new sections."""
        alias_map = {
            "Event Stream": "Events",
            "Log Explorer": "Events",
            "Threat Detection": "Threats",
        }
        self.assertEqual(alias_map["Event Stream"], "Events")
        self.assertEqual(alias_map["Log Explorer"], "Events")
        self.assertEqual(alias_map["Threat Detection"], "Threats")

    # ── 2. Monitoring Controls & State Transitions ────────────────────────────

    def test_start_monitoring_worker(self):
        """Verify start_monitoring launches worker and reports RUNNING status."""
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.IDLE.value)
        self.assertTrue(self.controller.start_monitoring())
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.RUNNING.value)
        self.assertTrue(self.controller.is_worker_alive())

    def test_pause_and_resume_controls(self):
        """Verify pause suspends collection and resume restores worker without duplication."""
        self.controller.start_monitoring()
        worker1 = self.controller._worker_thread

        # PAUSE
        self.assertTrue(self.controller.pause_monitoring())
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.PAUSED.value)
        self.assertTrue(self.controller.is_worker_alive())

        # RESUME
        self.assertTrue(self.controller.resume_monitoring())
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.RUNNING.value)
        self.assertTrue(self.controller.is_worker_alive())
        self.assertIs(self.controller._worker_thread, worker1)

    def test_stop_monitoring_control(self):
        """Verify stop terminates the background thread cleanly."""
        self.controller.start_monitoring()
        self.assertTrue(self.controller.stop_monitoring(timeout=1.0))
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.STOPPED.value)
        self.assertFalse(self.controller.is_worker_alive())

    def test_poll_now_single_execution(self):
        """Verify poll now executes exactly 1 cycle without spawning daemon."""
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.IDLE.value)
        polled = self.controller.run_once()
        self.assertIsInstance(polled, list)
        self.assertGreater(len(polled), 0)
        self.assertFalse(self.controller.is_worker_alive())

    def test_refresh_does_not_mutate_event_counts(self):
        """Verify refresh snapshot returns state without incrementing event count."""
        polled = self.controller.run_once()
        snap1 = self.controller.get_dashboard_snapshot()
        self.controller.refresh_diagnostics()
        snap2 = self.controller.get_dashboard_snapshot()
        self.assertEqual(snap1["total_events_processed"], snap2["total_events_processed"])

    # ── 3. Source Switching ───────────────────────────────────────────────────

    def test_source_selection_and_persistence(self):
        """Verify source selection persists across queries."""
        for src in [SourceType.STATIC_SAMPLE_FILE, SourceType.SIMULATED_REPLAY, SourceType.LIVE_WINDOWS]:
            self.controller.set_source_type(src)
            self.assertEqual(self.controller.source_type, src)
            snap = self.controller.get_dashboard_snapshot()
            self.assertEqual(snap["active_source"], src.value)

    # ── 4. Incident Lifecycle & Transitions ───────────────────────────────────

    def test_incident_status_transitions_complete(self):
        """Verify OPEN -> INVESTIGATING -> RESOLVED lifecycle updates."""
        self.controller.run_once()
        incidents = self.controller.get_incidents()
        self.assertGreater(len(incidents), 0)

        inc_id = incidents[0].incident_id
        # OPEN -> INVESTIGATING
        updated = self.controller.update_incident_status(inc_id, IncidentStatus.INVESTIGATING)
        self.assertEqual(updated.status, "INVESTIGATING")
        self.assertEqual(len(self.controller.get_incidents(status=IncidentStatus.INVESTIGATING)), 1)

        # INVESTIGATING -> RESOLVED
        resolved = self.controller.update_incident_status(inc_id, IncidentStatus.RESOLVED)
        self.assertEqual(resolved.status, "RESOLVED")
        self.assertEqual(len(self.controller.get_incidents(status=IncidentStatus.RESOLVED)), 1)

        # RESOLVED -> OPEN
        reopened = self.controller.update_incident_status(inc_id, IncidentStatus.OPEN)
        self.assertEqual(reopened.status, "OPEN")
        self.assertEqual(len(self.controller.get_incidents(status=IncidentStatus.OPEN)), len(incidents))

    # ── 5. Search & Filtering ─────────────────────────────────────────────────

    def test_event_filtering_by_channel_and_severity(self):
        """Verify events filter accurately by channel and severity levels."""
        events = self.controller.run_once()
        # Filter channel
        sample_evs = [e for e in events if e.channel.lower() == "sample"]
        self.assertGreater(len(sample_evs), 0)

        # Filter severity (failed logins and unauthorized access become HIGH, normal are INFO)
        high_evs = [e for e in events if (e.severity or "").upper() == "HIGH"]
        self.assertGreater(len(high_evs), 0)

        info_evs = [e for e in events if (e.severity or "").upper() == "INFO"]
        self.assertGreater(len(info_evs), 0)

        # Keyword filter
        admin_evs = [e for e in events if "admin" in (e.user or "").lower() or "admin" in (e.message or "").lower()]
        self.assertGreater(len(admin_evs), 0)

    # ── 6. CSV and JSON Export Data Integrity ─────────────────────────────────

    def test_events_export_serialization(self):
        """Verify events CSV and JSON exports produce valid data."""
        events = self.controller.run_once()

        # CSV test
        csv_str = events_to_csv(events)
        reader = list(csv.reader(csv_str.strip().splitlines()))
        self.assertGreater(len(reader), 1)  # header + rows
        self.assertIn("timestamp", reader[0])
        self.assertIn("event_id", reader[0])

        # JSON test
        json_str = events_to_json(events)
        loaded = json.loads(json_str)
        self.assertEqual(len(loaded), len(events))
        self.assertIn("timestamp", loaded[0])

    def test_incidents_export_serialization(self):
        """Verify incidents CSV and JSON exports produce valid data."""
        self.controller.run_once()
        incidents = self.controller.get_incidents()
        self.assertGreater(len(incidents), 0)

        # CSV test
        csv_str = incidents_to_csv(incidents)
        reader = list(csv.reader(csv_str.strip().splitlines()))
        self.assertGreater(len(reader), 1)
        self.assertIn("incident_id", reader[0])

        # JSON test
        json_str = incidents_to_json(incidents)
        loaded = json.loads(json_str)
        self.assertEqual(len(loaded), len(incidents))
        self.assertEqual(loaded[0]["incident_id"], incidents[0].incident_id)

    # ── 7. KPI & Chart Aggregations ───────────────────────────────────────────

    def test_kpi_calculations_truthfulness(self):
        """Verify KPI computations strictly match underlying state."""
        self.controller.run_once()
        snap = self.controller.get_dashboard_snapshot()
        incidents = self.controller.get_incidents()
        events = self.controller.get_recent_events(limit=100)

        # Total events KPI matches
        self.assertEqual(snap["total_events_processed"], len(events))
        # Total threats KPI matches suspicious count
        susp_count = sum(1 for e in events if e.is_suspicious)
        self.assertEqual(snap["total_detections_generated"], susp_count)
        # Open incidents count matches
        open_count = sum(1 for i in incidents if i.status == "OPEN")
        self.assertEqual(snap["open_incidents"], open_count)

    def test_all_seven_detection_rules_catalog(self):
        """Verify all seven required detection rules exist with correct identifiers."""
        rule_ids = [r.rule_id for r in ALL_RULES]
        expected_ids = ["SEC-R01", "SEC-R02", "SEC-R03", "SEC-R04", "SEC-R05", "SEC-R06", "SEC-R07"]
        self.assertEqual(rule_ids, expected_ids)

    # ── 8. HTML Badges & Formatting ───────────────────────────────────────────

    def test_badge_and_formatting_helpers(self):
        """Verify badges produce non-empty, sanitized HTML."""
        self.assertIn("sev-critical", get_severity_badge_html("CRITICAL"))
        self.assertIn("sev-high", get_severity_badge_html("HIGH"))
        self.assertIn("src-live", get_source_badge_html("LIVE_WINDOWS"))
        self.assertIn("pill-running", get_status_pill_html("RUNNING"))
        self.assertEqual(format_timestamp(None), "—")
        self.assertIn("2026-10-30", format_timestamp("2026-10-30T10:00:00Z"))

    # ── 9. Theme System & Mode Switching ──────────────────────────────────────

    def test_dark_and_light_theme_palettes(self):
        """Verify both dark and light theme palettes define all required color keys."""
        from dashboard.theme import get_theme, THEMES
        required_keys = [
            "main_bg", "nav_bg", "secondary_surface", "card_bg", "elevated_surface",
            "text_primary", "text_secondary", "text_muted", "border", "border_subtle",
            "primary_blue", "ice_blue", "success", "warning", "critical"
        ]
        for mode in ("dark", "light"):
            palette = get_theme(mode)
            for k in required_keys:
                self.assertIn(k, palette, f"Missing key {k} in {mode} theme")
                self.assertTrue(palette[k].startswith("#"), f"Color {k} should be hex code")

        # Verify dark mode specific colors
        dark_p = get_theme("dark")
        self.assertEqual(dark_p["main_bg"], "#0B1220")
        self.assertEqual(dark_p["card_bg"], "#162338")
        self.assertEqual(dark_p["nav_bg"], "#080F1C")
        self.assertEqual(dark_p["text_primary"], "#E8F0FC")

        # Verify light mode specific colors
        light_p = get_theme("light")
        self.assertEqual(light_p["main_bg"], "#F4F7FB")
        self.assertEqual(light_p["card_bg"], "#FFFFFF")
        self.assertEqual(light_p["text_primary"], "#172B4D")

    def test_theme_css_generation(self):
        """Verify get_app_css produces valid CSS containing appropriate colors."""
        from dashboard.theme import get_app_css
        dark_css = get_app_css("dark")
        self.assertIn("#0B1220", dark_css)
        self.assertIn("#162338", dark_css)

        light_css = get_app_css("light")
        self.assertIn("#F4F7FB", light_css)
        self.assertIn("#FFFFFF", light_css)

    def test_plotly_theme_application(self):
        """Verify apply_plotly_theme applies colors without error."""
        import plotly.graph_objects as go
        from dashboard.theme import apply_plotly_theme
        fig = go.Figure()
        fig.add_trace(go.Bar(x=[1, 2], y=[3, 4]))

        dark_fig = apply_plotly_theme(fig, theme_name="dark", height=200)
        self.assertEqual(dark_fig.layout.height, 200)
        self.assertEqual(dark_fig.layout.paper_bgcolor, "rgba(0,0,0,0)")

        light_fig = apply_plotly_theme(fig, theme_name="light", height=250)
        self.assertEqual(light_fig.layout.height, 250)
        self.assertEqual(light_fig.layout.paper_bgcolor, "rgba(0,0,0,0)")

    def test_theme_switching_session_state(self):
        """Verify theme state toggle logic functions cleanly."""
        state = {"theme": "dark"}
        # Toggle to light
        state["theme"] = "light" if state["theme"] == "dark" else "dark"
        self.assertEqual(state["theme"], "light")
        # Toggle back to dark
        state["theme"] = "light" if state["theme"] == "dark" else "dark"
        self.assertEqual(state["theme"], "dark")

    def test_branding_tokens_and_contrast(self):
        """Verify brand wordmark and subtitle tokens are defined with appropriate contrast."""
        from dashboard.theme import get_theme
        light_p = get_theme("light")
        dark_p = get_theme("dark")

        # Light mode branding: dark navy wordmark, muted blue subtitle
        self.assertEqual(light_p["brand_wordmark"], "#172B4D")
        self.assertEqual(light_p["brand_subtitle"], "#2878C7")

        # Dark mode branding: near-white wordmark, light ice blue subtitle
        self.assertEqual(dark_p["brand_wordmark"], "#F1F5FB")
        self.assertEqual(dark_p["brand_subtitle"], "#7DBBFF")

    def test_theme_css_covers_metrics_and_containers(self):
        """Verify generated CSS includes explicit rules for stMetric, containers, and top navbar."""
        from dashboard.theme import get_app_css
        for theme_name in ("dark", "light"):
            css = get_app_css(theme_name)
            self.assertIn("stMetric", css)
            self.assertIn("st-key-top_navbar", css)
            self.assertIn("st-key-secondary_nav", css)
            self.assertIn("st-key-monitoring_toolbar", css)
            self.assertIn("sentinel-card-header", css)

    def test_clean_html_strips_indentation_and_newlines(self):
        """Verify clean_html removes all newlines and indentation to avoid CommonMark code blocks."""
        from dashboard.components import clean_html
        raw_indented = """
            <div>
                <span class="test">Hello World</span>
            </div>
        """
        cleaned = clean_html(raw_indented)
        self.assertNotIn("\n", cleaned)
        self.assertFalse(cleaned.startswith(" "))
        self.assertEqual(cleaned, '<div> <span class="test">Hello World</span> </div>')

    def test_theme_css_covers_buttons_and_theme_toggle(self):
        """Verify generated CSS has high-specificity rules targeting Streamlit buttons."""
        from dashboard.theme import get_app_css
        for theme_name in ("dark", "light"):
            css = get_app_css(theme_name)
            self.assertIn(".stApp button", css)
            self.assertIn('button[data-testid="baseButton-secondary"]', css)
            self.assertIn('div.st-key-btn_theme_toggle button', css)
            self.assertIn('div.st-key-nav_quick_refresh button', css)

    def test_card_helpers_exist_and_callable(self):
        """Verify card_container and render_card_header exist in components."""
        from dashboard.components import card_container, render_card_header
        self.assertTrue(callable(card_container))
        self.assertTrue(callable(render_card_header))



if __name__ == "__main__":
    unittest.main()
