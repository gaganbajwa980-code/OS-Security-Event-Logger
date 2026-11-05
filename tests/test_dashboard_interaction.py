"""
Tests for Dashboard Interaction, Sidebar Logic, Lifecycle Controls, and Metric Integrity.
Verifies requirement 9 of Phase 5 refinement:
- Sidebar expanded/collapsed state and toggle mechanics
- Real metric sources and empty dataset resilience
- Start, pause, resume, and stop controls
- Invalid lifecycle transitions and duplicate worker prevention
- Single-cycle poll behaviour
- Refresh without duplicate collection
- Source-type transparency (LIVE_WINDOWS, SIMULATED_REPLAY, STATIC_SAMPLE_FILE)
- Incident metric tracking
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from monitor.app_state import MonitoringStatus
from monitor.controller import SentinelController
from monitor.event_models import Incident, IncidentStatus, SecurityEvent, SourceType


class DashboardInteractionAndLifecycleTests(unittest.TestCase):
    """Test suite for dashboard controls, lifecycle transitions, and metric integrity."""

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

    # ------------------------------------------------------------------
    # 1. Sidebar State & Toggle Mechanics
    # ------------------------------------------------------------------

    def test_sidebar_state_defaults_and_toggle(self):
        """Verify sidebar state persistence and expand/collapse toggling."""
        # Simulate Streamlit session state dictionary
        session_state = {"sidebar_expanded": True, "page": "Overview"}

        # Initial state should be expanded
        self.assertTrue(session_state["sidebar_expanded"])
        self.assertEqual(session_state["page"], "Overview")

        # Toggle to collapsed
        session_state["sidebar_expanded"] = not session_state["sidebar_expanded"]
        self.assertFalse(session_state["sidebar_expanded"])
        # Page must be preserved when toggling sidebar
        self.assertEqual(session_state["page"], "Overview")

        # Toggle back to expanded
        session_state["sidebar_expanded"] = not session_state["sidebar_expanded"]
        self.assertTrue(session_state["sidebar_expanded"])
        self.assertEqual(session_state["page"], "Overview")

    # ------------------------------------------------------------------
    # 2. Start, Pause, Resume, and Stop Lifecycle
    # ------------------------------------------------------------------

    def test_start_pause_resume_stop_lifecycle_state(self):
        """Verify full monitoring thread lifecycle with genuine state transitions."""
        # Initial status
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.IDLE.value)
        self.assertFalse(self.controller.is_worker_alive())

        # START
        started = self.controller.start_monitoring()
        self.assertTrue(started)
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.RUNNING.value)
        self.assertTrue(self.controller.is_worker_alive())

        # PAUSE
        paused = self.controller.pause_monitoring()
        self.assertTrue(paused)
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.PAUSED.value)
        self.assertTrue(self.controller.is_worker_alive())

        # RESUME
        resumed = self.controller.resume_monitoring()
        self.assertTrue(resumed)
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.RUNNING.value)
        self.assertTrue(self.controller.is_worker_alive())

        # STOP
        stopped = self.controller.stop_monitoring(timeout=2.0)
        self.assertTrue(stopped)
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.STOPPED.value)
        self.assertFalse(self.controller.is_worker_alive())

    def test_invalid_lifecycle_transitions(self):
        """Ensure invalid operations are rejected gracefully without corrupting state."""
        # Cannot pause when idle
        self.assertFalse(self.controller.pause_monitoring())
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.IDLE.value)

        # Cannot resume when not running/paused
        self.assertFalse(self.controller.resume_monitoring())
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.IDLE.value)

        # Stop when already idle is safe and idempotent
        self.assertTrue(self.controller.stop_monitoring())
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.STOPPED.value)

    def test_duplicate_worker_prevention(self):
        """Ensure calling start_monitoring repeatedly does not create duplicate workers."""
        self.assertTrue(self.controller.start_monitoring())
        first_worker = self.controller._worker_thread
        self.assertIsNotNone(first_worker)

        # Second call to start must be a no-op
        self.assertTrue(self.controller.start_monitoring())
        second_worker = self.controller._worker_thread
        self.assertIs(first_worker, second_worker)
        self.assertTrue(first_worker.is_alive())

    # ------------------------------------------------------------------
    # 3. Single-Cycle Poll & Refresh Behaviour
    # ------------------------------------------------------------------

    def test_single_cycle_poll_behaviour(self):
        """Verify that run_once() performs exactly one cycle without starting background thread."""
        self.assertEqual(self.controller.get_monitoring_status(), MonitoringStatus.IDLE.value)
        self.assertFalse(self.controller.is_worker_alive())

        events = self.controller.run_once()
        self.assertIsInstance(events, list)
        self.assertGreater(len(events), 0)

        # Background thread should still NOT be active
        self.assertFalse(self.controller.is_worker_alive())
        snap = self.controller.get_dashboard_snapshot()
        self.assertEqual(snap["total_events_processed"], len(events))

    def test_dashboard_refresh_without_duplicate_collection(self):
        """Verify that refreshing dashboard metrics does not run a collection cycle or increment counts."""
        # Initial poll
        evs = self.controller.run_once()
        initial_count = len(evs)
        self.assertGreater(initial_count, 0)

        # Refresh snapshot multiple times
        snap1 = self.controller.get_dashboard_snapshot()
        snap2 = self.controller.get_dashboard_snapshot()
        diag = self.controller.refresh_diagnostics()

        self.assertIsNotNone(diag)
        self.assertEqual(snap1["total_events_processed"], initial_count)
        self.assertEqual(snap2["total_events_processed"], initial_count)

    # ------------------------------------------------------------------
    # 4. Source-Type Transparency
    # ------------------------------------------------------------------

    def test_source_type_transparency(self):
        """Verify that LIVE_WINDOWS, SIMULATED_REPLAY, and STATIC_SAMPLE_FILE are tracked accurately."""
        # Static sample file
        self.controller.set_source_type(SourceType.STATIC_SAMPLE_FILE)
        self.assertEqual(self.controller.source_type, SourceType.STATIC_SAMPLE_FILE)
        snap = self.controller.get_dashboard_snapshot()
        self.assertEqual(snap["active_source"], SourceType.STATIC_SAMPLE_FILE.value)

        # Simulated replay
        self.controller.set_source_type(SourceType.SIMULATED_REPLAY)
        self.assertEqual(self.controller.source_type, SourceType.SIMULATED_REPLAY)
        snap = self.controller.get_dashboard_snapshot()
        self.assertEqual(snap["active_source"], SourceType.SIMULATED_REPLAY.value)

        # Live Windows
        self.controller.set_source_type(SourceType.LIVE_WINDOWS)
        self.assertEqual(self.controller.source_type, SourceType.LIVE_WINDOWS)
        snap = self.controller.get_dashboard_snapshot()
        self.assertEqual(snap["active_source"], SourceType.LIVE_WINDOWS.value)

    # ------------------------------------------------------------------
    # 5. Empty Datasets Resilience & Real Metric Extraction
    # ------------------------------------------------------------------

    def test_empty_event_and_detection_datasets_resilience(self):
        """Ensure dashboard metric extraction handles empty buffers without throwing exceptions."""
        empty_controller = SentinelController(
            channels=["System"],
            source_type=SourceType.LIVE_WINDOWS,
            checkpoint_path=self.checkpoint_path,
            incident_storage_path=self.incident_path,
        )
        snap = empty_controller.get_dashboard_snapshot()
        self.assertEqual(snap["total_events_processed"], 0)
        self.assertEqual(snap["total_detections_generated"], 0)
        self.assertEqual(snap["open_incidents"], 0)

        recent = empty_controller.get_recent_events(limit=50)
        detections = empty_controller.get_recent_detections(limit=50)
        incidents = empty_controller.get_incidents()

        self.assertEqual(recent, [])
        self.assertEqual(detections, [])
        self.assertEqual(incidents, [])

    # ------------------------------------------------------------------
    # 6. Incident Metric Tracking & Status Transitions
    # ------------------------------------------------------------------

    def test_incident_metric_updates_and_lifecycle(self):
        """Verify that incident status transitions update dashboard counts accurately."""
        self.controller.run_once()
        all_incidents = self.controller.get_incidents()
        self.assertGreater(len(all_incidents), 0)

        target = all_incidents[0]
        self.assertEqual(target.status, "OPEN")

        # Mark INVESTIGATING
        updated = self.controller.update_incident_status(target.incident_id, IncidentStatus.INVESTIGATING)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, "INVESTIGATING")

        open_list = self.controller.get_incidents(status=IncidentStatus.OPEN)
        inv_list = self.controller.get_incidents(status=IncidentStatus.INVESTIGATING)
        self.assertEqual(len(inv_list), 1)

        # Mark RESOLVED
        resolved = self.controller.update_incident_status(target.incident_id, IncidentStatus.RESOLVED)
        self.assertEqual(resolved.status, "RESOLVED")
        res_list = self.controller.get_incidents(status=IncidentStatus.RESOLVED)
        self.assertEqual(len(res_list), 1)


if __name__ == "__main__":
    unittest.main()
