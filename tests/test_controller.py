"""
Unit tests for monitor/controller.py.
Tests:
- Initialization and component wiring
- Start, pause, resume, stop lifecycle controls
- Duplicate worker prevention
- Idempotent lifecycle calls
- End-to-end event collection, detection, and incident integration
- Component error handling and recovery
- Sample file mode integration
- Security channel access denial handling
"""

import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from monitor.app_state import MonitoringStatus
from monitor.controller import SentinelController
from monitor.event_models import IncidentStatus, SecurityEvent, SeverityLevel, SourceType


class SentinelControllerTests(unittest.TestCase):
    """Test the central SentinelController integration engine."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_ctrl_"))
        self.checkpoint_path = self.test_dir / ".checkpoint.json"
        self.incidents_path = self.test_dir / "incidents.json"

        self.controller = SentinelController(
            channels=["System", "Application"],
            poll_interval=0.1,  # Fast polling for tests
            detection_threshold=3,
            window_seconds=60,
            checkpoint_path=self.checkpoint_path,
            incident_storage_path=self.incidents_path,
            source_type=SourceType.LIVE_WINDOWS,
        )

    def tearDown(self):
        # Guarantee background thread termination
        self.controller.stop_monitoring(timeout=1.0)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_initialization_state(self):
        """Verify initial state is IDLE with diagnostic metrics present."""
        self.assertEqual(self.controller.get_monitoring_status(), "IDLE")
        snapshot = self.controller.get_dashboard_snapshot()
        self.assertEqual(snapshot["status"], "IDLE")
        self.assertEqual(snapshot["active_source"], "LIVE_WINDOWS")
        self.assertIn("channels", snapshot["diagnostics"])
        self.assertEqual(len(self.controller.get_recent_events()), 0)
        self.assertEqual(len(self.controller.get_incidents()), 0)

    def test_start_pause_resume_stop_lifecycle(self):
        """Verify full monitoring lifecycle and thread management."""
        # 1. Start monitoring
        started = self.controller.start_monitoring()
        self.assertTrue(started)
        self.assertEqual(self.controller.get_monitoring_status(), "RUNNING")
        self.assertIsNotNone(self.controller._worker_thread)
        self.assertTrue(self.controller._worker_thread.is_alive())

        # 2. Prevent duplicate workers (calling start again must be a no-op)
        initial_thread = self.controller._worker_thread
        self.controller.start_monitoring()
        self.assertIs(self.controller._worker_thread, initial_thread)

        # 3. Pause monitoring
        paused = self.controller.pause_monitoring()
        self.assertTrue(paused)
        self.assertEqual(self.controller.get_monitoring_status(), "PAUSED")
        self.assertTrue(self.controller._worker_thread.is_alive())

        # 4. Resume monitoring
        resumed = self.controller.resume_monitoring()
        self.assertTrue(resumed)
        self.assertEqual(self.controller.get_monitoring_status(), "RUNNING")

        # 5. Stop monitoring
        stopped = self.controller.stop_monitoring(timeout=2.0)
        self.assertTrue(stopped)
        self.assertEqual(self.controller.get_monitoring_status(), "STOPPED")
        self.assertIsNone(self.controller._worker_thread)

    def test_idempotent_lifecycle_calls(self):
        """Ensure repeated or out-of-order lifecycle calls do not raise errors."""
        # Calling stop when already stopped
        self.assertTrue(self.controller.stop_monitoring())
        self.assertEqual(self.controller.get_monitoring_status(), "STOPPED")

        # Calling pause or resume when stopped/idle
        self.assertFalse(self.controller.pause_monitoring())
        self.assertFalse(self.controller.resume_monitoring())

    def test_run_once_collection_and_detection_integration(self):
        """Verify that run_once polls events, detects threats, and updates state."""
        # Create mock security events
        mock_events = [
            SecurityEvent(
                timestamp=f"2026-10-30T10:00:{i * 5:02d}Z",
                source_type=SourceType.LIVE_WINDOWS,
                channel="Security",
                event_id=4625,
                record_id=100 + i,
                user="attacker",
                ip_address="192.168.1.50",
                message="Failed login attempt",
            )
            for i in range(3)
        ]

        # Patch collector.poll_all_channels to return mock events
        with patch.object(self.controller.collector, "poll_all_channels", return_value=mock_events):
            results = self.controller.run_once()

        self.assertEqual(len(results), 3)
        # All 3 events flagged by detector
        self.assertTrue(all(e.is_suspicious for e in results))

        # Check app_state metrics
        snapshot = self.controller.get_dashboard_snapshot()
        self.assertEqual(snapshot["total_events_processed"], 3)
        self.assertEqual(snapshot["total_detections_generated"], 3)
        self.assertEqual(snapshot["total_incidents"], 1)
        self.assertEqual(snapshot["open_incidents"], 1)

        # Check incident created
        incidents = self.controller.get_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].user, "attacker")
        self.assertEqual(incidents[0].event_count, 3)

    def test_incident_status_update_via_controller(self):
        """Verify incident status transitions through controller API."""
        mock_event = SecurityEvent(
            timestamp="2026-10-30T10:00:00Z",
            channel="System",
            event_id=7045,
            message="New service installed: test_svc",
        )
        with patch.object(self.controller.collector, "poll_all_channels", return_value=[mock_event]):
            self.controller.run_once()

        incidents = self.controller.get_incidents()
        self.assertEqual(len(incidents), 1)
        inc_id = incidents[0].incident_id

        # Update status to RESOLVED
        updated = self.controller.update_incident_status(inc_id, IncidentStatus.RESOLVED)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, "RESOLVED")

        # Verify open incidents count is now 0
        snapshot = self.controller.get_dashboard_snapshot()
        self.assertEqual(snapshot["open_incidents"], 0)

    def test_collector_error_handling_and_resilience(self):
        """Ensure collector exceptions are captured in state without crashing."""
        with patch.object(
            self.controller.collector,
            "poll_all_channels",
            side_effect=OSError("RPC server unavailable"),
        ):
            results = self.controller.run_once()

        self.assertEqual(results, [])
        snapshot = self.controller.get_dashboard_snapshot()
        self.assertIn("RPC server unavailable", snapshot["last_error"])

    def test_sample_file_mode(self):
        """Verify switching to STATIC_SAMPLE_FILE processes data/sample_logs.txt."""
        self.controller.set_source_type(SourceType.STATIC_SAMPLE_FILE)
        self.assertEqual(self.controller.source_type, SourceType.STATIC_SAMPLE_FILE)

        results = self.controller.run_once()
        self.assertEqual(len(results), 8)  # 8 lines in sample_logs.txt
        self.assertTrue(all(e.source_type == SourceType.STATIC_SAMPLE_FILE for e in results))

        snapshot = self.controller.get_dashboard_snapshot()
        self.assertEqual(snapshot["active_source"], "STATIC_SAMPLE_FILE")
        self.assertEqual(snapshot["total_events_processed"], 8)
        self.assertEqual(snapshot["total_detections_generated"], 4)

    def test_security_channel_access_denied_handling(self):
        """Verify controller handles ACCESS_DENIED for Security channel gracefully."""
        self.controller.collector.channel_status["Security"] = {
            "channel": "Security",
            "accessible": False,
            "status": "ACCESS_DENIED",
            "details": "Requires elevation",
        }
        self.controller.collector.channel_status["System"] = {
            "channel": "System",
            "accessible": True,
            "status": "ONLINE",
        }

        # Controller should not crash and should reflect accurate status
        self.assertFalse(self.controller.collector.is_channel_accessible("Security"))
        self.assertTrue(self.controller.collector.is_channel_accessible("System"))


if __name__ == "__main__":
    unittest.main()
