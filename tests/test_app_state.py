"""
Unit tests for monitor/app_state.py.
Tests:
- Thread-safe concurrent state updates
- Telemetry snapshot consistency
- Bounded ring buffers (maxlen enforcement)
- Error recording, clearing, and status transitions
"""

import threading
import unittest
from datetime import datetime, timezone

from monitor.app_state import AppState, MonitoringStatus
from monitor.event_models import SecurityEvent, SeverityLevel, SourceType


class AppStateTests(unittest.TestCase):
    """Test the synchronized AppState container."""

    def setUp(self):
        self.state = AppState(max_events=10, max_detections=5)

    def test_initial_state_is_idle(self):
        self.assertEqual(self.state.get_status(), MonitoringStatus.IDLE)
        snapshot = self.state.get_dashboard_snapshot()
        self.assertEqual(snapshot["status"], "IDLE")
        self.assertEqual(snapshot["total_events_processed"], 0)
        self.assertEqual(snapshot["total_detections_generated"], 0)
        self.assertIsNone(snapshot["start_time"])
        self.assertIsNone(snapshot["last_error"])

    def test_status_and_timestamps(self):
        self.state.set_status(MonitoringStatus.RUNNING)
        self.assertEqual(self.state.get_status(), MonitoringStatus.RUNNING)
        snap1 = self.state.get_dashboard_snapshot()
        self.assertIsNotNone(snap1["start_time"])

        self.state.set_status(MonitoringStatus.PAUSED)
        self.assertEqual(self.state.get_status(), MonitoringStatus.PAUSED)

        self.state.set_status(MonitoringStatus.STOPPED)
        snap2 = self.state.get_dashboard_snapshot()
        self.assertEqual(snap2["status"], "STOPPED")
        self.assertIsNone(snap2["start_time"])

    def test_error_recording_and_clearing(self):
        self.state.set_error("RPC connection timeout")
        self.assertEqual(self.state.get_status(), MonitoringStatus.ERROR)
        snapshot = self.state.get_dashboard_snapshot()
        self.assertEqual(snapshot["last_error"], "RPC connection timeout")

        self.state.clear_error()
        self.assertIsNone(self.state.get_dashboard_snapshot()["last_error"])

    def test_bounded_ring_buffers(self):
        """Ensure ring buffers enforce maxlen without unbounded memory growth."""
        # Max events is 10
        for i in range(25):
            ev = SecurityEvent(
                timestamp=f"2026-10-30T10:00:{i:02d}Z",
                message=f"Event {i}",
                is_suspicious=(i % 2 == 0),
            )
            self.state.record_event(ev)

        recent = self.state.get_recent_events(limit=50)
        self.assertEqual(len(recent), 10)  # Capped at max_events (10)
        # Newest event should be first
        self.assertEqual(recent[0].message, "Event 24")

        detections = self.state.get_recent_detections(limit=50)
        self.assertEqual(len(detections), 5)  # Capped at max_detections (5)
        self.assertTrue(all(d.is_suspicious for d in detections))

        snapshot = self.state.get_dashboard_snapshot()
        self.assertEqual(snapshot["total_events_processed"], 25)
        self.assertEqual(snapshot["total_detections_generated"], 13)

    def test_thread_safe_concurrent_updates(self):
        """Verify state consistency under concurrent multi-threaded ingestion."""
        threads = []
        events_per_thread = 50

        def worker(thread_id: int):
            for i in range(events_per_thread):
                ev = SecurityEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    message=f"Thread {thread_id} Event {i}",
                    is_suspicious=(i == 0),
                )
                self.state.record_event(ev)

        for tid in range(4):
            t = threading.Thread(target=worker, args=(tid,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        snapshot = self.state.get_dashboard_snapshot()
        # 4 threads * 50 events = 200 total processed
        self.assertEqual(snapshot["total_events_processed"], 200)
        # 4 threads * 1 detection = 4 total detections
        self.assertEqual(snapshot["total_detections_generated"], 4)


if __name__ == "__main__":
    unittest.main()
