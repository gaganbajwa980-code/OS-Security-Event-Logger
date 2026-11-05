"""
Unit tests for Sentinel Phase 3: Detection Engine & Incident Management.
Tests:
- Failed login thresholds and sliding time-window expiration
- Grouping by account and source IP
- Handling of missing accounts and IP fields
- Windows Event IDs (4625, 4624, 7045, 1102, 4720, 4728)
- Duplicate incident prevention and event correlation
- Incident status transitions (OPEN -> INVESTIGATING -> RESOLVED)
- Incident persistence and restart recovery
- Mixed live, simulated, and sample event sources
- Incomplete and malformed event data resilience
"""

import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from monitor.event_models import (
    IncidentStatus,
    SecurityEvent,
    SeverityLevel,
    SourceType,
)
from detection.detector import SecurityDetector, detect_security_events
from detection.incident_manager import IncidentManager
from detection.rules import (
    RULE_ACCOUNT_CREATED,
    RULE_AUDIT_LOG_CLEARED,
    RULE_BRUTE_FORCE,
    RULE_NEW_SERVICE,
    RULE_PRIVILEGE_MODIFIED,
)


class DetectionEngineTests(unittest.TestCase):
    """Test the SecurityDetector rules and sliding time-window logic."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_det_"))
        self.incidents_path = self.test_dir / "incidents.json"
        self.incident_manager = IncidentManager(storage_path=self.incidents_path)
        self.detector = SecurityDetector(
            threshold=3,
            window_seconds=60,
            incident_manager=self.incident_manager,
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_failed_login_threshold_triggers_alert_and_incident(self):
        """Verify that 3 failed logins within 60s trigger an alert and create an incident."""
        events = [
            SecurityEvent(
                timestamp=f"2026-10-30T10:00:{i * 10:02d}Z",
                source_type=SourceType.LIVE_WINDOWS,
                channel="Security",
                event_id=4625,
                record_id=100 + i,
                user="target_user",
                ip_address="192.168.1.100",
                message="An account failed to log on",
            )
            for i in range(3)
        ]

        processed, incidents = self.detector.evaluate_batch(events)
        self.assertEqual(len(processed), 3)

        # All events in the triggered cluster must be marked suspicious
        self.assertTrue(all(e.is_suspicious for e in processed))
        self.assertTrue(all(e.severity == SeverityLevel.HIGH.value for e in processed))
        self.assertTrue(all(any("failed login" in a.lower() for a in e.alerts) for e in processed))

        # Exactly 1 correlated incident should be registered
        all_incidents = self.incident_manager.get_all_incidents()
        self.assertEqual(len(all_incidents), 1)
        inc = all_incidents[0]
        self.assertEqual(inc.rule_id, RULE_BRUTE_FORCE.rule_id)
        self.assertEqual(inc.user, "target_user")
        self.assertEqual(inc.source_ip, "192.168.1.100")
        self.assertEqual(inc.event_count, 3)

    def test_sliding_window_expiration_prevents_false_positive(self):
        """Attempts spaced wider than window_seconds should not accumulate to threshold."""
        events = [
            # Attempt 1 at 10:00:00
            SecurityEvent(
                timestamp="2026-10-30T10:00:00Z",
                channel="Security",
                event_id=4625,
                user="alice",
                ip_address="10.0.0.5",
                message="Logon failure",
            ),
            # Attempt 2 at 10:00:30
            SecurityEvent(
                timestamp="2026-10-30T10:00:30Z",
                channel="Security",
                event_id=4625,
                user="alice",
                ip_address="10.0.0.5",
                message="Logon failure",
            ),
            # Attempt 3 at 10:02:00 (90 seconds after attempt 2, 120s after attempt 1)
            SecurityEvent(
                timestamp="2026-10-30T10:02:00Z",
                channel="Security",
                event_id=4625,
                user="alice",
                ip_address="10.0.0.5",
                message="Logon failure",
            ),
        ]

        processed, incidents = self.detector.evaluate_batch(events)
        # Attempt 1 expired when Attempt 3 arrived; window count never reached 3
        self.assertFalse(any(e.is_suspicious for e in processed))
        self.assertEqual(len(self.incident_manager.get_all_incidents()), 0)

    def test_grouping_by_account_and_ip(self):
        """Attempts for different users or different IPs must not combine towards threshold."""
        events = [
            # 2 failures for user_A from 10.0.0.1
            SecurityEvent(
                timestamp="2026-10-30T10:00:00Z",
                event_id=4625,
                user="user_A",
                ip_address="10.0.0.1",
                message="Logon failure",
            ),
            SecurityEvent(
                timestamp="2026-10-30T10:00:10Z",
                event_id=4625,
                user="user_A",
                ip_address="10.0.0.1",
                message="Logon failure",
            ),
            # 2 failures for user_B from 10.0.0.1
            SecurityEvent(
                timestamp="2026-10-30T10:00:20Z",
                event_id=4625,
                user="user_B",
                ip_address="10.0.0.1",
                message="Logon failure",
            ),
            SecurityEvent(
                timestamp="2026-10-30T10:00:30Z",
                event_id=4625,
                user="user_B",
                ip_address="10.0.0.1",
                message="Logon failure",
            ),
            # 2 failures for user_A from 10.0.0.2
            SecurityEvent(
                timestamp="2026-10-30T10:00:40Z",
                event_id=4625,
                user="user_A",
                ip_address="10.0.0.2",
                message="Logon failure",
            ),
            SecurityEvent(
                timestamp="2026-10-30T10:00:50Z",
                event_id=4625,
                user="user_A",
                ip_address="10.0.0.2",
                message="Logon failure",
            ),
        ]

        processed, incidents = self.detector.evaluate_batch(events)
        # None of the (user, ip) pairs reached threshold 3
        self.assertFalse(any(e.is_suspicious for e in processed))
        self.assertEqual(len(self.incident_manager.get_all_incidents()), 0)

    def test_missing_account_and_ip_handled_safely(self):
        """Events with blank/None user and IP must evaluate without throwing errors."""
        event = SecurityEvent(
            timestamp="2026-10-30T10:00:00Z",
            event_id=4625,
            user="",
            ip_address=None,
            message="Failed login attempt",
        )
        proc, inc = self.detector.evaluate_event(event)
        self.assertEqual(proc.user, "unknown")
        self.assertEqual(proc.ip_address, "UNKNOWN")

    def test_service_installation_detection_7045(self):
        """Detect new service installation (Event ID 7045)."""
        event = SecurityEvent(
            timestamp="2026-10-30T10:00:00Z",
            channel="System",
            event_id=7045,
            message="New service installed: MalwareSvc (C:\\Temp\\svc.exe)",
            severity="INFO",
        )
        proc, inc = self.detector.evaluate_event(event)
        self.assertTrue(proc.is_suspicious)
        self.assertEqual(proc.severity, SeverityLevel.WARNING.value)
        self.assertIsNotNone(inc)
        self.assertEqual(inc.rule_id, RULE_NEW_SERVICE.rule_id)

    def test_audit_log_cleared_detection_1102(self):
        """Detect audit log clearing (Event ID 1102) as CRITICAL."""
        event = SecurityEvent(
            timestamp="2026-10-30T10:00:00Z",
            channel="Security",
            event_id=1102,
            user="bad_actor",
            message="The audit log was cleared",
            severity="INFO",
        )
        proc, inc = self.detector.evaluate_event(event)
        self.assertTrue(proc.is_suspicious)
        self.assertEqual(proc.severity, SeverityLevel.CRITICAL.value)
        self.assertIsNotNone(inc)
        self.assertEqual(inc.rule_id, RULE_AUDIT_LOG_CLEARED.rule_id)

    def test_account_creation_and_privilege_changes(self):
        """Detect account creation (4720) and group changes (4728)."""
        create_event = SecurityEvent(
            timestamp="2026-10-30T10:00:00Z",
            event_id=4720,
            user="backdoor_user",
            message="User account created: backdoor_user",
        )
        proc1, inc1 = self.detector.evaluate_event(create_event)
        self.assertTrue(proc1.is_suspicious)
        self.assertEqual(inc1.rule_id, RULE_ACCOUNT_CREATED.rule_id)

        group_event = SecurityEvent(
            timestamp="2026-10-30T10:01:00Z",
            event_id=4728,
            user="backdoor_user",
            message="Member backdoor_user added to Administrators group",
        )
        proc2, inc2 = self.detector.evaluate_event(group_event)
        self.assertTrue(proc2.is_suspicious)
        self.assertEqual(inc2.rule_id, RULE_PRIVILEGE_MODIFIED.rule_id)

    def test_successful_logon_is_contextual_not_threat(self):
        """Successful logon (4624) is recorded contextually and never flagged as a threat."""
        event = SecurityEvent(
            timestamp="2026-10-30T10:00:00Z",
            event_id=4624,
            user="legit_user",
            ip_address="192.168.1.10",
            message="Successful logon for user 'legit_user'",
            severity="INFO",
        )
        proc, inc = self.detector.evaluate_event(event)
        self.assertFalse(proc.is_suspicious)
        self.assertEqual(len(proc.alerts), 0)
        self.assertIsNone(inc)

    def test_mixed_live_and_simulated_sources_preserved(self):
        """Ensure source_type is preserved through detection evaluation."""
        e1 = SecurityEvent(
            timestamp="2026-10-30T10:00:00Z",
            source_type=SourceType.LIVE_WINDOWS,
            message="Test event 1",
        )
        e2 = SecurityEvent(
            timestamp="2026-10-30T10:00:05Z",
            source_type=SourceType.SIMULATED_REPLAY,
            message="Test event 2",
        )
        proc1, _ = self.detector.evaluate_event(e1)
        proc2, _ = self.detector.evaluate_event(e2)
        self.assertEqual(proc1.source_type, SourceType.LIVE_WINDOWS)
        self.assertEqual(proc2.source_type, SourceType.SIMULATED_REPLAY)

    def test_malformed_incomplete_event_data_resilience(self):
        """Detector must not crash when encountering malformed or incomplete dict events."""
        malformed_dict = {
            "timestamp": "invalid-timestamp-string-not-iso",
            "message": None,
            "user": None,
            "ip": 12345,  # Non-string IP
        }
        proc, inc = self.detector.evaluate_event(malformed_dict)
        self.assertIsInstance(proc, dict)
        self.assertFalse(proc["is_suspicious"])


class IncidentManagerTests(unittest.TestCase):
    """Test incident tracking, correlation, transitions, and persistence."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_inc_"))
        self.storage_file = self.test_dir / "incidents.json"
        self.manager = IncidentManager(storage_path=self.storage_file)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_duplicate_incident_prevention_and_correlation(self):
        """Repeated detections for the same active incident correlate rather than duplicate."""
        event1 = SecurityEvent(
            timestamp="2026-10-30T10:00:00Z",
            channel="Security",
            record_id=1,
            user="hacker",
            ip_address="192.168.1.55",
            message="Failed login attempt",
        )
        inc1 = self.manager.create_or_correlate(
            rule=RULE_BRUTE_FORCE,
            event=event1,
            event_count=3,
        )

        self.assertEqual(len(self.manager.get_all_incidents()), 1)
        self.assertEqual(inc1.event_count, 3)

        # Subsequent failed attempt for the same open incident
        event2 = SecurityEvent(
            timestamp="2026-10-30T10:00:15Z",
            channel="Security",
            record_id=2,
            user="hacker",
            ip_address="192.168.1.55",
            message="Another failed login",
        )
        inc2 = self.manager.create_or_correlate(
            rule=RULE_BRUTE_FORCE,
            event=event2,
            event_count=4,
        )

        # Must correlate to the exact same incident object
        self.assertEqual(inc1.incident_id, inc2.incident_id)
        self.assertEqual(len(self.manager.get_all_incidents()), 1)
        self.assertEqual(inc2.event_count, 4)
        self.assertEqual(inc2.timestamp_last, "2026-10-30T10:00:15Z")

    def test_incident_status_transitions(self):
        """Verify lifecycle status transitions (OPEN -> INVESTIGATING -> RESOLVED)."""
        event = SecurityEvent(
            timestamp="2026-10-30T10:00:00Z",
            user="victim",
            message="Unauthorized access",
        )
        inc = self.manager.create_or_correlate(rule=RULE_BRUTE_FORCE, event=event)
        self.assertEqual(inc.status, IncidentStatus.OPEN.value)

        # Transition to INVESTIGATING
        updated = self.manager.update_status(inc.incident_id, IncidentStatus.INVESTIGATING)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, IncidentStatus.INVESTIGATING.value)

        # Transition to RESOLVED
        resolved = self.manager.update_status(inc.incident_id, IncidentStatus.RESOLVED)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.status, IncidentStatus.RESOLVED.value)
        self.assertEqual(len(self.manager.get_open_incidents()), 0)

        # Invalid status must raise ValueError
        with self.assertRaises(ValueError):
            self.manager.update_status(inc.incident_id, "INVALID_STATUS")

    def test_incident_persistence_and_restart_recovery(self):
        """Verify that incidents persist across manager restarts."""
        event = SecurityEvent(
            timestamp="2026-10-30T10:00:00Z",
            event_id=1102,
            user="admin",
            message="Audit log cleared",
        )
        created_inc = self.manager.create_or_correlate(
            rule=RULE_AUDIT_LOG_CLEARED,
            event=event,
        )

        # Simulate restart: create a new IncidentManager pointing to the same storage
        restarted_manager = IncidentManager(storage_path=self.storage_file)
        loaded_incidents = restarted_manager.get_all_incidents()

        self.assertEqual(len(loaded_incidents), 1)
        self.assertEqual(loaded_incidents[0].incident_id, created_inc.incident_id)
        self.assertEqual(loaded_incidents[0].rule_id, RULE_AUDIT_LOG_CLEARED.rule_id)
        self.assertEqual(loaded_incidents[0].severity, SeverityLevel.CRITICAL.value)


if __name__ == "__main__":
    unittest.main()
