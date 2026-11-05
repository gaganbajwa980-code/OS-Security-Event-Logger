"""
Unit tests for Phase 1 foundations, models, atomic persistence, and diagnostics.
Uses mocked Windows API and subprocess responses to ensure tests run reliably
across all environments without requiring administrator privileges or active OS events.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from monitor.diagnostics import (
    check_all_channels,
    check_audit_policy,
    check_channel_accessibility,
    check_pywin32_compatibility,
    get_system_diagnostics,
)
from monitor.event_models import (
    Incident,
    SecurityEvent,
    SeverityLevel,
    SourceType,
    load_checkpoint,
    load_incidents,
    load_json_safe,
    normalize_ip_address,
    save_checkpoint_atomically,
    save_incidents_atomically,
    save_json_atomically,
)


class EventModelsTests(unittest.TestCase):
    """Test the unified SecurityEvent and Incident data models."""

    def test_security_event_defaults_and_serialization(self):
        event = SecurityEvent(
            timestamp="2026-10-30T10:00:00",
            source_type=SourceType.LIVE_WINDOWS,
            channel="Security",
            event_id=4625,
            record_id=101,
            user="target_user",
            computer="WORKSTATION1",
            ip_address="192.168.1.50",
            message="An account failed to log on",
            severity=SeverityLevel.HIGH.value,
        )

        self.assertEqual(event.source_type, SourceType.LIVE_WINDOWS)
        self.assertEqual(event.event_id, 4625)
        self.assertEqual(event.ip_address, "192.168.1.50")

        # Test dictionary conversion
        data = event.to_dict()
        self.assertEqual(data["source_type"], "LIVE_WINDOWS")
        self.assertEqual(data["event_id"], 4625)

        # Test round-trip reconstruction
        reconstructed = SecurityEvent.from_dict(data)
        self.assertEqual(reconstructed.source_type, SourceType.LIVE_WINDOWS)
        self.assertEqual(reconstructed.event_id, 4625)
        self.assertEqual(reconstructed.user, "target_user")

    def test_legacy_dict_compatibility(self):
        """Ensure to_legacy_dict output matches legacy dictionary consumers."""
        event = SecurityEvent(
            timestamp="2026-10-30T10:00:00",
            source_type=SourceType.STATIC_SAMPLE_FILE,
            channel="Sample",
            message="Test message",
            user="admin",
            severity="WARNING",
        )
        legacy = event.to_legacy_dict()
        self.assertIn("source", legacy)
        self.assertIn("user", legacy)
        self.assertIn("severity", legacy)
        self.assertIn("message", legacy)
        self.assertEqual(legacy["source"], "Sample (STATIC_SAMPLE_FILE)")

    def test_ip_normalization(self):
        """Test normalization of missing, blank, loopback, and valid IP strings."""
        self.assertEqual(normalize_ip_address(None), "UNKNOWN")
        self.assertEqual(normalize_ip_address(""), "UNKNOWN")
        self.assertEqual(normalize_ip_address("  -  "), "UNKNOWN")
        self.assertEqual(normalize_ip_address("0.0.0.0"), "UNKNOWN")
        self.assertEqual(normalize_ip_address("127.0.0.1"), "LOCAL_LOOPBACK")
        self.assertEqual(normalize_ip_address("::1"), "LOCAL_LOOPBACK")
        self.assertEqual(normalize_ip_address("10.0.0.15"), "10.0.0.15")

    def test_incident_model_and_serialization(self):
        incident = Incident(
            incident_id="INC-20261030-001",
            timestamp_first="2026-10-30T09:00:00",
            timestamp_last="2026-10-30T09:00:45",
            rule_id="RULE-BRUTEFORCE",
            rule_name="Repeated Failed Logins",
            severity="HIGH",
            user="admin",
            source_ip="192.168.1.100",
            description="3 failed login attempts within 45s",
            mitre_attack_id="T1110",
            event_ids=[4625],
            event_count=3,
        )
        d = incident.to_dict()
        self.assertEqual(d["incident_id"], "INC-20261030-001")
        self.assertEqual(d["mitre_attack_id"], "T1110")

        reconstructed = Incident.from_dict(d)
        self.assertEqual(reconstructed.incident_id, incident.incident_id)
        self.assertEqual(reconstructed.event_count, 3)


class PersistenceAndCheckpointTests(unittest.TestCase):
    """Test atomic persistence, checkpoint saving, and recovery."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_logger_persist_"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_atomic_file_write_and_recovery(self):
        target = self.test_dir / "test_data.json"
        data = {"status": "ok", "count": 42}

        save_json_atomically(data, target)
        self.assertTrue(target.exists())

        loaded = load_json_safe(target)
        self.assertEqual(loaded, data)

    def test_load_corrupted_file_returns_default(self):
        target = self.test_dir / "corrupted.json"
        target.write_text("NOT_VALID_JSON{::: broken", encoding="utf-8")

        result = load_json_safe(target, default={"fallback": True})
        self.assertEqual(result, {"fallback": True})

    def test_checkpoint_save_and_load(self):
        checkpoint_file = self.test_dir / ".checkpoint.json"
        checkpoints = {"Security": 15420, "System": 8921}

        save_checkpoint_atomically(checkpoints, checkpoint_file)
        loaded = load_checkpoint(checkpoint_file)

        self.assertEqual(loaded["Security"], 15420)
        self.assertEqual(loaded["System"], 8921)

    def test_incident_history_persistence(self):
        incidents_file = self.test_dir / "incidents.json"
        incidents = [
            Incident(
                incident_id="INC-1",
                timestamp_first="2026-10-30T10:00:00",
                timestamp_last="2026-10-30T10:00:30",
                rule_id="R1",
                rule_name="Rule 1",
                severity="HIGH",
                user="alice",
                source_ip="10.0.0.5",
                description="Test incident",
            )
        ]

        save_incidents_atomically(incidents, incidents_file)
        loaded = load_incidents(incidents_file)

        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].incident_id, "INC-1")
        self.assertEqual(loaded[0].user, "alice")


class MockedDiagnosticsTests(unittest.TestCase):
    """Test diagnostics with mocked Windows Event Log API and subprocesses."""

    def test_pywin32_compatibility_structure(self):
        compat = check_pywin32_compatibility()
        self.assertIn("is_compatible", compat)
        self.assertIn("modules_loaded", compat)

    @patch("win32evtlog.EvtQuery")
    def test_channel_accessibility_success(self, mock_evt_query):
        mock_evt_query.return_value = 12345  # Dummy handle
        diag = check_channel_accessibility("Security")

        self.assertTrue(diag["accessible"])
        self.assertEqual(diag["status"], "ONLINE")
        self.assertIn("Security", diag["details"])

    @patch("win32evtlog.OpenEventLog")
    @patch("win32evtlog.EvtQuery")
    def test_channel_accessibility_access_denied(self, mock_evt_query, mock_open_event_log):
        # Create an exception mimicking WinError 5
        err = OSError("Access is denied.")
        err.winerror = 5
        mock_evt_query.side_effect = err
        mock_open_event_log.side_effect = err

        diag = check_channel_accessibility("Security")
        self.assertFalse(diag["accessible"])
        self.assertEqual(diag["status"], "ACCESS_DENIED")
        self.assertEqual(diag["error_code"], 5)
        self.assertIn("Event Log Readers", diag["details"])

    @patch("subprocess.run")
    def test_audit_policy_active(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="System audit policy\r\nLogon                                     Success and Failure\r\n",
            stderr="",
        )
        diag = check_audit_policy("Logon")

        self.assertTrue(diag["accessible"])
        self.assertTrue(diag["auditing_enabled"])
        self.assertEqual(diag["status"], "AUDIT_ACTIVE")
        self.assertEqual(diag["setting"], "Success and Failure")

    @patch("subprocess.run")
    def test_audit_policy_access_denied(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error 0x00000005 occurred:\r\nAccess is denied.\r\n",
        )
        diag = check_audit_policy("Logon")

        self.assertFalse(diag["accessible"])
        self.assertFalse(diag["auditing_enabled"])
        self.assertEqual(diag["status"], "AUDIT_STATUS_UNVERIFIED")
        self.assertIn("Access Denied", diag["details"])

    @patch("subprocess.run")
    def test_audit_policy_disabled(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="System audit policy\r\nLogon                                     No Auditing\r\n",
            stderr="",
        )
        diag = check_audit_policy("Logon")

        self.assertTrue(diag["accessible"])
        self.assertFalse(diag["auditing_enabled"])
        self.assertEqual(diag["status"], "AUDIT_DISABLED")
        self.assertIn("No Auditing", diag["details"])

    def test_get_system_diagnostics_structure(self):
        system_diag = get_system_diagnostics()
        self.assertIn("platform", system_diag)
        self.assertIn("pywin32", system_diag)
        self.assertIn("channels", system_diag)
        self.assertIn("audit_policy", system_diag)
        self.assertIn("readiness", system_diag)


if __name__ == "__main__":
    unittest.main()
