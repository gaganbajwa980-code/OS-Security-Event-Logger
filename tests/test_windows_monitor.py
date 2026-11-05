"""
Unit tests for monitor/windows_monitor.py.
Uses mocked XML fixtures and simulated Windows Event Log responses to verify:
- System and Application event parsing
- Security event parsing and permission denial handling
- Handling of malformed XML and missing fields
- Event deduplication and checkpoint recovery
All tests run in any environment without requiring Windows Administrator privileges.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from monitor.event_models import SeverityLevel, SourceType
from monitor.windows_monitor import (
    WindowsEventCollector,
    parse_windows_event_xml,
)

# ----------------------------------------------------------------------
# Sample XML Fixtures
# ----------------------------------------------------------------------

FIXTURE_FAILED_LOGON_4625 = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-10-30T10:15:30.123456Z"/>
    <EventRecordID>100452</EventRecordID>
    <Channel>Security</Channel>
    <Computer>SEC-WORKSTATION</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">bad_actor</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="SubStatus">0xc000006a</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">192.168.1.150</Data>
  </EventData>
</Event>
"""

FIXTURE_SUCCESS_LOGON_4624 = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-10-30T10:20:00.000000Z"/>
    <EventRecordID>100453</EventRecordID>
    <Channel>Security</Channel>
    <Computer>SEC-WORKSTATION</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="LogonType">2</Data>
    <Data Name="IpAddress">127.0.0.1</Data>
  </EventData>
</Event>
"""

FIXTURE_SERVICE_INSTALLED_7045 = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager"/>
    <EventID>7045</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-10-30T10:25:00.000000Z"/>
    <EventRecordID>54210</EventRecordID>
    <Channel>System</Channel>
    <Computer>SERVER-01</Computer>
  </System>
  <EventData>
    <Data Name="ServiceName">SuspiciousService</Data>
    <Data Name="ImagePath">C:\\Windows\\Temp\\backdoor.exe</Data>
    <Data Name="ServiceType">user mode service</Data>
    <Data Name="AccountName">LocalSystem</Data>
  </EventData>
</Event>
"""

FIXTURE_APPLICATION_ERROR_1000 = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Application Error"/>
    <EventID>1000</EventID>
    <Level>2</Level>
    <TimeCreated SystemTime="2026-10-30T10:30:00.000000Z"/>
    <EventRecordID>32015</EventRecordID>
    <Channel>Application</Channel>
    <Computer>SERVER-01</Computer>
  </System>
  <EventData>
    <Data>explorer.exe</Data>
    <Data>10.0.22621.1</Data>
  </EventData>
</Event>
"""

FIXTURE_USER_CREATED_4720 = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4720</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-10-30T10:35:00.000000Z"/>
    <EventRecordID>100460</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DC-01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">contractor_bob</Data>
    <Data Name="SubjectUserName">admin_jane</Data>
  </EventData>
</Event>
"""

FIXTURE_AUDIT_LOG_CLEARED_1102 = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>1102</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-10-30T10:40:00.000000Z"/>
    <EventRecordID>100470</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DC-01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">intruder</Data>
  </EventData>
</Event>
"""


class WindowsEventXmlParsingTests(unittest.TestCase):
    """Test parsing and normalizing diverse Windows Event XML payloads."""

    def test_parse_failed_logon_4625(self):
        event = parse_windows_event_xml(FIXTURE_FAILED_LOGON_4625)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_id, 4625)
        self.assertEqual(event.record_id, 100452)
        self.assertEqual(event.channel, "Security")
        self.assertEqual(event.user, "bad_actor")
        self.assertEqual(event.ip_address, "192.168.1.150")
        self.assertEqual(event.source_type, SourceType.LIVE_WINDOWS)
        self.assertIn("Logon failure", event.message)
        self.assertEqual(event.raw_data.get("Status"), "0xc000006d")

    def test_parse_successful_logon_4624(self):
        event = parse_windows_event_xml(FIXTURE_SUCCESS_LOGON_4624)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_id, 4624)
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.ip_address, "LOCAL_LOOPBACK")
        self.assertIn("Successful logon", event.message)

    def test_parse_system_service_installed_7045(self):
        event = parse_windows_event_xml(FIXTURE_SERVICE_INSTALLED_7045)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_id, 7045)
        self.assertEqual(event.channel, "System")
        self.assertEqual(event.record_id, 54210)
        self.assertEqual(event.user, "LocalSystem")
        self.assertIn("SuspiciousService", event.message)
        self.assertIn("backdoor.exe", event.message)

    def test_parse_application_error_1000(self):
        event = parse_windows_event_xml(FIXTURE_APPLICATION_ERROR_1000)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_id, 1000)
        self.assertEqual(event.channel, "Application")
        self.assertEqual(event.severity, SeverityLevel.ERROR.value)
        self.assertEqual(event.raw_data.get("param_0"), "explorer.exe")

    def test_parse_user_created_4720(self):
        event = parse_windows_event_xml(FIXTURE_USER_CREATED_4720)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_id, 4720)
        self.assertEqual(event.user, "contractor_bob")
        self.assertIn("admin_jane", event.message)

    def test_parse_audit_log_cleared_1102(self):
        event = parse_windows_event_xml(FIXTURE_AUDIT_LOG_CLEARED_1102)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_id, 1102)
        self.assertEqual(event.severity, SeverityLevel.CRITICAL.value)
        self.assertIn("audit log was cleared", event.message)

    def test_malformed_xml_returns_none(self):
        malformed = "<Event><System><EventID>broken<unclosed"
        event = parse_windows_event_xml(malformed)
        self.assertIsNone(event)

    def test_empty_or_whitespace_xml_returns_none(self):
        self.assertIsNone(parse_windows_event_xml(""))
        self.assertIsNone(parse_windows_event_xml("   "))

    def test_missing_system_header_returns_none(self):
        no_system = "<Event><EventData><Data>value</Data></EventData></Event>"
        self.assertIsNone(parse_windows_event_xml(no_system))

    def test_missing_fields_handled_gracefully(self):
        minimal_xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="TestProvider"/>
          </System>
        </Event>
        """
        event = parse_windows_event_xml(minimal_xml)
        self.assertIsNotNone(event)
        self.assertIsNone(event.event_id)
        self.assertEqual(event.provider, "TestProvider")
        self.assertEqual(event.user, "unknown")
        self.assertEqual(event.ip_address, "UNKNOWN")
        self.assertTrue(bool(event.timestamp))

    def test_different_field_names_handled(self):
        xml_alternate = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="CustomAuth"/>
            <EventID>9001</EventID>
            <EventRecordID>1234</EventRecordID>
          </System>
          <EventData>
            <Data Name="AccountName">custom_user</Data>
            <Data Name="ClientAddress">10.20.30.40</Data>
          </EventData>
        </Event>
        """
        event = parse_windows_event_xml(xml_alternate)
        self.assertIsNotNone(event)
        self.assertEqual(event.user, "custom_user")
        self.assertEqual(event.ip_address, "10.20.30.40")


class WindowsEventCollectorTests(unittest.TestCase):
    """Test the WindowsEventCollector class, deduplication, and checkpoint recovery."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="test_collector_"))
        self.checkpoint_path = self.test_dir / ".checkpoint.json"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_security_access_denied_handled_gracefully(self):
        collector = WindowsEventCollector(
            channels=["Security"],
            checkpoint_path=self.checkpoint_path,
        )
        # Force channel status to ACCESS_DENIED
        collector.channel_status["Security"] = {
            "channel": "Security",
            "accessible": False,
            "status": "ACCESS_DENIED",
        }

        events = collector.poll_channel("Security")
        self.assertEqual(events, [])

    @patch("win32evtlog.EvtRender")
    @patch("win32evtlog.EvtNext")
    @patch("win32evtlog.EvtQuery")
    def test_collector_processes_system_events_and_updates_checkpoint(
        self, mock_query, mock_next, mock_render
    ):
        mock_query.return_value = 999
        mock_next.side_effect = [
            [101],   # Batch 1 returns 1 record handle
            [],      # Batch 2 returns empty, ending the loop
        ]
        mock_render.return_value = FIXTURE_SERVICE_INSTALLED_7045

        collector = WindowsEventCollector(
            channels=["System"],
            checkpoint_path=self.checkpoint_path,
        )
        # Mock channel as accessible
        collector.channel_status["System"] = {
            "channel": "System",
            "accessible": True,
            "status": "ONLINE",
        }

        events = collector.poll_channel("System")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_id, 7045)
        self.assertEqual(events[0].record_id, 54210)

        # Verify checkpoint was updated and persisted to disk
        self.assertEqual(collector.checkpoints.get("System"), 54210)
        self.assertTrue(self.checkpoint_path.exists())

    @patch("win32evtlog.EvtRender")
    @patch("win32evtlog.EvtNext")
    @patch("win32evtlog.EvtQuery")
    def test_duplicate_events_prevented(self, mock_query, mock_next, mock_render):
        mock_query.return_value = 999
        # Return two record handles representing the exact same record
        mock_next.side_effect = [
            [101, 102],
            [],
        ]
        mock_render.return_value = FIXTURE_SERVICE_INSTALLED_7045

        collector = WindowsEventCollector(
            channels=["System"],
            checkpoint_path=self.checkpoint_path,
        )
        collector.channel_status["System"] = {
            "channel": "System",
            "accessible": True,
            "status": "ONLINE",
        }

        events = collector.poll_channel("System")
        # Second event must be discarded by deduplication
        self.assertEqual(len(events), 1)

    @patch("win32evtlog.EvtRender")
    @patch("win32evtlog.EvtNext")
    @patch("win32evtlog.EvtQuery")
    def test_checkpoint_recovery_across_restarts(
        self, mock_query, mock_next, mock_render
    ):
        # 1. First run processes record 54210
        mock_query.return_value = 999
        mock_next.side_effect = [[101], []]
        mock_render.return_value = FIXTURE_SERVICE_INSTALLED_7045

        collector1 = WindowsEventCollector(
            channels=["System"],
            checkpoint_path=self.checkpoint_path,
        )
        collector1.channel_status["System"] = {"accessible": True, "status": "ONLINE"}
        events1 = collector1.poll_channel("System")
        self.assertEqual(len(events1), 1)

        # 2. Simulate application restart: instantiate collector2 with the same checkpoint file
        mock_query.reset_mock()
        mock_next.reset_mock()
        mock_render.reset_mock()

        # The new event has a newer record ID 54211
        newer_xml = FIXTURE_SERVICE_INSTALLED_7045.replace("54210", "54211")
        mock_next.side_effect = [[201], []]
        mock_render.return_value = newer_xml

        collector2 = WindowsEventCollector(
            channels=["System"],
            checkpoint_path=self.checkpoint_path,
        )
        collector2.channel_status["System"] = {"accessible": True, "status": "ONLINE"}

        # Verify collector2 started with the persisted checkpoint
        self.assertEqual(collector2.checkpoints.get("System"), 54210)

        events2 = collector2.poll_channel("System")
        self.assertEqual(len(events2), 1)
        self.assertEqual(events2[0].record_id, 54211)

        # Verify collector query used the checkpoint filter EventRecordID > 54210
        # Note: EvtQuery is called once during __init__ for accessibility check, and once for poll_channel
        self.assertEqual(mock_query.call_count, 2)
        args, kwargs = mock_query.call_args
        # The second call is the polling query with args: ('System', flags, query)
        self.assertIn("EventRecordID > 54210", args[2])


if __name__ == "__main__":
    unittest.main()
