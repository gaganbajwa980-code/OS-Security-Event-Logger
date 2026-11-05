"""
Windows Event Log collection and normalization engine.
Provides read-only incremental collection from Windows Event Log channels (System,
Application, Security) using pywin32, XML normalization into SecurityEvent models,
deduplication, and persistent checkpoint tracking.
"""

from __future__ import annotations

import logging
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from monitor.diagnostics import check_channel_accessibility
from monitor.event_models import (
    SecurityEvent,
    SeverityLevel,
    SourceType,
    load_checkpoint,
    normalize_ip_address,
    save_checkpoint_atomically,
)

logger = logging.getLogger(__name__)

# Windows Event schema namespace
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _strip_ns(tag: str) -> str:
    """Strip XML namespace prefix from tag if present."""
    return tag.split("}")[-1] if "}" in tag else tag


def parse_windows_event_xml(
    xml_content: str,
    default_channel: str = "System"
) -> Optional[SecurityEvent]:
    """
    Parse a Windows Event XML string into a structured SecurityEvent model.
    Robustly handles namespaces, missing fields, positional vs named data,
    and malformed content without raising exceptions.
    """
    if not xml_content or not isinstance(xml_content, str) or not xml_content.strip():
        return None

    try:
        root = ET.fromstring(xml_content)
    except (ET.ParseError, ValueError) as err:
        logger.warning(f"Failed to parse Windows Event XML: {err}")
        return None

    # Locate System and EventData/UserData sections
    system_elem: Optional[ET.Element] = None
    event_data_elem: Optional[ET.Element] = None

    for child in root:
        local_tag = _strip_ns(child.tag)
        if local_tag == "System":
            system_elem = child
        elif local_tag in ("EventData", "UserData"):
            event_data_elem = child

    if system_elem is None:
        logger.warning("Event XML is missing <System> header; skipping.")
        return None

    # -------------------------------------------------------------
    # 1. Extract System metadata
    # -------------------------------------------------------------
    event_id: Optional[int] = None
    record_id: Optional[int] = None
    channel: str = default_channel
    provider: str = "Windows"
    computer: str = "localhost"
    timestamp: str = ""
    level_num: Optional[int] = None
    user_sid: Optional[str] = None

    for elem in system_elem:
        tag = _strip_ns(elem.tag)
        text = (elem.text or "").strip()

        if tag == "EventID":
            try:
                event_id = int(text)
            except (ValueError, TypeError):
                event_id = None
        elif tag == "EventRecordID":
            try:
                record_id = int(text)
            except (ValueError, TypeError):
                record_id = None
        elif tag == "Channel" and text:
            channel = text
        elif tag == "Computer" and text:
            computer = text
        elif tag == "Provider":
            provider = elem.attrib.get("Name", text or "Windows")
        elif tag == "TimeCreated":
            timestamp = elem.attrib.get("SystemTime", text)
        elif tag == "Level":
            try:
                level_num = int(text)
            except (ValueError, TypeError):
                level_num = None
        elif tag == "Security":
            user_sid = elem.attrib.get("UserID", text or None)

    # Fallback for timestamp if missing or malformed
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    # -------------------------------------------------------------
    # 2. Extract EventData / UserData key-values
    # -------------------------------------------------------------
    event_data: dict[str, Any] = {}
    if event_data_elem is not None:
        pos_idx = 0
        for data_elem in event_data_elem.iter():
            if data_elem is event_data_elem:
                continue
            tag = _strip_ns(data_elem.tag)
            text_val = (data_elem.text or "").strip()
            name_attr = data_elem.attrib.get("Name")

            if name_attr:
                event_data[name_attr] = text_val
            elif tag == "Data":
                event_data[f"param_{pos_idx}"] = text_val
                pos_idx += 1
            else:
                event_data[tag] = text_val

    # -------------------------------------------------------------
    # 3. Resolve user identity
    # -------------------------------------------------------------
    user = "unknown"
    # Prioritized lookup of common user fields
    for key in (
        "TargetUserName",
        "SubjectUserName",
        "AccountName",
        "TargetUserSid",
        "SubjectUserSid",
        "User",
    ):
        val = event_data.get(key)
        if val and isinstance(val, str) and val.strip() and val.strip() != "-":
            domain = event_data.get("TargetDomainName") or event_data.get("SubjectDomainName")
            if domain and domain.strip() not in ("-", "", "NT AUTHORITY", "WORKGROUP"):
                user = f"{domain.strip()}\\{val.strip()}"
            else:
                user = val.strip()
            break

    if user == "unknown" and user_sid and user_sid not in ("S-1-5-18", "S-1-0-0"):
        user = user_sid

    # -------------------------------------------------------------
    # 4. Resolve IP address
    # -------------------------------------------------------------
    raw_ip = (
        event_data.get("IpAddress")
        or event_data.get("ClientAddress")
        or event_data.get("SourceAddress")
        or event_data.get("NetworkAddress")
    )
    ip_address = normalize_ip_address(raw_ip)

    # -------------------------------------------------------------
    # 5. Resolve severity
    # -------------------------------------------------------------
    # Windows Level: 1 = Critical, 2 = Error, 3 = Warning, 4 = Information, 0 = LogAlways
    if level_num == 1:
        severity = SeverityLevel.CRITICAL.value
    elif level_num == 2:
        severity = SeverityLevel.ERROR.value
    elif level_num == 3:
        severity = SeverityLevel.WARNING.value
    elif level_num == 4:
        severity = SeverityLevel.INFO.value
    else:
        # Contextual default based on Event ID
        if event_id in (4625, 4726):
            severity = SeverityLevel.WARNING.value
        elif event_id == 1102:
            severity = SeverityLevel.CRITICAL.value
        elif event_id == 7045:
            severity = SeverityLevel.INFO.value
        else:
            severity = SeverityLevel.INFO.value

    # -------------------------------------------------------------
    # 6. Compose human-readable message
    # -------------------------------------------------------------
    message = _generate_event_message(
        event_id=event_id,
        channel=channel,
        provider=provider,
        user=user,
        ip_address=ip_address,
        event_data=event_data,
    )

    return SecurityEvent(
        timestamp=timestamp,
        source_type=SourceType.LIVE_WINDOWS,
        channel=channel,
        event_id=event_id,
        record_id=record_id,
        provider=provider,
        severity=severity,
        event_type="windows_event",
        user=user,
        computer=computer,
        ip_address=ip_address,
        message=message,
        is_suspicious=False,
        alerts=[],
        raw_data=event_data,
    )


def _generate_event_message(
    event_id: Optional[int],
    channel: str,
    provider: str,
    user: str,
    ip_address: str,
    event_data: dict[str, Any],
) -> str:
    """Generate a clean, descriptive summary message for known security events."""
    if event_id == 4625:
        logon_type = event_data.get("LogonType", "unknown")
        status = event_data.get("Status", "N/A")
        sub_status = event_data.get("SubStatus", "N/A")
        return (
            f"Logon failure for user '{user}' from IP {ip_address} "
            f"(LogonType: {logon_type}, Status: {status}, SubStatus: {sub_status})"
        )

    if event_id == 4624:
        logon_type = event_data.get("LogonType", "unknown")
        return f"Successful logon for user '{user}' from IP {ip_address} (LogonType: {logon_type})"

    if event_id == 4720:
        creator = event_data.get("SubjectUserName", "SYSTEM")
        return f"User account created: '{user}' by '{creator}'"

    if event_id == 4722:
        return f"User account enabled: '{user}'"

    if event_id == 4726:
        remover = event_data.get("SubjectUserName", "SYSTEM")
        return f"User account deleted: '{user}' by '{remover}'"

    if event_id in (4728, 4732, 4756):
        group = event_data.get("TargetUserName", "SecurityGroup")
        member = event_data.get("MemberName", user)
        return f"Member '{member}' added to security group '{group}'"

    if event_id == 7045:
        service_name = event_data.get("ServiceName", "unknown")
        image_path = event_data.get("ImagePath", "unknown")
        account = event_data.get("AccountName", "LocalSystem")
        return f"New service installed: '{service_name}' ({image_path}) running as '{account}'"

    if event_id == 1102:
        cleared_by = event_data.get("SubjectUserName", user)
        return f"Security audit log was cleared by user '{cleared_by}'"

    if event_id == 1000:
        app_name = event_data.get("param_0") or event_data.get("AppName") or "Application"
        return f"Application error encountered by '{app_name}'"

    # Default descriptive fallback
    first_vals = [str(v) for v in event_data.values() if v and len(str(v)) < 60]
    extra_summary = f" - {', '.join(first_vals[:2])}" if first_vals else ""
    return f"[{channel}] Event {event_id or 'Unknown'} from {provider}{extra_summary}"


# ----------------------------------------------------------------------
# Windows Event Collector
# ----------------------------------------------------------------------

class WindowsEventCollector:
    """
    Incremental collector for Windows Event Log channels.
    Provides non-blocking delta collection, persistent checkpoints,
    deduplication, and robust channel permission handling.
    """

    def __init__(
        self,
        channels: Optional[list[str]] = None,
        checkpoint_path: Optional[Union[str, Path]] = None,
        batch_size: int = 100,
        max_seen_cache: int = 10000,
    ) -> None:
        self.channels: list[str] = channels or ["System", "Application"]
        self.checkpoint_path: Path = (
            Path(checkpoint_path) if checkpoint_path else Path("data/.checkpoint.json")
        )
        self.batch_size: int = batch_size
        self.max_seen_cache: int = max_seen_cache

        # Checkpoints track the highest processed record_id per channel
        self.checkpoints: dict[str, int] = load_checkpoint(self.checkpoint_path)

        # In-memory deduplication set: stores (channel, record_id)
        self.seen_records: set[tuple[str, int]] = set()

        # Cache of channel accessibility diagnostic results
        self.channel_status: dict[str, dict[str, Any]] = {}
        self.refresh_channel_status()

    def refresh_channel_status(self) -> dict[str, dict[str, Any]]:
        """Probe and record accessibility status for each monitored channel."""
        self.channel_status = {
            ch: check_channel_accessibility(ch) for ch in self.channels
        }
        return self.channel_status

    def is_channel_accessible(self, channel: str) -> bool:
        """Check if a specific channel is accessible."""
        status = self.channel_status.get(channel)
        if not status:
            status = check_channel_accessibility(channel)
            self.channel_status[channel] = status
        return status.get("accessible", False)

    def poll_channel(
        self,
        channel: str,
        max_events: Optional[int] = None
    ) -> list[SecurityEvent]:
        """
        Poll a single Windows Event Log channel incrementally.
        Uses recorded checkpoints to query only newly created events.
        """
        if sys.platform != "win32":
            logger.debug(f"Skipping channel '{channel}': not running on Windows.")
            return []

        if not self.is_channel_accessible(channel):
            logger.debug(f"Skipping channel '{channel}': channel not accessible.")
            return []

        try:
            import win32evtlog
        except ImportError:
            logger.warning("pywin32 (win32evtlog) is not available.")
            return []

        last_record_id = self.checkpoints.get(channel, 0)
        target_limit = max_events or self.batch_size

        # Formulate query:
        # If we have a checkpoint, collect forward strictly newer records.
        # If this is the initial run (checkpoint == 0), read the most recent batch in reverse.
        if last_record_id > 0:
            query = f"*[System[EventRecordID > {last_record_id}]]"
            query_flags = (
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
            )
        else:
            query = "*"
            query_flags = (
                win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
            )

        events: list[SecurityEvent] = []
        highest_record = last_record_id

        try:
            handle = win32evtlog.EvtQuery(channel, query_flags, query)
        except Exception as query_exc:
            logger.warning(f"EvtQuery failed on channel '{channel}': {query_exc}")
            return []

        try:
            while len(events) < target_limit:
                batch_limit = min(self.batch_size, target_limit - len(events))
                records = win32evtlog.EvtNext(handle, batch_limit)
                if not records:
                    break

                for rec in records:
                    try:
                        xml_data = win32evtlog.EvtRender(rec, win32evtlog.EvtRenderEventXml)
                        event = parse_windows_event_xml(xml_data, default_channel=channel)
                        if not event:
                            continue

                        # Deduplication check
                        rec_id = event.record_id
                        if rec_id is not None:
                            dedup_key = (channel, rec_id)
                            if dedup_key in self.seen_records:
                                continue

                            self.seen_records.add(dedup_key)
                            if len(self.seen_records) > self.max_seen_cache:
                                # Maintain bounded deduplication cache
                                self.seen_records.pop()

                            if rec_id > highest_record:
                                highest_record = rec_id

                        events.append(event)
                    except Exception as render_exc:
                        logger.warning(f"Error rendering event record on '{channel}': {render_exc}")

        except Exception as iter_exc:
            logger.warning(f"Error iterating records on channel '{channel}': {iter_exc}")

        # Update checkpoint if newer records were read
        if highest_record > last_record_id:
            self.checkpoints[channel] = highest_record
            try:
                save_checkpoint_atomically(self.checkpoints, self.checkpoint_path)
            except Exception as ckpt_exc:
                logger.warning(f"Failed to save checkpoint for '{channel}': {ckpt_exc}")

        # If this was an initial reverse read, sort events chronologically
        if last_record_id == 0:
            events.sort(key=lambda e: (e.timestamp, e.record_id or 0))

        return events

    def poll_all_channels(self, max_events_per_channel: Optional[int] = None) -> list[SecurityEvent]:
        """
        Poll all configured channels and return a combined list of new events,
        sorted chronologically by timestamp.
        """
        all_events: list[SecurityEvent] = []
        for ch in self.channels:
            channel_events = self.poll_channel(ch, max_events=max_events_per_channel)
            all_events.extend(channel_events)

        all_events.sort(key=lambda e: (e.timestamp, e.record_id or 0))
        return all_events

    def reset_checkpoints(self) -> None:
        """Clear checkpoints and deduplication cache."""
        self.checkpoints.clear()
        self.seen_records.clear()
        if self.checkpoint_path.exists():
            try:
                self.checkpoint_path.unlink()
            except OSError:
                pass
