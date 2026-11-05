"""
Detection Engine for Sentinel OS Security Event Logger.
Analyzes normalized SecurityEvent objects and legacy event dictionaries.
Provides configurable sliding time-window detection, multi-attribute grouping (account + IP),
support for Windows Security/System event IDs, and incident correlation.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Optional, Union

from monitor.event_models import (
    Incident,
    SecurityEvent,
    SeverityLevel,
    normalize_ip_address,
)
from detection.incident_manager import IncidentManager
from detection.rules import (
    RULE_ACCOUNT_CREATED,
    RULE_AUDIT_LOG_CLEARED,
    RULE_BRUTE_FORCE,
    RULE_NEW_SERVICE,
    RULE_PERMISSION_DENIED,
    RULE_PRIVILEGE_MODIFIED,
    RULE_UNAUTHORIZED_ACCESS,
    DetectionRule,
)

logger = logging.getLogger(__name__)


def parse_timestamp(ts: Union[str, datetime, None]) -> datetime:
    """
    Safely parse ISO or standard timestamp strings into timezone-aware datetimes.
    Normalizes naive datetimes to UTC to guarantee arithmetic comparability.
    """
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts

    if not ts or not isinstance(ts, str):
        return datetime.now(timezone.utc)

    cleaned = ts.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue

    return datetime.now(timezone.utc)


class SecurityDetector:
    """
    Thread-safe, stateful detection engine.
    Applies sliding time-window correlation for failed authentications,
    handles Windows Event IDs and legacy sample log patterns,
    and forwards security alerts to the IncidentManager.
    """

    def __init__(
        self,
        threshold: int = 3,
        window_seconds: int = 60,
        incident_manager: Optional[IncidentManager] = None,
    ) -> None:
        self.threshold: int = max(1, threshold)
        self.window_seconds: int = max(1, window_seconds)
        self.incident_manager: Optional[IncidentManager] = incident_manager
        self._lock = threading.Lock()

        # Sliding window for failed logins:
        # Key: (account, normalized_ip) -> deque of (timestamp: datetime, event_ref: Any)
        self._failed_windows: dict[tuple[str, str], deque[tuple[datetime, Any]]] = (
            defaultdict(deque)
        )

        # Contextual tracking for successful logons:
        # Key: (account, normalized_ip) -> deque of timestamp: datetime
        self._success_logons: dict[tuple[str, str], deque[datetime]] = (
            defaultdict(deque)
        )

    def reset_state(self) -> None:
        """Clear all in-memory correlation windows and context history."""
        with self._lock:
            self._failed_windows.clear()
            self._success_logons.clear()

    def evaluate_event(
        self,
        event: Union[SecurityEvent, dict[str, Any]],
    ) -> tuple[Union[SecurityEvent, dict[str, Any]], Optional[Incident]]:
        """
        Evaluate a single security event against all detection rules.
        Returns the updated event (with alerts/severity assigned) and any generated Incident.
        """
        with self._lock:
            return self._evaluate_single_unlocked(event)

    def _evaluate_single_unlocked(
        self,
        event_obj: Union[SecurityEvent, dict[str, Any]],
    ) -> tuple[Union[SecurityEvent, dict[str, Any]], Optional[Incident]]:
        is_dict = isinstance(event_obj, dict)
        if is_dict:
            item = dict(event_obj)
            event_id = item.get("event_id")
            message = str(item.get("message", ""))
            user = str(item.get("user", "unknown"))
            raw_ip = item.get("ip_address") or item.get("ip")
            ip_address = normalize_ip_address(raw_ip)
            timestamp_str = str(item.get("timestamp", ""))
            alerts = list(item.get("alerts") or [])
            severity = str(item.get("severity", "INFO"))
        else:
            item = event_obj  # type: ignore
            event_id = item.event_id
            message = item.message
            user = item.user
            ip_address = item.ip_address
            timestamp_str = item.timestamp
            alerts = list(item.alerts or [])
            severity = item.severity

        dt = parse_timestamp(timestamp_str)
        if not user or not user.strip() or user.strip() == "-":
            user = "unknown"

        if not is_dict:
            item.user = user
            item.ip_address = ip_address
        else:
            item["user"] = user
            item["ip_address"] = ip_address

        msg_lower = message.lower()
        matched_incident: Optional[Incident] = None

        # -------------------------------------------------------------
        # Rule 1: Failed Logins (Event ID 4625 or sample message)
        # -------------------------------------------------------------
        is_failed_login = (
            event_id == 4625
            or "failed login" in msg_lower
            or "failed log in" in msg_lower
        )

        if is_failed_login:
            corr_key = (user, ip_address)
            win = self._failed_windows[corr_key]

            # Prune events older than sliding time window
            cutoff = (dt.timestamp() - self.window_seconds)
            while win and win[0][0].timestamp() < cutoff:
                win.popleft()

            # Record this failed attempt
            win.append((dt, item))

            if len(win) >= self.threshold:
                alert_text = f"Repeated failed login attempts for user: {user}"
                if alert_text not in alerts:
                    alerts.append(alert_text)
                severity = SeverityLevel.HIGH.value

                if self.incident_manager is not None:
                    # Construct SecurityEvent model for incident record if needed
                    sec_event = (
                        item if not is_dict
                        else SecurityEvent(
                            timestamp=timestamp_str,
                            channel=str(item.get("channel", item.get("source", "Security"))),
                            event_id=event_id or 4625,
                            user=user,
                            ip_address=ip_address,
                            message=message,
                            severity=severity,
                        )
                    )
                    explanation = (
                        f"Brute-force pattern: {len(win)} failed login attempts "
                        f"for user '{user}' from IP {ip_address} within {self.window_seconds}s."
                    )
                    matched_incident = self.incident_manager.create_or_correlate(
                        rule=RULE_BRUTE_FORCE,
                        event=sec_event,
                        explanation=explanation,
                        event_count=len(win),
                    )

        # -------------------------------------------------------------
        # Rule 2: Successful Logons (Event ID 4624) - Contextual tracking
        # -------------------------------------------------------------
        if event_id == 4624 or "user session started" in msg_lower:
            corr_key = (user, ip_address)
            self._success_logons[corr_key].append(dt)
            # Retain only recent 20 success events
            while len(self._success_logons[corr_key]) > 20:
                self._success_logons[corr_key].popleft()

        # -------------------------------------------------------------
        # Rule 3: Service Installation (Event ID 7045)
        # -------------------------------------------------------------
        if event_id == 7045 or "new service installed" in msg_lower:
            alert_text = f"New service installed on system: {message}"
            if alert_text not in alerts:
                alerts.append(alert_text)
            if severity in ("INFO", "WARNING"):
                severity = SeverityLevel.WARNING.value

            if self.incident_manager is not None:
                sec_event = item if not is_dict else SecurityEvent.from_dict(item)
                matched_incident = self.incident_manager.create_or_correlate(
                    rule=RULE_NEW_SERVICE,
                    event=sec_event,
                    explanation=f"Service installed: {message}",
                )

        # -------------------------------------------------------------
        # Rule 4: Audit Log Cleared (Event ID 1102 / 104)
        # -------------------------------------------------------------
        if event_id in (1102, 104) or "audit log was cleared" in msg_lower:
            alert_text = "Security audit log was cleared"
            if alert_text not in alerts:
                alerts.append(alert_text)
            severity = SeverityLevel.CRITICAL.value

            if self.incident_manager is not None:
                sec_event = item if not is_dict else SecurityEvent.from_dict(item)
                matched_incident = self.incident_manager.create_or_correlate(
                    rule=RULE_AUDIT_LOG_CLEARED,
                    event=sec_event,
                    explanation="Security audit log was cleared by an administrator or intruder.",
                )

        # -------------------------------------------------------------
        # Rule 5: User Account Created (Event ID 4720)
        # -------------------------------------------------------------
        if event_id == 4720 or "user account created" in msg_lower:
            alert_text = f"User account created: {user}"
            if alert_text not in alerts:
                alerts.append(alert_text)
            if severity == "INFO":
                severity = SeverityLevel.WARNING.value

            if self.incident_manager is not None:
                sec_event = item if not is_dict else SecurityEvent.from_dict(item)
                matched_incident = self.incident_manager.create_or_correlate(
                    rule=RULE_ACCOUNT_CREATED,
                    event=sec_event,
                    explanation=f"New user account '{user}' was created.",
                )

        # -------------------------------------------------------------
        # Rule 6: Account/Group Privilege Modifications (4722, 4726, 4728, 4732)
        # -------------------------------------------------------------
        if event_id in (4722, 4726, 4728, 4732, 4756):
            alert_text = f"Privilege change or account modification (Event ID {event_id})"
            if alert_text not in alerts:
                alerts.append(alert_text)
            severity = SeverityLevel.HIGH.value

            if self.incident_manager is not None:
                sec_event = item if not is_dict else SecurityEvent.from_dict(item)
                matched_incident = self.incident_manager.create_or_correlate(
                    rule=RULE_PRIVILEGE_MODIFIED,
                    event=sec_event,
                    explanation=f"Account or group modified (Event ID {event_id}): {message}",
                )

        # -------------------------------------------------------------
        # Rule 7: Unauthorized Access Substring
        # -------------------------------------------------------------
        if "unauthorized access" in msg_lower:
            alert_text = "Unauthorized access attempt detected"
            if alert_text not in alerts:
                alerts.append(alert_text)
            severity = SeverityLevel.HIGH.value

            if self.incident_manager is not None:
                sec_event = (
                    item if not is_dict
                    else SecurityEvent(
                        timestamp=timestamp_str,
                        channel=str(item.get("channel", item.get("source", "Sample"))),
                        user=user,
                        ip_address=ip_address,
                        message=message,
                        severity=severity,
                    )
                )
                matched_incident = self.incident_manager.create_or_correlate(
                    rule=RULE_UNAUTHORIZED_ACCESS,
                    event=sec_event,
                    explanation="Unauthorized access attempt detected in log stream.",
                )

        # -------------------------------------------------------------
        # Rule 8: Permission Denied Substring
        # -------------------------------------------------------------
        if "permission denied" in msg_lower:
            alert_text = "Permission-denied event detected"
            if alert_text not in alerts:
                alerts.append(alert_text)
            severity = SeverityLevel.HIGH.value

            if self.incident_manager is not None:
                sec_event = (
                    item if not is_dict
                    else SecurityEvent(
                        timestamp=timestamp_str,
                        channel=str(item.get("channel", item.get("source", "Sample"))),
                        user=user,
                        ip_address=ip_address,
                        message=message,
                        severity=severity,
                    )
                )
                matched_incident = self.incident_manager.create_or_correlate(
                    rule=RULE_PERMISSION_DENIED,
                    event=sec_event,
                    explanation="Permission-denied access attempt detected.",
                )

        is_suspicious = bool(alerts)

        # Assign values back to output object
        if is_dict:
            item["is_suspicious"] = is_suspicious
            item["alerts"] = alerts
            if is_suspicious and severity:
                item["severity"] = severity
            return item, matched_incident
        else:
            item.is_suspicious = is_suspicious
            item.alerts = alerts
            if is_suspicious and severity:
                item.severity = severity
            return item, matched_incident

    def evaluate_batch(
        self,
        events: list[Union[SecurityEvent, dict[str, Any]]],
    ) -> tuple[list[Any], list[Incident]]:
        """
        Evaluate a sequence of events.
        Ensures sliding windows properly correlate consecutive failures in the batch,
        and marks all participating events within an active threshold cluster.
        """
        with self._lock:
            # Self-contained run: reset state for new batch analysis
            self._failed_windows.clear()
            self._success_logons.clear()

            processed_events: list[Any] = []
            incidents: list[Incident] = []

            # First pass: evaluate sequentially through the time windows
            for ev in events:
                proc, inc = self._evaluate_single_unlocked(ev)
                processed_events.append(proc)
                if inc and inc not in incidents:
                    incidents.append(inc)

            # Second pass: ensure all events belonging to triggered windows
            # are marked as part of the repeated-failure cluster (preserves legacy batch contract)
            triggered_clusters = {
                key: win for key, win in self._failed_windows.items()
                if len(win) >= self.threshold
            }

            if triggered_clusters:
                for ev in processed_events:
                    user = ev.get("user") if isinstance(ev, dict) else ev.user
                    raw_ip = (
                        ev.get("ip_address") or ev.get("ip") if isinstance(ev, dict)
                        else ev.ip_address
                    )
                    ip = normalize_ip_address(raw_ip)
                    msg = (
                        str(ev.get("message", "")).lower() if isinstance(ev, dict)
                        else ev.message.lower()
                    )
                    ev_id = ev.get("event_id") if isinstance(ev, dict) else ev.event_id

                    is_failed = (
                        ev_id == 4625
                        or "failed login" in msg
                        or "failed log in" in msg
                        or "failed to log on" in msg
                    )

                    if (user, ip) in triggered_clusters and is_failed:
                        alert_text = f"Repeated failed login attempts for user: {user}"
                        if isinstance(ev, dict):
                            ev["is_suspicious"] = True
                            if alert_text not in ev["alerts"]:
                                ev["alerts"].append(alert_text)
                            ev["severity"] = SeverityLevel.HIGH.value
                        else:
                            ev.is_suspicious = True
                            if alert_text not in ev.alerts:
                                ev.alerts.append(alert_text)
                            ev.severity = SeverityLevel.HIGH.value

            return processed_events, incidents


# ----------------------------------------------------------------------
# Backward-compatible functional entry point
# ----------------------------------------------------------------------

def detect_security_events(
    events: list[Union[SecurityEvent, dict[str, Any]]],
    threshold: int = 3,
    window_seconds: int = 60,
    incident_manager: Optional[IncidentManager] = None,
) -> list[Any]:
    """
    Detect security events across a batch of events.
    Maintains exact backward-compatible signature and return format for main.py,
    tests, and dashboard consumers.
    """
    detector = SecurityDetector(
        threshold=threshold,
        window_seconds=window_seconds,
        incident_manager=incident_manager,
    )
    processed, _ = detector.evaluate_batch(events)
    return processed
