"""
Incident Management Layer for Sentinel OS Security Event Logger.
Tracks, correlates, transitions, and persists security incidents.
Guarantees thread-safe access and atomic disk persistence across application restarts.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from monitor.event_models import (
    Incident,
    IncidentStatus,
    SecurityEvent,
    load_incidents,
    save_incidents_atomically,
)
from detection.rules import DetectionRule

logger = logging.getLogger(__name__)


class IncidentManager:
    """
    Thread-safe manager for security incidents.
    Supports deduplication, event correlation, status lifecycle,
    and atomic persistence across sessions.
    """

    def __init__(self, storage_path: Optional[Union[str, Path]] = None) -> None:
        self.storage_path = (
            Path(storage_path) if storage_path else Path("data/incidents_history.json")
        )
        self._lock = threading.Lock()
        self._incidents: list[Incident] = []
        self._incidents_by_id: dict[str, Incident] = {}
        # Correlation map: (rule_id, user, source_ip) -> active open Incident
        self._active_correlations: dict[tuple[str, str, str], Incident] = {}
        # Deduplication fingerprints to avoid duplicate incident generation
        self._processed_event_fingerprints: set[str] = set()

        self.load()

    def load(self) -> None:
        """Load persistent incident history from disk."""
        with self._lock:
            loaded = load_incidents(self.storage_path)
            self._incidents = loaded
            self._incidents_by_id = {inc.incident_id: inc for inc in self._incidents}

            # Rebuild active correlations for open incidents
            self._active_correlations.clear()
            for inc in self._incidents:
                if inc.status in (IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value):
                    corr_key = (inc.rule_id, inc.user, inc.source_ip)
                    self._active_correlations[corr_key] = inc

    def save(self) -> None:
        """Atomically persist incidents to disk."""
        with self._lock:
            self._save_unlocked()

    def _save_unlocked(self) -> None:
        """Internal save assuming caller holds self._lock."""
        try:
            save_incidents_atomically(self._incidents, self.storage_path)
        except Exception as exc:
            logger.error(f"Failed to save incidents atomically: {exc}")

    def create_or_correlate(
        self,
        rule: DetectionRule,
        event: SecurityEvent,
        explanation: Optional[str] = None,
        event_count: int = 1,
    ) -> Incident:
        """
        Record a security detection. If an active correlation exists for the same
        rule, account, and source IP, associates the event with the existing open incident
        instead of creating a duplicate.
        """
        fingerprint = (
            f"{event.channel}:{event.record_id or 'none'}:"
            f"{event.timestamp}:{rule.rule_id}:{event.user}"
        )

        with self._lock:
            # Check deduplication
            if fingerprint in self._processed_event_fingerprints:
                corr_key = (rule.rule_id, event.user, event.ip_address)
                if corr_key in self._active_correlations:
                    return self._active_correlations[corr_key]

            self._processed_event_fingerprints.add(fingerprint)

            # Check if this detection should correlate with an existing open incident
            corr_key = (rule.rule_id, event.user, event.ip_address)
            existing = self._active_correlations.get(corr_key)

            if existing is not None and existing.status in (
                IncidentStatus.OPEN.value,
                IncidentStatus.INVESTIGATING.value,
            ):
                # Associate event with existing incident
                existing.event_count = max(existing.event_count + 1, event_count)
                existing.timestamp_last = event.timestamp
                if event.event_id and event.event_id not in existing.event_ids:
                    existing.event_ids.append(event.event_id)

                existing.related_events.append({
                    "timestamp": event.timestamp,
                    "event_id": event.event_id,
                    "record_id": event.record_id,
                    "channel": event.channel,
                    "source_type": event.source_type.value,
                    "message": event.message,
                })

                if explanation:
                    existing.description = explanation

                self._save_unlocked()
                return existing

            # Otherwise, create a new incident
            now_str = datetime.now(timezone.utc).strftime("%Y%m%d")
            unique_suffix = uuid.uuid4().hex[:6].upper()
            incident_id = f"INC-{now_str}-{unique_suffix}"

            description = (
                explanation
                or f"{rule.name} detected for user '{event.user}' from IP {event.ip_address}."
            )

            related_event_summary = {
                "timestamp": event.timestamp,
                "event_id": event.event_id,
                "record_id": event.record_id,
                "channel": event.channel,
                "source_type": event.source_type.value,
                "message": event.message,
            }

            event_ids = [event.event_id] if event.event_id else []

            incident = Incident(
                incident_id=incident_id,
                timestamp_first=event.timestamp,
                timestamp_last=event.timestamp,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                user=event.user,
                source_ip=event.ip_address,
                description=description,
                mitre_attack_id=rule.mitre_attack_id,
                event_ids=event_ids,
                event_count=event_count,
                related_events=[related_event_summary],
                title=f"{rule.name}: {event.user}",
                status=IncidentStatus.OPEN.value,
            )

            self._incidents.insert(0, incident)
            self._incidents_by_id[incident_id] = incident
            self._active_correlations[corr_key] = incident
            self._save_unlocked()
            return incident

    def update_status(
        self,
        incident_id: str,
        new_status: Union[str, IncidentStatus]
    ) -> Optional[Incident]:
        """Update incident lifecycle status (OPEN, INVESTIGATING, RESOLVED)."""
        with self._lock:
            incident = self._incidents_by_id.get(incident_id)
            if not incident:
                return None

            incident.set_status(new_status)

            # If resolved, remove from active correlations so future detections create fresh incidents
            if incident.status == IncidentStatus.RESOLVED.value:
                corr_key = (incident.rule_id, incident.user, incident.source_ip)
                if self._active_correlations.get(corr_key) == incident:
                    self._active_correlations.pop(corr_key, None)

            self._save_unlocked()
            return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve an incident by ID."""
        with self._lock:
            return self._incidents_by_id.get(incident_id)

    def get_all_incidents(self) -> list[Incident]:
        """Return a copy of all tracked incidents."""
        with self._lock:
            return list(self._incidents)

    def get_open_incidents(self) -> list[Incident]:
        """Return currently open or investigating incidents."""
        with self._lock:
            return [
                inc for inc in self._incidents
                if inc.status in (IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value)
            ]

    def clear(self) -> None:
        """Clear all in-memory and persisted incidents."""
        with self._lock:
            self._incidents.clear()
            self._incidents_by_id.clear()
            self._active_correlations.clear()
            self._processed_event_fingerprints.clear()
            if self.storage_path.exists():
                try:
                    self.storage_path.unlink()
                except OSError:
                    pass
