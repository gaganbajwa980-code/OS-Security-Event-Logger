"""
Thread-safe shared application state for Sentinel OS Security Event Logger.
Coordinates in-memory metrics, event and alert ring buffers, diagnostics,
and monitoring status for concurrent background workers and presentation tiers.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Union

from monitor.event_models import Incident, SecurityEvent, SourceType


class MonitoringStatus(str, Enum):
    """Lifecycle status of the Sentinel monitoring engine."""
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPED = "STOPPED"
    ERROR = "ERROR"


class AppState:
    """
    Synchronized, thread-safe state container.
    Protects all mutable monitoring telemetry with an RLock.
    Provides bounded in-memory ring buffers and safe immutable snapshots.
    """

    def __init__(
        self,
        max_events: int = 1000,
        max_detections: int = 500,
    ) -> None:
        self._lock = threading.RLock()
        self.max_events = max(1, max_events)
        self.max_detections = max(1, max_detections)

        # Core lifecycle attributes
        self._status: MonitoringStatus = MonitoringStatus.IDLE
        self._start_time: Optional[str] = None
        self._last_collection_time: Optional[str] = None
        self._last_error: Optional[str] = None

        # Source and channel metadata
        self._active_source: SourceType = SourceType.LIVE_WINDOWS
        self._monitored_channels: list[str] = ["System", "Application"]

        # Telemetry counters
        self._total_events_processed: int = 0
        self._total_detections_generated: int = 0

        # Diagnostics snapshot
        self._diagnostics: dict[str, Any] = {}

        # Bounded in-memory ring buffers (stores newest first or chronological)
        self._recent_events: deque[SecurityEvent] = deque(maxlen=self.max_events)
        self._recent_detections: deque[SecurityEvent] = deque(maxlen=self.max_detections)

    # ------------------------------------------------------------------
    # Lifecycle & Status Mutators
    # ------------------------------------------------------------------

    def set_status(self, status: Union[MonitoringStatus, str]) -> None:
        """Update monitoring lifecycle status."""
        with self._lock:
            if isinstance(status, str):
                try:
                    status = MonitoringStatus(status.upper().strip())
                except ValueError:
                    status = MonitoringStatus.ERROR

            self._status = status
            if status == MonitoringStatus.RUNNING and not self._start_time:
                self._start_time = datetime.now(timezone.utc).isoformat()
            elif status == MonitoringStatus.STOPPED:
                self._start_time = None

    def get_status(self) -> MonitoringStatus:
        """Retrieve current lifecycle status."""
        with self._lock:
            return self._status

    def set_active_source(self, source: Union[SourceType, str]) -> None:
        """Record the active event ingestion source."""
        with self._lock:
            if isinstance(source, str):
                try:
                    source = SourceType(source.upper().strip())
                except ValueError:
                    source = SourceType.STATIC_SAMPLE_FILE
            self._active_source = source

    def set_monitored_channels(self, channels: list[str]) -> None:
        """Set the active list of monitored channel names."""
        with self._lock:
            self._monitored_channels = list(channels)

    def set_error(self, error_message: str) -> None:
        """Record a component or collection error."""
        with self._lock:
            self._last_error = error_message
            self._status = MonitoringStatus.ERROR

    def clear_error(self) -> None:
        """Clear the last recorded error message."""
        with self._lock:
            self._last_error = None

    def update_diagnostics(self, diagnostics: dict[str, Any]) -> None:
        """Update system and channel diagnostics information."""
        with self._lock:
            self._diagnostics = dict(diagnostics)

    def update_collection_time(self) -> None:
        """Record the timestamp of a successful collection cycle."""
        with self._lock:
            self._last_collection_time = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Event & Detection Ingestion
    # ------------------------------------------------------------------

    def record_event(self, event: SecurityEvent) -> None:
        """Record a single processed event into state."""
        with self._lock:
            self._total_events_processed += 1
            self._recent_events.appendleft(event)

            if event.is_suspicious:
                self._total_detections_generated += 1
                self._recent_detections.appendleft(event)

    def record_events_batch(self, events: list[SecurityEvent]) -> None:
        """Record a batch of processed events into state efficiently."""
        with self._lock:
            for ev in events:
                self.record_event(ev)
            self.update_collection_time()

    # ------------------------------------------------------------------
    # State Inspection & Snapshots
    # ------------------------------------------------------------------

    def get_recent_events(self, limit: int = 50) -> list[SecurityEvent]:
        """Return a safe copy of the most recent events (newest first)."""
        with self._lock:
            slice_limit = min(max(1, limit), len(self._recent_events))
            return [self._recent_events[i] for i in range(slice_limit)]

    def get_recent_detections(self, limit: int = 50) -> list[SecurityEvent]:
        """Return a safe copy of the most recent detections (newest first)."""
        with self._lock:
            slice_limit = min(max(1, limit), len(self._recent_detections))
            return [self._recent_detections[i] for i in range(slice_limit)]

    def get_dashboard_snapshot(
        self,
        incident_stats: Optional[dict[str, int]] = None
    ) -> dict[str, Any]:
        """
        Produce a consistent, thread-safe telemetry snapshot for the presentation tier.
        Guarantees that all metrics are internally consistent at the moment of reading.
        """
        with self._lock:
            inc_total = incident_stats.get("total", 0) if incident_stats else 0
            inc_open = incident_stats.get("open", 0) if incident_stats else 0

            return {
                "status": self._status.value,
                "active_source": self._active_source.value,
                "monitored_channels": list(self._monitored_channels),
                "start_time": self._start_time,
                "last_collection_time": self._last_collection_time,
                "last_error": self._last_error,
                "total_events_processed": self._total_events_processed,
                "total_detections_generated": self._total_detections_generated,
                "total_incidents": inc_total,
                "open_incidents": inc_open,
                "recent_events_count": len(self._recent_events),
                "recent_detections_count": len(self._recent_detections),
                "diagnostics": dict(self._diagnostics),
            }

    def reset(self) -> None:
        """Reset state metrics, buffers, and status back to IDLE."""
        with self._lock:
            self._status = MonitoringStatus.IDLE
            self._start_time = None
            self._last_collection_time = None
            self._last_error = None
            self._total_events_processed = 0
            self._total_detections_generated = 0
            self._recent_events.clear()
            self._recent_detections.clear()
