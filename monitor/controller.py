"""
Central Sentinel Controller.
Integrates Windows Event Log Ingestion, Security Detection, Incident Lifecycle Management,
System Diagnostics, and Thread-Safe Shared State into a unified security monitoring engine.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from monitor.app_state import AppState, MonitoringStatus
from monitor.diagnostics import get_system_diagnostics
from monitor.event_models import (
    Incident,
    IncidentStatus,
    SecurityEvent,
    SourceType,
)
from monitor.windows_monitor import WindowsEventCollector
from detection.detector import SecurityDetector
from detection.incident_manager import IncidentManager
from detection.rules import DetectionRule

logger = logging.getLogger(__name__)


class SentinelController:
    """
    Central coordinator for Sentinel security monitoring operations.
    Manages background thread lifecycle, dispatches events to detection engine,
    tracks incidents, and exposes clean APIs for presentation tiers.
    """

    def __init__(
        self,
        channels: Optional[list[str]] = None,
        poll_interval: float = 1.0,
        detection_threshold: int = 3,
        window_seconds: int = 60,
        checkpoint_path: Optional[Union[str, Path]] = None,
        incident_storage_path: Optional[Union[str, Path]] = None,
        max_state_events: int = 1000,
        source_type: Union[SourceType, str] = SourceType.LIVE_WINDOWS,
    ) -> None:
        self.poll_interval: float = max(0.2, poll_interval)
        self.channels: list[str] = list(channels or ["System", "Application"])

        # Resolve active source type
        if isinstance(source_type, str):
            try:
                self.source_type = SourceType(source_type.upper().strip())
            except ValueError:
                self.source_type = SourceType.LIVE_WINDOWS
        else:
            self.source_type = source_type

        # 1. State container
        self.app_state: AppState = AppState(max_events=max_state_events)
        self.app_state.set_active_source(self.source_type)
        self.app_state.set_monitored_channels(self.channels)

        # 2. Incident Manager
        self.incident_manager: IncidentManager = IncidentManager(
            storage_path=incident_storage_path
        )

        # 3. Detection Engine
        self.detector: SecurityDetector = SecurityDetector(
            threshold=detection_threshold,
            window_seconds=window_seconds,
            incident_manager=self.incident_manager,
        )

        # 4. Windows Event Collector
        self.collector: WindowsEventCollector = WindowsEventCollector(
            channels=self.channels,
            checkpoint_path=checkpoint_path,
        )

        # Threading and lifecycle synchronization
        self._lifecycle_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused by default
        self._worker_thread: Optional[threading.Thread] = None

        # Perform initial non-invasive diagnostic probe
        self.refresh_diagnostics()

    # ------------------------------------------------------------------
    # Lifecycle Management (Start, Pause, Resume, Stop)
    # ------------------------------------------------------------------

    def start_monitoring(self) -> bool:
        """
        Start the background monitoring worker thread.
        Idempotent: prevents duplicate workers if already running.
        """
        with self._lifecycle_lock:
            if self._worker_thread and self._worker_thread.is_alive():
                current_status = self.app_state.get_status()
                if current_status == MonitoringStatus.PAUSED:
                    return self.resume_monitoring()
                logger.info("Monitoring worker is already active.")
                return True

            # Prepare thread control events
            self._stop_event.clear()
            self._pause_event.set()
            self.app_state.clear_error()
            self.app_state.set_status(MonitoringStatus.RUNNING)

            # Spawn dedicated daemon worker thread
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="SentinelWorkerThread",
                daemon=True,
            )
            self._worker_thread.start()
            logger.info("Sentinel background monitoring worker started.")
            return True

    def pause_monitoring(self) -> bool:
        """
        Pause event collection temporarily without destroying worker or resetting state.
        """
        with self._lifecycle_lock:
            if not self._worker_thread or not self._worker_thread.is_alive():
                logger.warning("Cannot pause: monitoring is not active.")
                return False

            self._pause_event.clear()
            self.app_state.set_status(MonitoringStatus.PAUSED)
            logger.info("Sentinel monitoring paused.")
            return True

    def resume_monitoring(self) -> bool:
        """Resume monitoring collection from saved checkpoints."""
        with self._lifecycle_lock:
            if not self._worker_thread or not self._worker_thread.is_alive():
                logger.warning("Cannot resume: monitoring thread is not running.")
                return False

            self._pause_event.set()
            self.app_state.set_status(MonitoringStatus.RUNNING)
            logger.info("Sentinel monitoring resumed.")
            return True

    def stop_monitoring(self, timeout: float = 3.0) -> bool:
        """
        Signal the worker to terminate gracefully and wait up to timeout seconds.
        Preserves all checkpoints, persistent incidents, and recent event history.
        """
        with self._lifecycle_lock:
            if not self._worker_thread or not self._worker_thread.is_alive():
                self.app_state.set_status(MonitoringStatus.STOPPED)
                return True

            # Unblock any waiting loops and set stop signal
            self._stop_event.set()
            self._pause_event.set()

            self._worker_thread.join(timeout=timeout)
            is_dead = not self._worker_thread.is_alive()
            if not is_dead:
                logger.warning("Monitoring thread did not terminate within timeout.")

            self._worker_thread = None
            self.app_state.set_status(MonitoringStatus.STOPPED)
            logger.info("Sentinel monitoring stopped.")
            return is_dead

    def get_monitoring_status(self) -> str:
        """Return the current string lifecycle status."""
        return self.app_state.get_status().value

    def is_worker_alive(self) -> bool:
        """Return True if the background monitoring worker thread is currently active."""
        return bool(self._worker_thread and self._worker_thread.is_alive())

    # ------------------------------------------------------------------
    # Worker Thread Routine & Collection Execution
    # ------------------------------------------------------------------

    def _worker_loop(self) -> None:
        """Internal worker loop running on a background daemon thread."""
        logger.debug("Worker loop entered.")
        while not self._stop_event.is_set():
            # Check pause state
            if not self._pause_event.is_set():
                self._pause_event.wait(timeout=0.5)
                continue

            # Run a single collection & detection cycle
            try:
                self.run_once()
            except Exception as cycle_exc:
                err_msg = f"Unexpected error during monitoring cycle: {cycle_exc}"
                logger.error(err_msg, exc_info=True)
                self.app_state.set_error(err_msg)

            # Interruptible sleep between polling cycles
            self._stop_event.wait(timeout=self.poll_interval)

        logger.debug("Worker loop exited cleanly.")

    def run_once(self, max_events: Optional[int] = None) -> list[SecurityEvent]:
        """
        Execute a single synchronous cycle of collection, detection, and state update.
        Safe for use by background threads, CLI one-shot runs, and unit tests.
        """
        raw_events: list[SecurityEvent] = []

        try:
            if self.source_type == SourceType.LIVE_WINDOWS:
                raw_events = self.collector.poll_all_channels(max_events_per_channel=max_events)
            elif self.source_type == SourceType.STATIC_SAMPLE_FILE:
                raw_events = self._load_sample_file_events()
            elif self.source_type == SourceType.SIMULATED_REPLAY:
                raw_events = self._load_sample_file_events()
                # For simulated replay, tag appropriately
                for ev in raw_events:
                    ev.source_type = SourceType.SIMULATED_REPLAY

            if raw_events:
                # 2. Evaluate events through detection engine
                processed, _ = self.detector.evaluate_batch(raw_events)

                # 3. Commit processed events into thread-safe state
                self.app_state.record_events_batch(processed)
                return processed
            else:
                self.app_state.update_collection_time()
                return []

        except Exception as exc:
            err_msg = f"Collection/Detection failure: {exc}"
            logger.error(err_msg)
            self.app_state.set_error(err_msg)
            return []

    def _load_sample_file_events(self) -> list[SecurityEvent]:
        """Helper to load sample log lines and normalize to SecurityEvent instances."""
        from monitor.log_monitor import read_logs

        sample_dicts = read_logs()
        events: list[SecurityEvent] = []
        for d in sample_dicts:
            event = SecurityEvent(
                timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
                source_type=self.source_type,
                channel="Sample",
                severity=d.get("severity", "INFO"),
                event_type="system_event",
                user=d.get("user", "unknown"),
                message=d.get("message", ""),
            )
            events.append(event)
        return events

    # ------------------------------------------------------------------
    # Configuration & Diagnostics API
    # ------------------------------------------------------------------

    def refresh_diagnostics(self) -> dict[str, Any]:
        """Run a read-only diagnostics probe and update state."""
        diag = get_system_diagnostics()
        self.app_state.update_diagnostics(diag)
        return diag

    def set_channels(self, channels: list[str]) -> None:
        """Update monitored channels."""
        self.channels = list(channels)
        self.collector.channels = self.channels
        self.collector.refresh_channel_status()
        self.app_state.set_monitored_channels(self.channels)

    def set_source_type(self, source_type: Union[SourceType, str]) -> None:
        """Switch the active ingestion source."""
        if isinstance(source_type, str):
            try:
                st = SourceType(source_type.upper().strip())
            except ValueError:
                st = SourceType.STATIC_SAMPLE_FILE
        else:
            st = source_type
        self.source_type = st
        self.app_state.set_active_source(st)

    def set_detection_parameters(
        self,
        threshold: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> None:
        """Update detection engine threshold and sliding window seconds."""
        if threshold is not None:
            self.detector.threshold = max(1, threshold)
        if window_seconds is not None:
            self.detector.window_seconds = max(1, window_seconds)

    # ------------------------------------------------------------------
    # Public Query API for Future Dashboard / CLI
    # ------------------------------------------------------------------

    def get_dashboard_snapshot(self) -> dict[str, Any]:
        """Produce a complete, thread-safe snapshot for the dashboard."""
        all_inc = self.incident_manager.get_all_incidents()
        open_inc = self.incident_manager.get_open_incidents()
        stats = {
            "total": len(all_inc),
            "open": len(open_inc),
        }
        return self.app_state.get_dashboard_snapshot(incident_stats=stats)

    def get_recent_events(self, limit: int = 50) -> list[SecurityEvent]:
        """Return a slice of the most recent processed events."""
        return self.app_state.get_recent_events(limit=limit)

    def get_recent_detections(self, limit: int = 50) -> list[SecurityEvent]:
        """Return a slice of the most recent security detections/alerts."""
        return self.app_state.get_recent_detections(limit=limit)

    def get_incidents(
        self,
        status: Optional[Union[str, IncidentStatus]] = None
    ) -> list[Incident]:
        """Return persistent incidents, optionally filtered by status."""
        incidents = self.incident_manager.get_all_incidents()
        if status is not None:
            target_status = status.value if isinstance(status, IncidentStatus) else str(status).upper()
            return [inc for inc in incidents if inc.status == target_status]
        return incidents

    def update_incident_status(
        self,
        incident_id: str,
        new_status: Union[str, IncidentStatus]
    ) -> Optional[Incident]:
        """Update an incident's lifecycle status."""
        return self.incident_manager.update_status(incident_id, new_status)

    def get_system_diagnostics(self) -> dict[str, Any]:
        """Return current system diagnostic information."""
        return self.refresh_diagnostics()
