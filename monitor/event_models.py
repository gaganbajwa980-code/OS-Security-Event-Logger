"""
Data models and atomic persistence utilities for the OS Security Event Logger.
Defines unified representations for security events, incidents, and source types.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union


class SourceType(str, Enum):
    """Identifies the origin of a security event."""
    LIVE_WINDOWS = "LIVE_WINDOWS"
    SIMULATED_REPLAY = "SIMULATED_REPLAY"
    STATIC_SAMPLE_FILE = "STATIC_SAMPLE_FILE"


class SeverityLevel(str, Enum):
    """Standardized severity classification."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    """Lifecycle status of a security incident."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


def normalize_ip_address(ip: Optional[str]) -> str:
    """
    Normalize an IP address string.
    Gracefully handles missing, loopback, or blank representations.
    """
    if not ip or not isinstance(ip, str):
        return "UNKNOWN"

    cleaned = ip.strip()
    if cleaned in ("", "-", "0.0.0.0", "::"):
        return "UNKNOWN"
    if cleaned in ("127.0.0.1", "::1"):
        return "LOCAL_LOOPBACK"

    return cleaned


@dataclass
class SecurityEvent:
    """Unified security event model."""
    timestamp: str
    source_type: SourceType = SourceType.STATIC_SAMPLE_FILE
    channel: str = "Sample"
    event_id: Optional[int] = None
    record_id: Optional[int] = None
    provider: str = "System"
    severity: str = SeverityLevel.INFO.value
    event_type: str = "system_event"
    user: str = "unknown"
    computer: str = "localhost"
    ip_address: str = "UNKNOWN"
    message: str = ""
    is_suspicious: bool = False
    alerts: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.source_type, str) and not isinstance(self.source_type, SourceType):
            try:
                self.source_type = SourceType(self.source_type)
            except ValueError:
                self.source_type = SourceType.STATIC_SAMPLE_FILE
        self.ip_address = normalize_ip_address(self.ip_address)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary."""
        data = asdict(self)
        data["source_type"] = self.source_type.value
        return data

    def to_legacy_dict(self) -> dict[str, Any]:
        """Convert to the legacy dictionary shape expected by existing modules."""
        legacy = self.to_dict()
        legacy["source"] = f"{self.channel} ({self.source_type.value})"
        return legacy

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityEvent:
        """Create a SecurityEvent instance from a dictionary."""
        cleaned = data.copy()
        raw_source = cleaned.pop("source_type", SourceType.STATIC_SAMPLE_FILE)
        if isinstance(raw_source, str):
            try:
                source_type = SourceType(raw_source)
            except ValueError:
                source_type = SourceType.STATIC_SAMPLE_FILE
        else:
            source_type = raw_source

        # Handle legacy field mappings if present
        if "source" in cleaned and "channel" not in cleaned:
            cleaned["channel"] = cleaned.pop("source")

        known_fields = {f for f in cls.__dataclass_fields__.keys()}
        filtered = {k: v for k, v in cleaned.items() if k in known_fields}
        return cls(source_type=source_type, **filtered)


@dataclass
class Incident:
    """Security incident representing a correlated set of suspicious events."""
    incident_id: str
    timestamp_first: str
    timestamp_last: str
    rule_id: str
    rule_name: str
    severity: str
    user: str
    source_ip: str
    description: str
    mitre_attack_id: Optional[str] = None
    event_ids: list[int] = field(default_factory=list)
    event_count: int = 1
    related_events: list[dict[str, Any]] = field(default_factory=list)
    title: str = ""
    status: str = "OPEN"

    def __post_init__(self):
        if not self.title:
            self.title = self.rule_name

    def set_status(self, new_status: Union[str, IncidentStatus]) -> None:
        """Update incident lifecycle status with validation."""
        if isinstance(new_status, IncidentStatus):
            self.status = new_status.value
        elif isinstance(new_status, str):
            val = new_status.upper().strip()
            if val in (s.value for s in IncidentStatus):
                self.status = val
            else:
                raise ValueError(
                    f"Invalid incident status '{new_status}'. "
                    f"Must be OPEN, INVESTIGATING, or RESOLVED."
                )
        else:
            raise TypeError("Status must be str or IncidentStatus enum.")

    def to_dict(self) -> dict[str, Any]:
        """Convert incident to a JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Incident:
        """Instantiate an Incident from a dictionary."""
        known_fields = {f for f in cls.__dataclass_fields__.keys()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)


# ----------------------------------------------------------------------
# Safe Atomic Persistence Utilities
# ----------------------------------------------------------------------

def save_json_atomically(data: Any, target_path: Union[str, Path]) -> None:
    """
    Safely write JSON data to disk using an atomic replace operation.
    Guarantees that files are not left in a corrupted or partial state
    if the process is interrupted during writing.
    """
    target = Path(target_path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    temp_fd, temp_path_str = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.stem}_",
        suffix=".tmp"
    )

    try:
        with os.fdopen(temp_fd, "w", encoding="utf-8") as temp_file:
            json.dump(data, temp_file, indent=2, default=str)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        os.replace(temp_path_str, target)
    except Exception:
        if os.path.exists(temp_path_str):
            try:
                os.remove(temp_path_str)
            except OSError:
                pass
        raise


def load_json_safe(target_path: Union[str, Path], default: Any = None) -> Any:
    """
    Safely load JSON data from disk.
    Returns the specified default if the file is missing or corrupted.
    """
    target = Path(target_path)
    if not target.exists() or not target.is_file():
        return default

    try:
        with open(target, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def save_checkpoint_atomically(checkpoints: dict[str, int], path: Union[str, Path]) -> None:
    """Atomically persist event record checkpoints per channel."""
    save_json_atomically(checkpoints, path)


def load_checkpoint(path: Union[str, Path]) -> dict[str, int]:
    """Load channel record checkpoints, returning an empty dict if not found."""
    loaded = load_json_safe(path, default={})
    if isinstance(loaded, dict):
        return {str(k): int(v) for k, v in loaded.items() if str(v).isdigit() or isinstance(v, int)}
    return {}


def save_incidents_atomically(incidents: list[Incident], path: Union[str, Path]) -> None:
    """Atomically persist a list of Incident instances."""
    data = [inc.to_dict() for inc in incidents]
    save_json_atomically(data, path)


def load_incidents(path: Union[str, Path]) -> list[Incident]:
    """Load a list of Incident instances from persistent storage."""
    loaded = load_json_safe(path, default=[])
    if isinstance(loaded, list):
        results = []
        for item in loaded:
            if isinstance(item, dict):
                try:
                    results.append(Incident.from_dict(item))
                except Exception:
                    continue
        return results
    return []
