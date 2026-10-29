
from pathlib import Path
from datetime import datetime
import re

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG_FILE = PROJECT_ROOT / "data" / "sample_logs.txt"

PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"(?P<level>INFO|WARNING|ERROR) "
    r"(?P<message>.*)$"
)


def parse_log_line(line):
    """Parse one sample log line into a dictionary."""
    match = PATTERN.match(line.strip())

    if not match:
        return None

    event = match.groupdict()
    event["timestamp"] = datetime.strptime(
        event["timestamp"], "%Y-%m-%d %H:%M:%S"
    ).isoformat()

    event["source"] = "sample_logs.txt"
    event["severity"] = event.pop("level")
    event["event_type"] = "system_event"

    user_match = re.search(
        r"\bfor user\s+([A-Za-z0-9_.-]+)",
        event["message"],
        re.IGNORECASE,
    )

    event["user"] = user_match.group(1) if user_match else "unknown"

    return event


def read_logs(file_path=DEFAULT_LOG_FILE):
    """Read and parse all valid log lines."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    events = []

    with path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            event = parse_log_line(line)
            if event:
                events.append(event)

    return events
