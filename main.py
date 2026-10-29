
import json
from pathlib import Path

from monitor.log_monitor import read_logs
from detection.detector import detect_security_events


PROJECT_ROOT = Path(__file__).resolve().parent
REPORT_FILE = PROJECT_ROOT / "data" / "security_report.json"


def main():
    """Run the security logger from the command line."""
    try:
        events = read_logs()
        results = detect_security_events(events)
    except (OSError, ValueError) as error:
        print(f"Error reading security logs: {error}")
        return

    suspicious = [
        event for event in results
        if event["is_suspicious"]
    ]

    print("=" * 55)
    print("       OS SECURITY EVENT LOGGER")
    print("=" * 55)
    print(f"Total events processed : {len(results)}")
    print(f"Suspicious events      : {len(suspicious)}")
    print(f"Normal events          : {len(results) - len(suspicious)}")
    print("-" * 55)

    if suspicious:
        print("SECURITY ALERTS")
        for event in suspicious:
            print(f"[{event['severity']}] {event['message']}")
            for alert in event["alerts"]:
                print(f"  Alert: {alert}")
    else:
        print("No suspicious events detected.")

    REPORT_FILE.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8",
    )

    print("-" * 55)
    print(f"JSON report saved to: {REPORT_FILE}")
    print("=" * 55)


if __name__ == "__main__":
    main()
