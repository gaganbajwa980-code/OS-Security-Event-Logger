
from collections import Counter


def detect_security_events(events, threshold=3):
    """
    Analyze parsed log events and flag suspicious activity.
    Returns a new list with detection results.
    """
    failed_logins = Counter()
    results = []

    # First pass: count failed login attempts by user.
    for event in events:
        message = event.get("message", "").lower()

        if "failed login" in message or "failed log in" in message:
            user = event.get("user", "unknown")
            failed_logins[user] += 1

    # Second pass: classify each event.
    for event in events:
        item = event.copy()
        message = item.get("message", "").lower()
        severity = item.get("severity", "INFO")
        alerts = []

        if "failed login" in message or "failed log in" in message:
            user = item.get("user", "unknown")
            if failed_logins[user] >= threshold:
                alerts.append(
                    f"Repeated failed login attempts for user: {user}"
                )

        if "unauthorized access" in message:
            alerts.append("Unauthorized access attempt detected")

        if "permission denied" in message:
            alerts.append("Permission-denied event detected")

        if alerts:
            item["is_suspicious"] = True
            item["alerts"] = alerts
            item["severity"] = "HIGH"
        else:
            item["is_suspicious"] = False
            item["alerts"] = []
            item["severity"] = severity

        results.append(item)

    return results
