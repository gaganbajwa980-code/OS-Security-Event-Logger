
from collections import Counter


def detect_security_events(events, threshold=3):
    """
    Detect repeated failed logins and suspicious access events.
    Return a new list containing detection results.
    """
    failed_logins = Counter()
    results = []

    # Count failed login attempts for each user.
    for event in events:
        message = event.get("message", "").lower()

        if "failed login" in message or "failed log in" in message:
            user = event.get("user", "unknown")
            failed_logins[user] += 1

    # Analyze every event.
    for event in events:
        item = event.copy()
        message = item.get("message", "").lower()
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

        item["is_suspicious"] = bool(alerts)
        item["alerts"] = alerts

        if alerts:
            item["severity"] = "HIGH"

        results.append(item)

    return results
