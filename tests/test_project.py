
import unittest

from monitor.log_monitor import parse_log_line
from detection.detector import detect_security_events


class SecurityLoggerTests(unittest.TestCase):

    def test_parse_valid_log(self):
        event = parse_log_line(
            "2026-10-29 09:00:00 INFO System started"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["severity"], "INFO")

    def test_invalid_log_is_ignored(self):
        self.assertIsNone(parse_log_line("invalid log entry"))

    def test_repeated_failed_logins_are_detected(self):
        events = [
            {
                "timestamp": f"2026-10-29T09:05:{i * 10:02d}",
                "message": "Failed login attempt for user admin",
                "user": "admin",
                "severity": "WARNING",
            }
            for i in range(3)
        ]

        results = detect_security_events(events, threshold=3)

        self.assertEqual(len(results), 3)
        self.assertTrue(
            all(event["is_suspicious"] for event in results)
        )

    def test_normal_event_is_not_suspicious(self):
        events = [{
            "message": "System service running normally",
            "user": "unknown",
            "severity": "INFO",
        }]

        results = detect_security_events(events)
        self.assertFalse(results[0]["is_suspicious"])


    def test_unauthorized_access_is_detected(self):
        events = [{
            "message": "Unauthorized access attempt detected",
            "user": "unknown",
            "severity": "ERROR",
        }]

        results = detect_security_events(events)

        self.assertTrue(results[0]["is_suspicious"])
        self.assertIn(
            "Unauthorized access attempt detected",
            results[0]["alerts"],
        )
        self.assertEqual(results[0]["severity"], "HIGH")

    def test_permission_denied_is_detected(self):
        events = [{
            "message": "Permission denied while opening file",
            "user": "unknown",
            "severity": "ERROR",
        }]

        results = detect_security_events(events)

        self.assertTrue(results[0]["is_suspicious"])
        self.assertEqual(results[0]["severity"], "HIGH")

    def test_failed_logins_below_threshold_are_not_flagged(self):
        events = [
            {
                "message": "Failed login attempt for user admin",
                "user": "admin",
                "severity": "WARNING",
            },
            {
                "message": "Failed login attempt for user admin",
                "user": "admin",
                "severity": "WARNING",
            },
        ]

        results = detect_security_events(events, threshold=3)

        self.assertFalse(
            any(event["is_suspicious"] for event in results)
        )

if __name__ == "__main__":
    unittest.main()
