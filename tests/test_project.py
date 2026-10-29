
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


if __name__ == "__main__":
    unittest.main()
