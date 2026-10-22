from __future__ import annotations

import threading
import unittest

from srcguard.quota import watch_host_quota


class _Cage:
    def __init__(self, counters):
        self.counters = counters

    def host_counters(self):
        return self.counters


class _Proc:
    def poll(self):
        return None


class _Kill:
    def __init__(self):
        self.reasons = []

    def trip(self, reason, proc=None):
        self.reasons.append(reason)


class QuotaTests(unittest.TestCase):
    def test_trips_over_limit(self) -> None:
        kill = _Kill()
        stop = threading.Event()
        reason = watch_host_quota(
            _Cage({"1.1.1.1": 3}), {"1.1.1.1": 2}, _Proc(), kill, stop, interval_s=0
        )
        self.assertIn("host_request_quota:1.1.1.1:3>2", reason or "")
        self.assertEqual(kill.reasons, [reason])

    def test_below_limit_no_trip(self) -> None:
        kill = _Kill()
        stop = threading.Event()
        stop.set()
        self.assertIsNone(
            watch_host_quota(_Cage({"1.1.1.1": 2}), {"1.1.1.1": 2}, _Proc(), kill, stop, interval_s=0)
        )
        self.assertEqual(kill.reasons, [])


if __name__ == "__main__":
    unittest.main()
