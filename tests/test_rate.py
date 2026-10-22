from __future__ import annotations

import unittest

from srcguard.rate import Bucket, HostRateLimiter, global_new_connection_rate


class RateTests(unittest.TestCase):
    def test_bucket_refill(self) -> None:
        bucket = Bucket(capacity=2, refill_per_s=1, tokens=2, updated=0)
        self.assertTrue(bucket.take(0))
        self.assertTrue(bucket.take(0))
        self.assertFalse(bucket.take(0))
        self.assertTrue(bucket.take(1.0))

    def test_hosts_are_isolated(self) -> None:
        limiter = HostRateLimiter(
            default_rps=1, window_s=10, tolerance=1, violations_window_s=1, max_violations=10
        )
        for _ in range(8):
            self.assertIsNone(limiter.check("b.test", now=0))
        self.assertEqual(limiter.violations.get("b.test", 0), 0)
        for _ in range(12):
            limiter.check("a.test", now=0)
        self.assertEqual(limiter.violations["a.test"], 1)

    def test_page_load_burst_is_not_abuse(self) -> None:
        limiter = HostRateLimiter(default_rps=2, window_s=60, tolerance=1.5, max_violations=3)
        for i in range(52):  # one page load
            self.assertIsNone(limiter.check("a.test", now=float(i) / 50))
        # ... followed by a polite trickle, well inside 2 rps sustained.
        for i in range(40):
            self.assertIsNone(limiter.check("a.test", now=2.0 + i * 1.2))
        self.assertEqual(limiter.violations.get("a.test", 0), 0)

    def test_sustained_rate_still_trips(self) -> None:
        limiter = HostRateLimiter(default_rps=2, window_s=10, tolerance=1.5, violations_window_s=1)
        reason = None
        for i in range(200):
            reason = limiter.check("a.test", now=i * 0.1)  # 10 rps for 20s
            if reason:
                break
        self.assertEqual(reason, "rate_exceeded:a.test")

    def test_same_path_repeated_403_kills(self) -> None:
        limiter = HostRateLimiter(max_blocked=99, blocked_same_path=3)
        for _ in range(2):
            self.assertIsNone(limiter.check("a.test", status=403, path="/api/x"))
        self.assertEqual(
            limiter.check("a.test", status=403, path="/api/x"), "repeated_403:a.test:/api/x"
        )

    def test_scattered_403s_only_slow_down(self) -> None:
        limiter = HostRateLimiter(max_blocked=99, blocked_same_path=8)
        for i in range(5):
            self.assertIsNone(limiter.check("a.test", status=403, path=f"/p{i}"))
        self.assertGreaterEqual(limiter.slow_down, 5)

    def test_homepage_403_is_a_ban(self) -> None:
        limiter = HostRateLimiter()
        self.assertEqual(limiter.check("a.test", status=403, path="/"), "waf_banned:a.test")
        self.assertEqual(limiter.check("a.test", status=429, path="/index.html"), "waf_banned:a.test")

    def test_path_window_expires(self) -> None:
        limiter = HostRateLimiter(blocked_same_path=3, blocked_paths_window_s=10, max_blocked=99)
        self.assertIsNone(limiter.check("a.test", status=403, path="/x", now=0))
        self.assertIsNone(limiter.check("a.test", status=403, path="/x", now=5))
        self.assertIsNone(limiter.check("a.test", status=403, path="/x", now=50))
        self.assertIsNone(limiter.check("a.test", status=403, path="/x", now=51))

    def test_global_threshold_still_backstops(self) -> None:
        limiter = HostRateLimiter(max_blocked=5, blocked_same_path=99)
        for i in range(4):
            self.assertIsNone(limiter.check("a.test", status=403, path=f"/p{i}"))
        self.assertEqual(limiter.check("a.test", status=403, path="/p4"), "repeated_403:a.test")

    def test_spread_out_403s_do_not_stop_the_run(self) -> None:
        limiter = HostRateLimiter(max_blocked=5, blocked_window_s=60)
        for index, minute in enumerate((0, 30, 60, 120, 130)):
            self.assertIsNone(
                limiter.check("a.test", now=minute, status=403, path=f"/p{index}")
            )
        # A burst inside one minute still stops it.
        for i in range(5):
            limiter.check("b.test", now=1000 + i, status=403, path=f"/p{i}")
        self.assertEqual(
            limiter.check("b.test", now=1005, status=403, path="/p5"), "repeated_403:b.test"
        )

    def test_global_cap(self) -> None:
        self.assertEqual(global_new_connection_rate(5, 50), (50, 100))


if __name__ == "__main__":
    unittest.main()
