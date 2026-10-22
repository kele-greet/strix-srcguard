"""P1-F7: per-host token bucket + global new-connection cap."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Bucket:
    capacity: float
    refill_per_s: float
    tokens: float
    updated: float

    def take(self, now: float, cost: float = 1.0) -> bool:
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_s)
        self.updated = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


@dataclass
class HostRateLimiter:
    """Host rate limit judged over a sliding window, not per request.

    A browser loading one page fires dozens of requests in a second; judged one
    request at a time that looks like abuse, even when the sustained rate is far
    below the limit. The limiter therefore compares the request count in the last
    ``window_s`` seconds against ``default_rps * window_s * tolerance`` and only
    records a violation when that window stays over budget.
    """

    default_rps: float = 5.0
    burst_rps: float = 50.0
    window_s: float = 60.0
    tolerance: float = 1.5
    violations_window_s: float = 10.0
    buckets: dict[str, Bucket] = field(default_factory=dict)
    hits: dict[str, list[float]] = field(default_factory=dict)
    violations: dict[str, int] = field(default_factory=dict)
    last_violation: dict[str, float] = field(default_factory=dict)
    blocked_counts: dict[str, int] = field(default_factory=dict)
    blocked_hits: dict[str, list[float]] = field(default_factory=dict)
    blocked_window_s: float = 60.0
    max_violations: int = 3
    max_blocked: int = 5
    log_path: Path | None = None

    def _bucket(self, host: str, now: float) -> Bucket:
        bucket = self.buckets.get(host)
        if bucket is None:
            bucket = Bucket(
                capacity=max(1.0, self.burst_rps),
                refill_per_s=max(0.1, self.default_rps),
                tokens=max(1.0, self.burst_rps),
                updated=now,
            )
            self.buckets[host] = bucket
        return bucket

    def _write(self, row: dict) -> None:
        if self.log_path is None:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def check(self, host: str, *, now: float | None = None, status: int | None = None) -> str | None:
        """Return a kill reason when the host exceeded the limit, else None."""
        now = time.time() if now is None else now
        if status in {403, 429}:
            # "Consecutive" blocks: a few 403s spread over the scan (WAF rejecting
            # individual probes) must not stop the run; a burst within the window
            # does.
            hits = self.blocked_hits.setdefault(host, [])
            hits.append(now)
            cutoff = now - self.blocked_window_s
            hits[:] = [stamp for stamp in hits if stamp >= cutoff]
            self.blocked_counts[host] = len(hits)
            self._write(
                {"host": host, "event": "blocked", "status": status, "count": len(hits), "ts": now}
            )
            if len(hits) >= self.max_blocked:
                return f"repeated_{status}:{host}"
            return None
        hits = self.hits.setdefault(host, [])
        hits.append(now)
        cutoff = now - self.window_s
        hits[:] = [stamp for stamp in hits if stamp >= cutoff]
        budget = self.default_rps * self.window_s * self.tolerance
        if len(hits) <= budget:
            return None
        last = self.last_violation.get(host)
        if last is not None and now - last < self.violations_window_s:
            return None
        self.last_violation[host] = now
        self.violations[host] = self.violations.get(host, 0) + 1
        self._write(
            {
                "host": host,
                "event": "rate_exceeded",
                "count": self.violations[host],
                "requests": len(hits),
                "window_s": self.window_s,
                "ts": now,
            }
        )
        if self.violations[host] >= self.max_violations:
            return f"rate_exceeded:{host}"
        return None


def global_new_connection_rate(default_rps: int, burst_rps: int) -> tuple[int, int]:
    """A coarse global cap for all sandbox egress (per container)."""
    rate = max(default_rps * 10, burst_rps)
    burst = max(rate * 2, burst_rps)
    return rate, burst
