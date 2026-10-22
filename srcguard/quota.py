"""P2-6: per-host new-connection quota backed by nft counters.

The cage adds a `counter` rule for every limited host. This watcher polls the
counters and trips the kill switch when a host exceeds its total quota. It is
post-hoc enforcement (not an nft drop), but the counter itself is in the kernel.
"""

from __future__ import annotations

import threading
import time
from typing import Any


def watch_host_quota(
    cage: Any,
    limits: dict[str, int],
    proc: Any,
    kill: Any,
    stop: threading.Event,
    *,
    interval_s: float = 1.0,
) -> str | None:
    while not stop.is_set():
        try:
            counters = cage.host_counters()
        except Exception:  # noqa: BLE001
            counters = {}
        for ip, limit in limits.items():
            if limit > 0 and counters.get(ip, 0) > limit:
                reason = f"host_request_quota:{ip}:{counters[ip]}>{limit}"
                kill.trip(reason, proc)
                return reason
        if proc.poll() is not None:
            return None
        stop.wait(interval_s)
    return None


def start_quota_watcher(
    cage: Any,
    limits: dict[str, int],
    proc: Any,
    kill: Any,
    stop: threading.Event,
    *,
    interval_s: float = 1.0,
) -> tuple[threading.Thread, list[str]]:
    reasons: list[str] = []

    def loop() -> None:
        reason = watch_host_quota(cage, limits, proc, kill, stop, interval_s=interval_s)
        if reason:
            reasons.append(reason)

    thread = threading.Thread(target=loop, name="srcguard-quota", daemon=True)
    thread.start()
    return thread, reasons
