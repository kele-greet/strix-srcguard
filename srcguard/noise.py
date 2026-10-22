"""Known browser background/telemetry hosts that are not target testing.

Chromium in the sandbox phones home (component updates, account list, safe
browsing). Those requests are out of scope but are infrastructure noise, not
the operator testing another target. They are recorded, not killed.
"""

from __future__ import annotations

BROWSER_TELEMETRY_HOSTS = {
    "clients2.google.com",
    "clients4.google.com",
    "accounts.google.com",
    "www.google.com",
    "www.gstatic.com",
    "ssl.gstatic.com",
    "optimizationguide-pa.googleapis.com",
    "play.googleapis.com",
    "update.googleapis.com",
    "safebrowsing.googleapis.com",
    "content-autofill.googleapis.com",
}


def is_browser_telemetry(host: str) -> bool:
    value = (host or "").strip().lower().rstrip(".")
    return any(value == item or value.endswith("." + item) for item in BROWSER_TELEMETRY_HOSTS)
