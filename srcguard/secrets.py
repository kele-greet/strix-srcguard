"""Redaction for credentials that must never reach logs or reports."""

from __future__ import annotations

import re

_HEADER_RE = re.compile(
    r"(?i)\b(cookie|authorization|proxy-authorization|set-cookie)\s*:\s*[^\"'\s]+"
)
_COOKIE_FLAG_RE = re.compile(r"(?i)(--cookie|-b)\s+['\"]?[^'\"\s]+")


def redact(text: str) -> str:
    """Mask Cookie/Authorization header values and -b/--cookie arguments."""
    if not text:
        return text
    out = _HEADER_RE.sub(lambda m: f"{m.group(1)}: <redacted>", text)
    return _COOKIE_FLAG_RE.sub(lambda m: f"{m.group(1)} <redacted>", out)
