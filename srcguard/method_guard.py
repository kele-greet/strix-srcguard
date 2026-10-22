"""Command-level method guard for the MCP sandbox channel.

This is defense-in-depth, not a network MITM: it catches the common
``curl -X DELETE`` / ``--request DELETE`` forms before ``docker exec``. A
determined shell can evade it; HTTPS method blocking still needs P2-2.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse

# -X DELETE, -XDELETE, --request DELETE, --request=DELETE, optional quotes
_METHOD_RE = re.compile(
    r"(?:^|\s)(?:-X|--request)(?:=|\s*)(?P<quote>['\"]?)(?P<method>[A-Za-z]+)(?P=quote)",
    re.IGNORECASE,
)
_WGET_RE = re.compile(
    r"--method(?:=|\s+)(?P<quote>['\"]?)(?P<method>[A-Za-z]+)(?P=quote)", re.IGNORECASE
)


def blocked_method(cmd: str, denied: set[str]) -> str | None:
    """Return the first denied HTTP method found in a shell command."""
    if not denied:
        return None
    upper_denied = {item.upper() for item in denied}
    for pattern in (_METHOD_RE, _WGET_RE):
        for match in pattern.finditer(cmd):
            method = match.group("method").upper()
            if method in upper_denied:
                return method
    return None


_POST_HINT_RE = re.compile(
    r"(?:^|\s)(?:-X|--request|--method)(?:=|\s*)(?P<quote>['\"]?)(?P<method>POST)(?P=quote)"
    r"|(?:^|\s)(?:--data|--data-raw|--data-binary|--data-urlencode|--form|-F|-d"
    r"|--post-data|--post-file|--body-data)(?:=|\s)",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 remove_dot_segments; empty segments from '//' are preserved."""
    output: list[str] = []
    while path:
        if path.startswith("../"):
            path = path[3:]
        elif path.startswith("./"):
            path = path[2:]
        elif path.startswith("/./"):
            path = "/" + path[3:]
        elif path == "/.":
            path = "/"
        elif path.startswith("/../"):
            path = "/" + path[4:]
            if output:
                output.pop()
        elif path == "/..":
            path = "/"
            if output:
                output.pop()
        elif path in (".", ".."):
            path = ""
        else:
            start = 1 if path.startswith("/") else 0
            index = path.find("/", start)
            if index == -1:
                output.append(path)
                path = ""
            else:
                output.append(path[:index])
                path = path[index:]
    return "".join(output)


def normalize_path(path: str) -> str:
    """Decode percent-escapes and resolve dot segments before policy checks.

    A server that normalises ``/allowed/../manage`` to ``/manage`` would see a
    write request even though the literal path started with the allowed prefix.
    """
    value = path or "/"
    for _ in range(3):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    if not value.startswith("/"):
        value = "/" + value
    return _remove_dot_segments(value)


def post_violation(
    cmd: str,
    *,
    mode: str = "allowlist",
    allow_paths: tuple[str, ...] | list[str] = (),
    deny_paths: tuple[str, ...] | list[str] = (),
    deny_keywords: tuple[str, ...] | list[str] = (),
) -> str | None:
    """Return a reason when a command sends POST outside the allowed paths.

    This is a command-level guard for the MCP shell channel: it inspects curl-like
    POST invocations (``-X POST``, ``--data``, ``-F`` ...) and requires every URL
    to sit under ``allow_paths`` and not under ``deny_paths``. It cannot see
    traffic a script generates internally, so the proxy-level monitor is the
    second line of defence.
    """
    if not allow_paths and not deny_paths and not deny_keywords:
        return None
    if not _POST_HINT_RE.search(cmd):
        return None
    urls = _URL_RE.findall(cmd)
    if not urls:
        return "POST with no inspectable URL"
    for url in urls:
        parsed = urlparse(url)
        path = normalize_path(parsed.path or "/")
        normalized_deny = [normalize_path(prefix) for prefix in deny_paths]
        normalized_allow = [normalize_path(prefix) for prefix in allow_paths]
        if any(path.startswith(prefix) for prefix in normalized_deny):
            return f"POST denied path {path}"
        low = path.lower()
        for word in deny_keywords:
            token = str(word).strip().lower()
            if token and token in low:
                return f"POST denied keyword {token!r} in {path}"
        if mode == "allowlist" and normalized_allow:
            if not any(path.startswith(prefix) for prefix in normalized_allow):
                return f"POST path not allowed {path}"
    return None
