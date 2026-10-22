"""Operator-supplied login session (cookie header) for authenticated runs.

The cookie is never written into the run directory or the instruction file: it
lives in a 0600 file chosen by the operator and is copied into the sandbox at a
fixed path so the agent can use it without the value appearing in prompts/logs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

COOKIE_CONTAINER_PATH = "/tmp/.srcguard-cookie"


class SessionError(ValueError):
    """The session cookie file is missing or too permissive."""


def load_session_cookie(path: str | Path) -> str:
    """Read and validate a cookie header value (``name=value; name2=value2``)."""
    file = Path(path)
    if not file.is_file():
        raise SessionError(f"session cookie file not found: {file}")
    mode = file.stat().st_mode & 0o777
    if mode & 0o077:
        raise SessionError(
            f"session cookie file must be 0600 (chmod 600 {file}); current mode {oct(mode)}"
        )
    text = file.read_text(encoding="utf-8").strip()
    if not text:
        raise SessionError("session cookie file is empty")
    if "\n" in text or "\r" in text:
        raise SessionError("session cookie must be a single line")
    if len(text) > 8192:
        raise SessionError("session cookie is too large (limit 8 KiB)")
    return text


def copy_into_container(cid: str, path: str | Path, *, timeout: int = 20) -> None:
    """Copy the cookie into the sandbox and lock it down."""
    target = f"{cid}:{COOKIE_CONTAINER_PATH}"
    proc = subprocess.run(
        ["docker", "cp", str(path), target], capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        raise SessionError(f"docker cp failed: {(proc.stderr or proc.stdout).strip()[:200]}")
    subprocess.run(
        ["docker", "exec", cid, "chmod", "600", COOKIE_CONTAINER_PATH],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
