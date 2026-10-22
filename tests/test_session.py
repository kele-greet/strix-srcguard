from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from srcguard.secrets import redact
from srcguard.session import SessionError, load_session_cookie


class SessionCookieTests(unittest.TestCase):
    def test_accepts_0600_single_line_cookie(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cookie.txt"
            path.write_text("SESSION=abc123; uid=42", encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(load_session_cookie(path), "SESSION=abc123; uid=42")

    def test_rejects_group_or_world_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cookie.txt"
            path.write_text("SESSION=abc", encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaises(SessionError):
                load_session_cookie(path)

    def test_rejects_multiline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cookie.txt"
            path.write_text("SESSION=abc\nInjected: 1", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(SessionError):
                load_session_cookie(path)


class RedactionTests(unittest.TestCase):
    def test_cookie_and_authorization_are_masked(self) -> None:
        cmd = (
            "curl -H 'Cookie: SESSION=abc123' -H 'Authorization: Bearer tok' "
            "-b 'SESSION=zzz' https://example.com/"
        )
        out = redact(cmd)
        for secret in ("abc123", "Bearer tok", "SESSION=zzz"):
            self.assertNotIn(secret, out)
        self.assertIn("<redacted>", out)

    def test_plain_command_is_untouched(self) -> None:
        self.assertEqual(redact("curl https://example.com/"), "curl https://example.com/")


if __name__ == "__main__":
    unittest.main()
