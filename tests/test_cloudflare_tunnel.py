from __future__ import annotations

import unittest

from srcguard.cloudflare_tunnel import parse_tunnel_url


class TunnelParseTests(unittest.TestCase):
    def test_extracts_quick_tunnel_url(self) -> None:
        logs = "INF Your quick Tunnel has been created! https://abc-def.trycloudflare.com"
        self.assertEqual(parse_tunnel_url(logs), "https://abc-def.trycloudflare.com")

    def test_no_url(self) -> None:
        self.assertIsNone(parse_tunnel_url("still starting"))


if __name__ == "__main__":
    unittest.main()
