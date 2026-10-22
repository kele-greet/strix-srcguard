from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from srcguard.dns_sync import DnsAnswer, DnsSync, dig_answer, sync_once


class FakeCage:
    def __init__(self) -> None:
        self.ips: list[str] = []
        self.removed: list[str] = []

    def allow_ip(self, ip: str) -> bool:
        if ip not in self.ips:
            self.ips.append(ip)
        return True

    def remove_ip(self, ip: str) -> bool:
        if ip in self.ips:
            self.ips.remove(ip)
        self.removed.append(ip)
        return True


class DigAnswerTests(unittest.TestCase):
    def test_parses_ttl_cname_a(self) -> None:
        from unittest import mock
        import subprocess

        class Proc:
            returncode = 0
            stdout = (
                "api.example.com. 300 IN CNAME edge.example.net.\n"
                "edge.example.net. 120 IN A 203.0.113.9\n"
            )

        with mock.patch("srcguard.dns_sync.subprocess.run", return_value=Proc()):
            answer = dig_answer("api.example.com", "172.17.0.1")
        self.assertEqual(answer.cnames, ["edge.example.net"])
        self.assertEqual(answer.ips, ["203.0.113.9"])
        self.assertEqual(answer.ttl, 120)


class DnsSyncTests(unittest.TestCase):
    def test_only_allowed_names_are_added_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns.jsonl"
            path.write_text(
                json.dumps({"qname": "api.example.com", "allowed": True}) + "\n"
                + json.dumps({"qname": "evil.test", "allowed": False}) + "\n",
                encoding="utf-8",
            )
            cage = FakeCage()
            seen: set[str] = set()
            offset = sync_once(path, offset=0, seen=seen, cage=cage, resolver=lambda _: ["203.0.113.9"])
            self.assertEqual(cage.ips, ["203.0.113.9"])
            sync_once(path, offset=offset, seen=seen, cage=cage, resolver=lambda _: ["203.0.113.10"])
            self.assertEqual(cage.ips, ["203.0.113.9"])

    def test_dns_token_becomes_oob_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns.jsonl"
            oob = Path(tmp) / "oob.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "qname": "abcdef0123456789.oob.example.net",
                        "allowed": True,
                        "client": "172.17.0.4",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            cage = FakeCage()
            sync_once(
                path,
                offset=0,
                seen=set(),
                cage=cage,
                resolver=lambda _: [],
                oob_path=oob,
                oob_domain="oob.example.net",
            )
            rows = [json.loads(line) for line in oob.read_text().splitlines()]
            self.assertEqual(rows[0]["token"], "abcdef0123456789")
            self.assertEqual(rows[0]["path"], "dns")
            self.assertEqual(rows[0]["remote"], "172.17.0.4")

    def test_refresh_withdraws_stale_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns.jsonl"
            path.write_text("", encoding="utf-8")
            cage = FakeCage()
            sync = DnsSync(
                path,
                cage,
                refresh_s=0.0,
                resolver=lambda _: ["1.1.1.1"],
            )
            sync.resolved = {"api.example.com": {"1.1.1.1", "2.2.2.2"}}
            cage.ips = ["1.1.1.1", "2.2.2.2"]
            sync.refresh()
            self.assertIn("1.1.1.1", cage.ips)
            self.assertNotIn("2.2.2.2", cage.ips)
            self.assertEqual(cage.removed, ["2.2.2.2"])

    def test_allowed_cidr_blocks_other_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns.jsonl"
            path.write_text(
                json.dumps({"qname": "api.example.com", "allowed": True}) + "\n",
                encoding="utf-8",
            )
            cage = FakeCage()
            sync_once(
                path,
                offset=0,
                seen=set(),
                cage=cage,
                resolver=lambda _: [],
                answer_resolver=lambda _: DnsAnswer(["203.0.113.9"], [], 30),
                allowed_cidrs=("10.0.0.0/8",),
            )
            self.assertEqual(cage.ips, [])

    def test_answer_ttl_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns.jsonl"
            path.write_text(
                json.dumps({"qname": "api.example.com", "allowed": True}) + "\n",
                encoding="utf-8",
            )
            cage = FakeCage()
            ttl: dict[str, int] = {}
            sync_once(
                path,
                offset=0,
                seen=set(),
                cage=cage,
                resolver=lambda _: [],
                answer_resolver=lambda _: DnsAnswer(["203.0.113.9"], [], 30),
                ttl_map=ttl,
            )
            self.assertEqual(cage.ips, ["203.0.113.9"])
            self.assertEqual(ttl["api.example.com"], 30)

    def test_cname_out_of_scope_blocks_ip_add(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns.jsonl"
            path.write_text(
                json.dumps({"qname": "api.example.com", "allowed": True}) + "\n",
                encoding="utf-8",
            )
            cage = FakeCage()
            sync_once(
                path,
                offset=0,
                seen=set(),
                cage=cage,
                resolver=lambda _: ["1.1.1.1"],
                cname_resolver=lambda _: ["internal.evil.test"],
                cname_allowed=lambda name: name == "api.example.com",
            )
            self.assertEqual(cage.ips, [])

    def test_thread_stop_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns.jsonl"
            path.write_text("", encoding="utf-8")
            sync = DnsSync(path, FakeCage(), interval_s=0.01)
            sync.start()
            sync.stop()
            sync.stop()


if __name__ == "__main__":
    unittest.main()
