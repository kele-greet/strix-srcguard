from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from srcguard.cage import NftCage
from srcguard.egress import EgressCollector, parse_line


LOG = (
    "[123.456] srcguard-srcguard_run1-allow IN=eth0 OUT=br-1 MAC=aa:bb "
    "SRC=172.17.0.3 DST=1.1.1.1 LEN=60 PROTO=TCP SPT=40000 DPT=80 WINDOW=1024"
)


class EgressParseTests(unittest.TestCase):
    def test_parse_allow_with_host_map(self) -> None:
        event = parse_line(LOG, tag="srcguard_run1", ip_hosts={"1.1.1.1": "api.example.com"})
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.host, "api.example.com")
        self.assertEqual(event.ip, "1.1.1.1")
        self.assertEqual(event.decision, "allow")
        self.assertEqual(event.port, 80)

    def test_parse_rate_drop(self) -> None:
        line = LOG.replace("-allow", "-rate")
        event = parse_line(line, tag="srcguard_run1", ip_hosts={})
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.decision, "rate")

    def test_parse_resolver_dns(self) -> None:
        line = LOG.replace("-allow", "-dns").replace("DST=1.1.1.1", "DST=10.255.255.254")
        event = parse_line(line, tag="srcguard_run1", ip_hosts={})
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.decision, "dns")
        self.assertEqual(event.port, 80)

    def test_parse_wrong_tag_returns_none(self) -> None:
        self.assertIsNone(parse_line(LOG, tag="other", ip_hosts={}))


@unittest.skipUnless(shutil.which("docker"), "docker not installed")
class EgressIntegrationTests(unittest.TestCase):
    def test_collector_writes_allowed_event(self) -> None:
        name = "srcguard-egress-test"
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        cid = subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", name, "alpine:3.20", "sleep", "20"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not cid:
            self.skipTest("docker run failed")
        time.sleep(0.8)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "egress.jsonl"
            cage = NftCage.for_run("egress-test")
            ip = subprocess.run(
                ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid],
                capture_output=True,
                text=True,
            ).stdout.strip()
            collector = EgressCollector(tag=cage.table, out_path=out, ip_hosts={"172.17.0.1": "gateway"})
            try:
                cage.install(["172.17.0.1"], [], lab4=["172.17.0.1"])
                cage.attach(ip)
                collector.start()
                time.sleep(0.5)
                subprocess.run(
                    ["docker", "exec", cid, "ping", "-c1", "-W1", "172.17.0.1"],
                    capture_output=True,
                    timeout=15,
                )
                deadline = time.time() + 8.0
                text = ""
                while time.time() < deadline:
                    text = out.read_text(encoding="utf-8") if out.exists() else ""
                    if "172.17.0.1" in text:
                        break
                    time.sleep(0.5)
                self.assertIn("172.17.0.1", text)
                self.assertIn('"decision": "allow"', text)
            finally:
                collector.stop()
                cage.cleanup(ignore_missing=True)
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)


if __name__ == "__main__":
    unittest.main()
