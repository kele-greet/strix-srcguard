from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import httpx

from srcguard.cage import NftCage
from srcguard.oob import OobServer


class OobServerTests(unittest.TestCase):
    def test_http_callback_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = OobServer(run_dir=tmp, run_id="r1", bind_host="127.0.0.1", advertised_host="127.0.0.1")
            url = server.start()
            try:
                resp = httpx.get(url, timeout=5)
                self.assertEqual(resp.status_code, 200)
                self.assertTrue(server.wait(timeout=3))
                rows = (Path(tmp) / "audit" / "oob.jsonl").read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(rows), 1)
                self.assertEqual(json.loads(rows[0])["token"], server.token)
            finally:
                server.stop()


@unittest.skipUnless(shutil.which("docker"), "docker not installed")
class OobCageTests(unittest.TestCase):
    def test_cage_allows_oob_but_blocks_other_private(self) -> None:
        name = "srcguard-oob-test"
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        cid = subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", name, "alpine:3.20", "sleep", "30"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not cid:
            self.skipTest("docker run failed")
        time.sleep(0.8)
        with tempfile.TemporaryDirectory() as tmp:
            oob = OobServer(run_dir=tmp, run_id="oob", bind_host="0.0.0.0", advertised_host="127.0.0.1")
            oob.start()
            try:
                ip = subprocess.run(
                    ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid],
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                gateway = subprocess.run(
                    ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", cid],
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                self.assertTrue(ip and gateway)
                cage = NftCage.for_run("oob-test")
                try:
                    cage.install(["1.1.1.1"], [], oob4=[gateway])
                    cage.attach(ip)
                    ok = subprocess.run(
                        ["docker", "exec", cid, "wget", "-q", "-O", "-", f"http://{gateway}:{oob.port}/{oob.token}"],
                        capture_output=True,
                    )
                    blocked = subprocess.run(
                        ["docker", "exec", cid, "wget", "-q", "-O", "-", "-T", "2", "http://8.8.8.8/"],
                        capture_output=True,
                    )
                    self.assertEqual(ok.returncode, 0, ok.stderr[-200:])
                    self.assertNotEqual(blocked.returncode, 0)
                    self.assertTrue(oob.wait(timeout=3))
                finally:
                    cage.cleanup(ignore_missing=True)
            finally:
                oob.stop()
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)
