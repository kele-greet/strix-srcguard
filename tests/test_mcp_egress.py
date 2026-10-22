from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from srcguard.mcp_shim import _log_egress


class McpEgressTests(unittest.TestCase):
    def test_only_direct_curl_targets_are_logged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "egress.jsonl"
            old = os.environ.get("SRCGUARD_EGRESS_LOG")
            os.environ["SRCGUARD_EGRESS_LOG"] = str(out)
            try:
                _log_egress(
                    "curl -s 'http://172.17.0.1:4000/fetch?url=http://127.0.0.1:4000/internal/flag'; "
                    "curl http://172.17.0.1:4000/admin"
                )
            finally:
                if old is None:
                    os.environ.pop("SRCGUARD_EGRESS_LOG", None)
                else:
                    os.environ["SRCGUARD_EGRESS_LOG"] = old
            rows = [json.loads(line) for line in out.read_text().splitlines()]
            self.assertEqual([row["host"] for row in rows], ["172.17.0.1"])

    def test_proxy_url_is_not_a_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "egress.jsonl"
            old = os.environ.get("SRCGUARD_EGRESS_LOG")
            os.environ["SRCGUARD_EGRESS_LOG"] = str(out)
            try:
                _log_egress("curl -x http://proxy:8080 http://target.example/")
            finally:
                if old is None:
                    os.environ.pop("SRCGUARD_EGRESS_LOG", None)
                else:
                    os.environ["SRCGUARD_EGRESS_LOG"] = old
            hosts = [json.loads(line)["host"] for line in out.read_text().splitlines()]
            self.assertEqual(hosts, ["target.example"])


if __name__ == "__main__":
    unittest.main()
