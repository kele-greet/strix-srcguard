from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from srcguard.mcp_shim import _sandbox_exec


class McpQuotaTests(unittest.TestCase):
    def test_quota_blocks_after_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            count = Path(tmp) / "commands.count"
            old = {key: os.environ.get(key) for key in ("SRCGUARD_MAX_COMMANDS", "SRCGUARD_COMMAND_COUNT", "STRIX_RUN_ID")}
            os.environ.update(
                {"SRCGUARD_MAX_COMMANDS": "1", "SRCGUARD_COMMAND_COUNT": str(count), "STRIX_RUN_ID": "x"}
            )
            try:
                first = _sandbox_exec("curl -X GET http://x/")
                second = _sandbox_exec("curl -X GET http://x/")
            finally:
                for key, value in old.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            self.assertIn("sandbox container not found", first)
            self.assertIn("command quota exceeded", second)
            self.assertEqual(count.read_text(), "2")


if __name__ == "__main__":
    unittest.main()
