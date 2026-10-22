from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from srcguard.registry import RunRegistry


class RegistryTests(unittest.TestCase):
    def test_max_concurrent_and_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reg = RunRegistry(path=Path(tmp) / "runs.json")
            self.assertTrue(reg.acquire("a", 1))
            self.assertFalse(reg.acquire("b", 1))
            self.assertTrue(reg.acquire("a", 1))  # same run idempotent
            reg.release("a")
            self.assertTrue(reg.acquire("b", 1))

    def test_unlimited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reg = RunRegistry(path=Path(tmp) / "runs.json")
            self.assertTrue(reg.acquire("a", 0))
            self.assertTrue(reg.acquire("b", 0))

    def test_stale_pid_is_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runs.json"
            path.write_text('{"dead": {"pid": 999999, "ts": 1}}', encoding="utf-8")
            reg = RunRegistry(path=path)
            self.assertTrue(reg.acquire("new", 1))


if __name__ == "__main__":
    unittest.main()
