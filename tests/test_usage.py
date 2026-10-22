from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from srcguard.usage import aggregate_usage, build_usage, write_usage


class UsageTests(unittest.TestCase):
    def test_counts_commands_egress_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "commands.count").write_text("3", encoding="utf-8")
            (run / "audit" / "egress.jsonl").write_text(
                json.dumps({"host": "a.example", "decision": "allow"}) + "\n"
                + json.dumps({"host": "b.example", "decision": "block"}) + "\n",
                encoding="utf-8",
            )
            strix = run / "strix_runs" / "s1"
            strix.mkdir(parents=True)
            (strix / "run.json").write_text(
                json.dumps({"llm_usage": {"input_tokens": 10, "output_tokens": 2, "cost": 0.01}}),
                encoding="utf-8",
            )
            usage = build_usage(run, wall_s=12.345, container_ip="172.17.0.4")
            self.assertEqual(usage["commands"], 3)
            self.assertEqual(usage["egress_events"], 2)
            self.assertEqual(usage["egress_hosts"], ["a.example", "b.example"])
            self.assertEqual(usage["input_tokens"], 10)
            self.assertEqual(usage["wall_s"], 12.35)
            self.assertTrue(write_usage(run, wall_s=1.0).exists())
            base = Path(tmp)
            second = base / "run2"
            second.mkdir()
            write_usage(second, wall_s=2.0)
            agg = aggregate_usage(base)
            self.assertEqual(agg["totals"]["runs"], 2)
            self.assertEqual(agg["totals"]["wall_s"], 3.0)


if __name__ == "__main__":
    unittest.main()
