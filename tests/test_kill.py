from __future__ import annotations

import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from srcguard.kill import KillSwitch


class KillTests(unittest.TestCase):
    def test_trip_terminates_process_and_writes_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            proc = subprocess.Popen(["sleep", "30"], start_new_session=True)
            try:
                switch = KillSwitch(run_dir=run_dir, run_id="kill-test")
                path = switch.trip("unit test", proc)
                self.assertTrue(switch.triggered)
                self.assertTrue(path.exists())
                self.assertEqual(proc.poll() is not None, True)
                record = path.read_text(encoding="utf-8")
                self.assertIn("unit test", record)
            finally:
                if proc.poll() is None:
                    proc.kill()


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(__import__("shutil").which("docker"), "docker not installed")
class MonitorTests(unittest.TestCase):
    def test_monitor_trips_on_out_of_scope_contact(self) -> None:
        import json
        import tempfile
        from pathlib import Path

        from srcguard.monitor import start_monitor
        from srcguard.scope import compile_policy, load_scope

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['*.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            run_dir = base / "run"
            (run_dir / "audit").mkdir(parents=True)
            (run_dir / "audit" / "caido.jsonl").write_text(
                json.dumps({"id": "r1", "host": "evil.test"}) + "\n", encoding="utf-8"
            )
            proc = subprocess.Popen(["sleep", "30"], start_new_session=True)
            stop = __import__("threading").Event()
            try:
                switch = KillSwitch(run_dir=run_dir, run_id="monitor-test")
                thread, reasons = start_monitor(run_dir, compiled, proc, switch, stop)
                thread.join(timeout=3)
                stop.set()
                self.assertTrue(switch.triggered)
                self.assertTrue(reasons and "evil.test" in reasons[0])
                self.assertIsNotNone(proc.poll())
            finally:
                if proc.poll() is None:
                    proc.kill()


@unittest.skipUnless(__import__("shutil").which("docker"), "docker not installed")
class RateMonitorTests(unittest.TestCase):
    def test_monitor_trips_on_rate_exceeded(self) -> None:
        import json
        import tempfile
        import threading
        from pathlib import Path

        from srcguard.monitor import start_monitor
        from srcguard.rate import HostRateLimiter
        from srcguard.scope import compile_policy, load_scope

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['*.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            run_dir = base / "run"
            (run_dir / "audit").mkdir(parents=True)
            rows = [
                json.dumps({"id": f"r{i}", "host": "api.example.com"}) for i in range(6)
            ]
            (run_dir / "audit" / "caido.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
            proc = subprocess.Popen(["sleep", "30"], start_new_session=True)
            stop = threading.Event()
            try:
                limiter = HostRateLimiter(
                    default_rps=1,
                    window_s=1,
                    tolerance=1,
                    violations_window_s=0,
                    max_violations=2,
                )
                switch = KillSwitch(run_dir=run_dir, run_id="rate-test")
                thread, reasons = start_monitor(run_dir, compiled, proc, switch, stop, limiter=limiter)
                thread.join(timeout=3)
                stop.set()
                self.assertTrue(switch.triggered)
                self.assertTrue(reasons and "rate_exceeded" in reasons[0])
                self.assertIsNotNone(proc.poll())
            finally:
                if proc.poll() is None:
                    proc.kill()
