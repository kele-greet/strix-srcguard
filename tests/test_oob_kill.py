from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from srcguard.monitor import watch
from srcguard.scope import compile_policy, load_scope


class _Proc:
    def poll(self):
        return None


class _Kill:
    def __init__(self):
        self.reasons = []

    def trip(self, reason, proc=None):
        self.reasons.append(reason)


def _watch(run, compiled, kill, **kwargs):
    """Run one monitor pass: a timer stops the loop after the rows are processed."""
    stop = threading.Event()
    threading.Timer(0.05, stop.set).start()
    kwargs.setdefault("interval_s", 0.01)
    return watch(run, compiled, _Proc(), kill, stop, **kwargs)


class OobKillTests(unittest.TestCase):
    def test_kill_on_oob_callback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "oob.jsonl").write_text(
                json.dumps({"token": "abc123", "path": "/abc123", "ts": 1.0}) + "\n",
                encoding="utf-8",
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            reason = watch(
                run,
                compiled,
                _Proc(),
                kill,
                threading.Event(),
                interval_s=0,
                kill_on_oob=True,
            )
            self.assertEqual(reason, "oob_callback:abc123")
            self.assertEqual(kill.reasons, [reason])

    def test_allowed_resolver_dns_does_not_kill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "egress.jsonl").write_text(
                json.dumps(
                    {
                        "ip": "10.255.255.254",
                        "host": "",
                        "decision": "dns",
                        "source": "nft",
                        "port": 53,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            self.assertIsNone(_watch(run, compiled, kill))
            self.assertEqual(kill.reasons, [])

    def test_egress_packets_do_not_trip_the_rate_limiter(self) -> None:
        from srcguard.rate import HostRateLimiter

        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            rows = [
                {"ip": "93.184.216.34", "host": "api.example.com", "decision": "allow", "port": 443}
                for _ in range(10)
            ]
            (run / "audit" / "egress.jsonl").write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            limiter = HostRateLimiter(default_rps=1, burst_rps=1, max_violations=2)
            self.assertIsNone(_watch(run, compiled, kill, limiter=limiter))
            self.assertEqual(kill.reasons, [])
            self.assertEqual(limiter.violations, {})

    def test_caido_requests_still_trip_the_rate_limiter(self) -> None:
        from srcguard.rate import HostRateLimiter

        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            base = 1_700_000_000_000
            rows = [
                {"id": str(i), "host": "api.example.com", "method": "GET", "createdAt": base + i * 100}
                for i in range(60)
            ]
            (run / "audit" / "caido.jsonl").write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            limiter = HostRateLimiter(
                default_rps=2, window_s=10, tolerance=1.5, violations_window_s=1
            )
            reason = _watch(run, compiled, kill, limiter=limiter)
            self.assertEqual(reason, "rate_exceeded:api.example.com")

    def test_out_of_scope_attempt_blocked_by_cage_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "caido.jsonl").write_text(
                json.dumps({"id": "b1", "host": "localhost"}) + "\n", encoding="utf-8"
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            self.assertIsNone(
                _watch(run, compiled, kill, allowed_ips={"93.184.216.34"})
            )
            self.assertEqual(kill.reasons, [])
            rows = [
                json.loads(line)
                for line in (run / "audit" / "blocked.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[0]["host"], "localhost")
            self.assertIn("127.0.0.1", rows[0]["ips"])

    def test_unresolvable_out_of_scope_host_is_blocked_not_killed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "caido.jsonl").write_text(
                json.dumps({"id": "b1", "host": "burpsuite"}) + "\n", encoding="utf-8"
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            self.assertIsNone(_watch(run, compiled, kill, allowed_ips={"93.184.216.34"}))
            self.assertEqual(kill.reasons, [])
            rows = [
                json.loads(line)
                for line in (run / "audit" / "blocked.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[0]["host"], "burpsuite")

    def test_out_of_scope_host_reachable_inside_allow_set_still_kills(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "caido.jsonl").write_text(
                json.dumps({"id": "b1", "host": "localhost"}) + "\n", encoding="utf-8"
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            reason = _watch(run, compiled, kill, allowed_ips={"127.0.0.1", "10.0.0.0/8"})
            self.assertEqual(reason, "out_of_scope_contact:localhost")

    def test_late_backlog_is_charged_to_request_time(self) -> None:
        """A slow observer must not charge a whole backlog to 'now'."""
        from srcguard.rate import HostRateLimiter

        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            base = 1_700_000_000_000  # ms
            rows = [
                {"id": str(i), "host": "api.example.com", "createdAt": base + i * 1000}
                for i in range(20)
            ]
            (run / "audit" / "caido.jsonl").write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            limiter = HostRateLimiter(default_rps=2, burst_rps=10, max_violations=5)
            # 20 requests, one per second, never exceed 2 rps: no kill.
            self.assertIsNone(_watch(run, compiled, kill, limiter=limiter))
            self.assertEqual(kill.reasons, [])

    def test_post_to_allowed_path_is_fine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "caido.jsonl").write_text(
                json.dumps(
                    {
                        "id": "p1",
                        "host": "api.example.com",
                        "method": "POST",
                        "path": "/search/queryPage",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            self.assertIsNone(
                _watch(run, compiled, kill, post_mode="allowlist", post_allow_paths=("/search/",))
            )
            self.assertEqual(kill.reasons, [])

    def test_post_to_other_path_is_killed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "caido.jsonl").write_text(
                json.dumps(
                    {"id": "p1", "host": "api.example.com", "method": "POST", "path": "/admin/save"}
                )
                + "\n",
                encoding="utf-8",
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            reason = _watch(run, compiled, kill, post_mode="allowlist", post_allow_paths=("/search/",))
            self.assertEqual(reason, "post_blocked:/admin/save")

    def test_open_mode_allows_any_post_and_records_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "caido.jsonl").write_text(
                json.dumps(
                    {"id": "p1", "host": "api.example.com", "method": "POST", "path": "/login"}
                )
                + "\n",
                encoding="utf-8",
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            self.assertIsNone(_watch(run, compiled, kill, post_mode="open"))
            self.assertEqual(kill.reasons, [])
            rows = [
                json.loads(line)
                for line in (run / "audit" / "writes.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(rows[0]["decision"], "allowed")
            self.assertEqual(rows[0]["path"], "/login")

    def test_destructive_path_is_killed_in_open_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "caido.jsonl").write_text(
                json.dumps(
                    {"id": "p1", "host": "api.example.com", "method": "POST", "path": "/api/user/delete"}
                )
                + "\n",
                encoding="utf-8",
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            reason = _watch(
                run, compiled, kill, post_mode="open", post_deny_keywords=("delete",)
            )
            self.assertEqual(reason, "post_blocked:/api/user/delete")

    def test_denied_method_is_killed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "caido.jsonl").write_text(
                json.dumps(
                    {"id": "d1", "host": "api.example.com", "method": "DELETE", "path": "/x/1"}
                )
                + "\n",
                encoding="utf-8",
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            reason = _watch(run, compiled, kill, deny_methods=("DELETE", "PUT"))
            self.assertEqual(reason, "denied_method:DELETE:/x/1")

    def test_blocked_egress_does_not_kill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "egress.jsonl").write_text(
                json.dumps({"ip": "10.255.255.254", "decision": "block", "port": 53}) + "\n",
                encoding="utf-8",
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            self.assertIsNone(_watch(run, compiled, kill))
            self.assertEqual(kill.reasons, [])

    def test_browser_telemetry_does_not_kill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "caido.jsonl").write_text(
                json.dumps({"id": "b1", "host": "clients2.google.com"}) + "\n",
                encoding="utf-8",
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            self.assertIsNone(_watch(run, compiled, kill))
            self.assertEqual(kill.reasons, [])

    def test_default_does_not_kill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "audit" / "oob.jsonl").write_text(
                json.dumps({"token": "abc123", "path": "/abc123", "ts": 1.0}) + "\n",
                encoding="utf-8",
            )
            scope = Path(tmp) / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['api.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            kill = _Kill()
            self.assertIsNone(_watch(run, compiled, kill, kill_on_oob=False))
            self.assertEqual(kill.reasons, [])


if __name__ == "__main__":
    unittest.main()
