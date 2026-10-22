from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from srcguard.audit import build_audit, write_compliance
from srcguard.scope import compile_policy, load_scope, write_policy


class AuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.scope = self.base / "scope.yaml"
        self.scope.write_text(
            "program: x\nin_scope: ['*.example.com']\n"
            "oob:\n  mode: self_hosted\n  domain: oob.example.net\n",
            encoding="utf-8",
        )
        self.compiled = compile_policy(load_scope(self.scope))
        self.run = self.base / "srcguard_runs" / "r1"
        (self.run / "audit").mkdir(parents=True)
        (self.run / "run.json").write_text('{"run_id":"r1","status":"completed"}', encoding="utf-8")
        (self.run / "vulnerabilities.json").write_text(
            json.dumps(
                [
                    {
                        "id": "v1",
                        "title": "Example finding",
                        "description": "leaked AKIA1234567890ABCDEF",
                        "http_exchange_ids": ["r1", "r2"],
                    }
                ]
            ),
            encoding="utf-8",
        )
        (self.run / "audit" / "egress.jsonl").write_text(
            "\n".join(
                [
                    json.dumps({"host": "api.example.com", "decision": "allow"}),
                    json.dumps({"host": "evil.test", "decision": "deny"}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (self.run / "audit" / "caido.jsonl").write_text(
            "\n".join(
                [
                    json.dumps({"id": "r1", "host": "api.example.com"}),
                    json.dumps({"id": "r2", "host": "evil.test"}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        write_policy(self.run / "policy.json", self.compiled)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_flags_out_of_scope_evidence_and_secret(self) -> None:
        report = build_audit(self.run, self.compiled)
        self.assertEqual(report.status, "fail")
        self.assertTrue(report.policy_match)
        self.assertIn("evil.test", report.out_of_scope)
        self.assertIn("v1:r2:evil.test", report.evidence_issues)
        self.assertTrue(report.secret_hits)
        path = write_compliance(report)
        text = path.read_text(encoding="utf-8")
        self.assertIn("evil.test", text)
        self.assertIn("Residual risks", text)

    def test_browser_telemetry_is_ignored(self) -> None:
        (self.run / "audit" / "caido.jsonl").write_text(
            json.dumps({"id": "b1", "host": "clients2.google.com"}) + "\n",
            encoding="utf-8",
        )
        report = build_audit(self.run, self.compiled)
        self.assertNotIn("clients2.google.com", report.out_of_scope)
        self.assertTrue(any("browser telemetry ignored" in note for note in report.notes))

    def test_resolver_dns_is_not_contact(self) -> None:
        (self.run / "audit" / "egress.jsonl").write_text(
            json.dumps(
                {"ip": "10.255.255.254", "decision": "dns", "source": "nft", "port": 53}
            )
            + "\n",
            encoding="utf-8",
        )
        report = build_audit(self.run, self.compiled)
        self.assertNotIn("10.255.255.254", report.contacted)
        self.assertTrue(any("resolver DNS ignored" in note for note in report.notes))

    def test_write_requests_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "policy.json").write_text(
                json.dumps({"policy_hash": self.compiled.policy_hash}), encoding="utf-8"
            )
            (run / "audit" / "writes.jsonl").write_text(
                json.dumps(
                    {
                        "host": "api.example.com",
                        "method": "POST",
                        "path": "/login",
                        "status": 200,
                        "decision": "allowed",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            report = build_audit(run, self.compiled)
            self.assertEqual(len(report.writes), 1)
            self.assertEqual(report.writes[0]["method"], "POST")
            text = write_compliance(report, run / "compliance.md").read_text(encoding="utf-8")
            self.assertIn("POST api.example.com/login", text)

    def test_blocked_attempt_is_reported_not_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            (run / "audit").mkdir(parents=True)
            (run / "policy.json").write_text(
                json.dumps({"policy_hash": self.compiled.policy_hash}), encoding="utf-8"
            )
            (run / "audit" / "caido.jsonl").write_text(
                json.dumps({"id": "c1", "host": "cdn.third-party.test"}) + "\n",
                encoding="utf-8",
            )
            (run / "audit" / "blocked.jsonl").write_text(
                json.dumps({"host": "cdn.third-party.test", "ips": ["203.0.113.9"]}) + "\n",
                encoding="utf-8",
            )
            report = build_audit(run, self.compiled)
            self.assertNotIn("cdn.third-party.test", report.out_of_scope)
            self.assertIn("cdn.third-party.test", report.blocked_attempts)
            self.assertEqual(report.status, "warn")
            self.assertTrue(any("blocked attempts" in note for note in report.notes))

    def test_blocked_egress_is_not_contacted(self) -> None:
        (self.run / "audit" / "egress.jsonl").write_text(
            json.dumps({"ip": "10.255.255.254", "decision": "block", "port": 53})
            + "\n"
            + json.dumps({"host": "api.example.com", "decision": "allow"})
            + "\n",
            encoding="utf-8",
        )
        report = build_audit(self.run, self.compiled)
        self.assertNotIn("10.255.255.254", report.contacted)
        self.assertIn("api.example.com", report.contacted)

    def test_dns_and_method_events_are_reported(self) -> None:
        (self.run / "audit" / "dns.jsonl").write_text(
            json.dumps({"qname": "evil.test", "allowed": False}) + "\n"
            + json.dumps({"qname": "abcdef0123456789.oob.example.net", "allowed": True}) + "\n",
            encoding="utf-8",
        )
        (self.run / "audit" / "method.jsonl").write_text(
            json.dumps({"event": "method_blocked", "method": "DELETE", "cmd": "curl -X DELETE"})
            + "\n",
            encoding="utf-8",
        )
        report = build_audit(self.run, self.compiled)
        self.assertEqual(report.dns_blocked, ["evil.test"])
        self.assertIn("abcdef0123456789.oob.example.net", report.dns_oob)
        self.assertEqual(report.method_blocked[0]["method"], "DELETE")
        text = write_compliance(report).read_text(encoding="utf-8")
        self.assertIn("HTTP methods blocked", text)

    def test_srcguard_run_dir_with_nested_strix_run(self) -> None:
        nested = self.base / "outer"
        (nested / "audit").mkdir(parents=True)
        strix_run = nested / "strix_runs" / "scan-1"
        strix_run.mkdir(parents=True)
        (strix_run / "run.json").write_text('{"run_id":"scan-1","status":"completed"}', encoding="utf-8")
        (strix_run / "vulnerabilities.json").write_text("[]", encoding="utf-8")
        (nested / "audit" / "egress.jsonl").write_text(
            json.dumps({"host": "api.example.com"}) + "\n", encoding="utf-8"
        )
        write_policy(nested / "policy.json", self.compiled)
        report = build_audit(nested, self.compiled)
        self.assertEqual(report.contacted, ["api.example.com"])
        self.assertEqual(report.status, "pass")
        path = write_compliance(report)
        self.assertTrue(path.exists())

    def test_policy_mismatch_fails(self) -> None:
        other = self.base / "other.yaml"
        other.write_text("program: y\nin_scope: ['example.org']\n", encoding="utf-8")
        report = build_audit(self.run, compile_policy(load_scope(other)))
        self.assertFalse(report.policy_match)
        self.assertEqual(report.status, "fail")


if __name__ == "__main__":
    unittest.main()
