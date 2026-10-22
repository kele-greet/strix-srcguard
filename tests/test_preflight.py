from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from srcguard import cli
from srcguard.preflight import PreflightError, _private_targets, prepare_resume, prepare_run
from srcguard.scope import compile_policy, load_scope


SCOPE = """
program: test
in_scope: ["*.example.com", "api.example.com"]
out_of_scope: ["internal.example.com"]
allow_spec_hosts: true
ssrf_probe:
  mode: limited
  max_requests: 3
  methods: [GET]
  metadata_paths: ["/latest/meta-data/"]
  denied_paths: ["/latest/meta-data/iam/"]
methods:
  deny: [DELETE]
  allow: [GET, HEAD, POST, PUT, PATCH]
rate:
  default_rps: 5
  burst_rps: 50
oob:
  mode: self_hosted
  domain: oob.example.net
budgets:
  max_turns: 120
  max_budget_usd: 15
web_search:
  enabled: false
"""


class PreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.scope = self.base / "scope.yaml"
        self.scope.write_text(SCOPE, encoding="utf-8")
        self.compiled = compile_policy(load_scope(self.scope))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_allowed_target_and_instruction(self) -> None:
        spec = prepare_run(
            self.compiled,
            ["https://api.example.com"],
            base_dir=self.base / "runs",
            run_id="r1",
            gateway_base="http://127.0.0.1:8787/v1",
        )
        self.assertIn("-t", spec.argv)
        self.assertIn("--instruction-file", spec.argv)
        self.assertIn("--scan-mode", spec.argv)
        self.assertIn("quick", spec.argv)
        self.assertEqual(spec.env["STRIX_RUN_ID"], "r1")
        self.assertEqual(spec.env["STRIX_API_TYPE"], "chat_completions")
        self.assertEqual(spec.env["LLM_API_BASE"], "http://127.0.0.1:8787/v1")
        self.assertEqual(spec.env["STRIX_TELEMETRY"], "false")
        self.assertEqual(spec.env["PERPLEXITY_API_KEY"], "")
        text = spec.instruction_path.read_text(encoding="utf-8")
        self.assertIn("api.example.com", text)
        self.assertIn("DELETE", text)
        self.assertIn("子 agent", text)
        self.assertIn("3", text)  # ssrf max requests
        self.assertTrue(spec.policy_path.exists())
        self.assertIsNotNone(spec.mcp_config_path)
        assert spec.mcp_config_path is not None
        self.assertIn("--mcp-config", spec.argv)
        config = json.loads(spec.mcp_config_path.read_text(encoding="utf-8"))
        self.assertEqual(config[0]["name"], "srcguard")
        self.assertEqual(config[0]["env"]["STRIX_RUN_ID"], "r1")

    def test_out_of_scope_rejected(self) -> None:
        with self.assertRaises(PreflightError):
            prepare_run(self.compiled, ["https://evil.test"], base_dir=self.base / "runs")

    def test_local_path_rejected(self) -> None:
        with self.assertRaises(PreflightError):
            prepare_run(self.compiled, ["./repo"], base_dir=self.base / "runs")

    def test_deep_requires_flag(self) -> None:
        with self.assertRaises(PreflightError):
            prepare_run(
                self.compiled,
                ["https://api.example.com"],
                scan_mode="deep",
                base_dir=self.base / "runs",
            )
        spec = prepare_run(
            self.compiled,
            ["https://api.example.com"],
            scan_mode="deep",
            allow_deep=True,
            base_dir=self.base / "runs",
        )
        self.assertIn("deep", spec.argv)

    def test_mcp_preserves_real_docker_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['1.1.1.1']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            old = os.environ.get("DOCKER_HOST")
            os.environ["DOCKER_HOST"] = "tcp://remote-docker:2375"
            try:
                spec = prepare_run(
                    compiled, ["https://1.1.1.1"], base_dir=base / "runs", run_id="dockerhost"
                )
            finally:
                if old is None:
                    os.environ.pop("DOCKER_HOST", None)
                else:
                    os.environ["DOCKER_HOST"] = old
            config = json.loads((spec.run_dir / "mcp-servers.json").read_text(encoding="utf-8"))[0]
            self.assertEqual(config["env"]["DOCKER_HOST"], "tcp://remote-docker:2375")

    def test_max_commands_is_written_into_mcp_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['1.1.1.1']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            spec = prepare_run(
                compiled,
                ["https://1.1.1.1"],
                base_dir=base / "runs",
                run_id="quota",
                max_commands=7,
            )
            config = json.loads((spec.run_dir / "mcp-servers.json").read_text(encoding="utf-8"))[0]
            self.assertEqual(config["env"]["SRCGUARD_MAX_COMMANDS"], "7")
            self.assertIn("commands.count", config["env"]["SRCGUARD_COMMAND_COUNT"])

    def test_private_targets_bypass_caido(self) -> None:
        self.assertEqual(_private_targets(["http://172.17.0.1:3000/"]), ["172.17.0.1"])
        self.assertEqual(_private_targets(["https://api.example.com/"]), [])

    def test_no_mcp_disables_config(self) -> None:
        spec = prepare_run(
            self.compiled,
            ["https://api.example.com"],
            base_dir=self.base / "runs",
            mcp=False,
        )
        self.assertIsNone(spec.mcp_config_path)
        self.assertNotIn("--mcp-config", spec.argv)

    def test_web_search_switch(self) -> None:
        spec = prepare_run(
            self.compiled,
            ["https://api.example.com"],
            allow_web_search=True,
            base_dir=self.base / "runs",
        )
        self.assertNotIn("PERPLEXITY_API_KEY", spec.env)
        self.assertNotIn("EXA_API_KEY", spec.env)

    def test_target_list_and_conflicting_args(self) -> None:
        targets = self.base / "targets.txt"
        targets.write_text("# comment\nhttps://api.example.com\n", encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(
                [
                    "run",
                    "--scope",
                    str(self.scope),
                    "--target-list",
                    str(targets),
                    "--dry-run",
                    "--out-dir",
                    str(self.base / "runs"),
                    "--json",
                    "--",
                    "-t",
                    "https://api.example.com",
                    "--scan-mode",
                    "deep",
                ]
            )
        self.assertEqual(rc, 0)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["targets"], ["https://api.example.com"])
        self.assertEqual(doc["targets"], ["https://api.example.com"])
        self.assertIn("quick", doc["argv"])
        self.assertNotIn("deep", doc["argv"])  # SRCGuard owns scan mode; trailing deep is dropped


if __name__ == "__main__":
    unittest.main()


class OobResolutionTests(unittest.TestCase):
    def _compiled(self, oob: str):
        import tempfile
        from pathlib import Path

        from srcguard.scope import compile_policy, load_scope

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.yaml"
            path.write_text(
                "program: p\nin_scope: ['www.example.com']\n" + oob, encoding="utf-8"
            )
            return compile_policy(load_scope(path))

    def test_scope_http_public_turns_oob_on(self) -> None:
        from srcguard.preflight import resolve_oob

        compiled = self._compiled("oob:\n  mode: http\n  public: true\n")
        host, domain, public = resolve_oob(compiled)
        self.assertEqual(host, "127.0.0.1")
        self.assertTrue(public)

    def test_scope_off_keeps_oob_disabled(self) -> None:
        from srcguard.preflight import resolve_oob

        compiled = self._compiled("oob:\n  mode: off\n")
        host, _, public = resolve_oob(compiled)
        self.assertIsNone(host)
        self.assertFalse(public)

    def test_cli_flags_win(self) -> None:
        from srcguard.preflight import resolve_oob

        compiled = self._compiled("oob:\n  mode: off\n")
        host, domain, public = resolve_oob(
            compiled, host="192.0.2.5", domain="oob.test", public=True
        )
        self.assertEqual(host, "192.0.2.5")
        self.assertEqual(domain, "oob.test")
        self.assertTrue(public)


class ResumeTests(unittest.TestCase):
    def _fake_run(self, base, run_id, compiled, *, with_state=True, policy_hash=None):
        root = base / run_id
        (root / "strix_runs" / "www-example" / ".state").mkdir(parents=True)
        (root / "policy.json").write_text(
            json.dumps({"policy_hash": policy_hash or compiled.policy_hash}), encoding="utf-8"
        )
        (root / "instruction.md").write_text("RULES", encoding="utf-8")
        (root / "strix_runs" / "www-example" / "run.json").write_text(
            json.dumps({"targets_info": [{"original": "https://www.example.com/"}]}),
            encoding="utf-8",
        )
        if with_state:
            (root / "strix_runs" / "www-example" / ".state" / "agents.json").write_text("{}", encoding="utf-8")
        return root

    def test_resume_builds_strix_resume_argv(self) -> None:
        from srcguard.preflight import prepare_resume

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text("program: p\nin_scope: ['www.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            root = self._fake_run(base / "runs", "r1", compiled)
            spec = prepare_resume(compiled, resume_run_id="r1", base_dir=base / "runs")
            self.assertEqual(spec.run_dir, root)
            self.assertIn("--resume", spec.argv)
            self.assertEqual(spec.argv[spec.argv.index("--resume") + 1], "www-example")
            self.assertNotIn("-t", spec.argv)
            self.assertEqual(spec.env["STRIX_RUN_ID"], "r1")

    def test_budget_model_sets_accounting_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text("program: p\nin_scope: ['*.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            spec = prepare_run(
                compiled,
                ["https://api.example.com"],
                base_dir=base / "runs",
                budget_model="openai/gpt-4o-mini",
            )
            self.assertEqual(spec.env["STRIX_LLM"], "openai/gpt-4o-mini")
            self.assertTrue(any("budget accounting model" in w for w in spec.warnings))

    def test_resume_finds_run_under_program_subdir(self) -> None:
        from srcguard.preflight import prepare_resume

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text("program: p\nin_scope: ['www.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            root = self._fake_run(base / "runs" / "prog", "r1", compiled)
            spec = prepare_resume(compiled, resume_run_id="r1", base_dir=base / "runs")
            self.assertEqual(spec.run_dir, root)

    def test_resume_rejects_changed_scope(self) -> None:
        from srcguard.preflight import PreflightError, prepare_resume

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text("program: p\nin_scope: ['www.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            self._fake_run(base / "runs", "r1", compiled, policy_hash="deadbeef")
            with self.assertRaises(PreflightError):
                prepare_resume(compiled, resume_run_id="r1", base_dir=base / "runs")

    def test_resume_requires_state(self) -> None:
        from srcguard.preflight import PreflightError, prepare_resume

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text("program: p\nin_scope: ['www.example.com']\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            self._fake_run(base / "runs", "r1", compiled, with_state=False)
            with self.assertRaises(PreflightError):
                prepare_resume(compiled, resume_run_id="r1", base_dir=base / "runs")
