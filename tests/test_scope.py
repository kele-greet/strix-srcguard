from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from srcguard import cli
from srcguard.scope import (
    ScopeError,
    extract_api_spec_base_urls,
    host_allowed,
    compile_policy,
    load_scope,
    spec_hosts,
    url_allowed,
    write_policy,
)


BASE = """
program: test
in_scope:
  - "*.example.com"
  - "api.example.com"
  - "203.0.113.0/24"
out_of_scope:
  - "internal.example.com"
  - "*.thirdparty.com"
allow_third_party:
  - "trusted.test"
allow_spec_hosts: true
ssrf_probe:
  mode: limited
  max_requests: 3
methods:
  deny: [DELETE]
  allow: [GET, HEAD, POST, PUT, PATCH]
rate:
  default_rps: 5
  burst_rps: 50
web_search:
  enabled: false
"""


class ScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "scope.yaml"
        self.path.write_text(BASE, encoding="utf-8")
        self.policy = load_scope(self.path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_wildcard_matches_subdomain_not_apex(self) -> None:
        self.assertTrue(host_allowed(self.policy, "a.example.com")[0])
        self.assertFalse(host_allowed(self.policy, "example.com")[0])

    def test_deny_wins(self) -> None:
        self.assertFalse(host_allowed(self.policy, "internal.example.com")[0])
        self.assertFalse(host_allowed(self.policy, "x.thirdparty.com")[0])

    def test_cidr_only_matches_ip_literals(self) -> None:
        self.assertTrue(host_allowed(self.policy, "203.0.113.7")[0])
        self.assertFalse(host_allowed(self.policy, "203.0.113.300")[0])

    def test_url_allowed_uses_host(self) -> None:
        self.assertTrue(url_allowed(self.policy, "https://api.example.com/v1")[0])
        self.assertFalse(url_allowed(self.policy, "https://internal.example.com/")[0])

    def test_bare_wildcard_rejected(self) -> None:
        bad = Path(self.tmp.name) / "bad.yaml"
        bad.write_text("program: x\nin_scope: ['*']\n", encoding="utf-8")
        with self.assertRaises(ScopeError):
            load_scope(bad)

    def test_delete_is_always_denied_by_default(self) -> None:
        self.assertIn("DELETE", self.policy.deny_methods)
        unsafe = Path(self.tmp.name) / "unsafe.yaml"
        unsafe.write_text(BASE.replace("deny: [DELETE]", "deny: []"), encoding="utf-8")
        self.assertIn("DELETE", load_scope(unsafe).deny_methods)

    def test_extract_openapi_and_postman(self) -> None:
        openapi = Path(self.tmp.name) / "openapi.yaml"
        openapi.write_text(
            """
openapi: 3.0.0
servers:
  - url: https://api.example.com/v1
  - url: https://{env}.example.com
    variables:
      env: {default: staging}
""",
            encoding="utf-8",
        )
        self.assertEqual(
            extract_api_spec_base_urls(openapi),
            ["https://api.example.com/v1", "https://staging.example.com"],
        )
        postman = Path(self.tmp.name) / "postman.json"
        postman.write_text(
            '{"info":{"name":"x"},"item":[{"name":"r","request":{"url":{"raw":"https://api.example.com/a"}}}]}',
            encoding="utf-8",
        )
        self.assertEqual(extract_api_spec_base_urls(postman), ["https://api.example.com"])
        self.assertEqual(spec_hosts(postman), ["api.example.com"])


if __name__ == "__main__":
    unittest.main()


class CompileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _scope(self, body: str) -> Path:
        path = self.base / "scope.yaml"
        path.write_text(body, encoding="utf-8")
        return path

    def test_ipv6_cidr(self) -> None:
        path = self._scope("program: x\nin_scope: ['2001:db8::/32']\n")
        policy = load_scope(path)
        self.assertTrue(host_allowed(policy, "2001:db8::1")[0])
        self.assertFalse(host_allowed(policy, "2001:db9::1")[0])

    def test_idn_wildcard_and_trailing_dot_port(self) -> None:
        path = self._scope("program: x\nin_scope: ['*.例子.中国', 'api.example.com']\n")
        policy = load_scope(path)
        self.assertTrue(host_allowed(policy, "a.xn--fsqu00a.xn--fiqs8s")[0])
        self.assertTrue(host_allowed(policy, "api.example.com.:443")[0])
        self.assertFalse(host_allowed(policy, "api.example.com.evil.test")[0])

    def test_compile_merges_spec_hosts_and_hashes(self) -> None:
        path = self._scope(
            "program: x\nin_scope: ['*.example.com']\nallow_spec_hosts: true\n"
        )
        openapi = self.base / "openapi.yaml"
        openapi.write_text("openapi: 3.0.0\nservers:\n  - url: https://api.example.com/v1\n", encoding="utf-8")
        c1 = compile_policy(load_scope(path), spec_paths=(openapi,))
        c2 = compile_policy(load_scope(path), spec_paths=(openapi,))
        self.assertIn("api.example.com", c1.allow)
        self.assertEqual(c1.policy_hash, c2.policy_hash)
        out = write_policy(self.base / "policy.json", c1)
        self.assertTrue(out.exists())
        self.assertIn(c1.policy_hash, out.read_text(encoding="utf-8"))

    def test_spec_hosts_not_merged_without_flag(self) -> None:
        path = self._scope("program: x\nin_scope: ['*.example.com']\n")
        openapi = self.base / "openapi.yaml"
        openapi.write_text("openapi: 3.0.0\nservers:\n  - url: https://api.other.test/v1\n", encoding="utf-8")
        compiled = compile_policy(load_scope(path), spec_paths=(openapi,))
        self.assertNotIn("api.other.test", compiled.allow)
        self.assertIn("api.other.test", compiled.spec_hosts)

    def test_cli_check_json(self) -> None:
        path = self._scope("program: x\nin_scope: ['*.example.com']\n")
        openapi = self.base / "openapi.yaml"
        openapi.write_text("openapi: 3.0.0\nservers:\n  - url: https://api.example.com/v1\n", encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["check", "--scope", str(path), "--spec", str(openapi), "--json"])
        self.assertEqual(rc, 0)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["program"], "x")
        self.assertIn("policy_hash", doc)


if __name__ == "__main__":
    unittest.main()


class PostPathPolicyTests(unittest.TestCase):
    def test_post_paths_are_compiled_and_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.yaml"
            path.write_text(
                "program: p\nin_scope: ['www.example.com']\n"
                "methods:\n  allow: [GET, HEAD, POST]\n  deny: [DELETE]\n"
                "  post_allow_paths: ['/search/', '/_dwr/']\n"
                "  post_deny_paths: ['/manage/']\n",
                encoding="utf-8",
            )
            compiled = compile_policy(load_scope(path))
            self.assertEqual(compiled.post_allow_paths, ("/search/", "/_dwr/"))
            self.assertEqual(compiled.post_deny_paths, ("/manage/",))
            self.assertIn("/search/", json.dumps(compiled.to_dict()))
            other = Path(tmp) / "other.yaml"
            other.write_text(
                "program: p\nin_scope: ['www.example.com']\nmethods:\n  allow: [GET, HEAD]\n",
                encoding="utf-8",
            )
            self.assertNotEqual(compiled.policy_hash, compile_policy(load_scope(other)).policy_hash)

    def test_max_blocked_is_configurable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.yaml"
            path.write_text(
                "program: p\nin_scope: ['www.example.com']\nlimits:\n  max_blocked: 8\n",
                encoding="utf-8",
            )
            self.assertEqual(compile_policy(load_scope(path)).max_blocked, 8)

    def test_post_is_open_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.yaml"
            path.write_text(
                "program: p\nin_scope: ['www.example.com']\nmethods:\n  allow: [GET, HEAD, POST]\n",
                encoding="utf-8",
            )
            compiled = compile_policy(load_scope(path))
            self.assertEqual(compiled.post_mode, "open")
            self.assertIn("delete", compiled.post_deny_keywords)

    def test_explicit_allowlist_keeps_strict_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.yaml"
            path.write_text(
                "program: p\nin_scope: ['www.example.com']\n"
                "methods:\n  post_allow_paths: ['/search/']\n",
                encoding="utf-8",
            )
            self.assertEqual(compile_policy(load_scope(path)).post_mode, "allowlist")

    def test_post_paths_must_start_with_slash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.yaml"
            path.write_text(
                "program: p\nin_scope: ['www.example.com']\n"
                "methods:\n  post_allow_paths: ['search']\n",
                encoding="utf-8",
            )
            with self.assertRaises(ScopeError):
                load_scope(path)
