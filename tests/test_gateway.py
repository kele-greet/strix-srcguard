from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

from srcguard.gateway import Gateway, GatewayConfig


class Upstream:
    requests: list[dict] = []

    @classmethod
    def handler(cls):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *args):  # noqa: N802, ANN002
                return

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                cls.requests.append(body)
                if body.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    self.wfile.write(b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n')
                    self.wfile.write(
                        b'data: {"choices":[],"usage":{"prompt_tokens":500,'
                        b'"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":0}}}\n\n'
                    )
                    self.wfile.write(b"data: [DONE]\n\n")
                    return
                raw = json.dumps(
                    {
                        "ok": True,
                        "usage": {
                            "prompt_tokens": 1000,
                            "completion_tokens": 100,
                            "prompt_tokens_details": {"cached_tokens": 800},
                        },
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        return H


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


class GatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        Upstream.requests = []
        self.upstream, up_port = serve(Upstream.handler())
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = Path(self.tmp.name) / "llm.jsonl"
        self.gateway = Gateway(
            GatewayConfig(
                upstream_url=f"http://127.0.0.1:{up_port}/chat",
                policy="SRC_POLICY: allowlist only.",
                api_key="test",
                model_rewrite="deepseek-flash",
                audit_path=self.audit,
            )
        )
        self.gateway.start()

    def tearDown(self) -> None:
        self.gateway.stop()
        self.upstream.shutdown()
        self.tmp.cleanup()

    def _post(self, body):
        return httpx.post(self.gateway.base_url + "/v1/chat/completions", json=body, timeout=10)

    def test_existing_system_gets_policy_appended(self) -> None:
        resp = self._post(
            {
                "model": "x",
                "messages": [
                    {"role": "system", "content": "STRIX_SYSTEM"},
                    {"role": "user", "content": "scan"},
                ],
            }
        )
        self.assertEqual(resp.status_code, 200)
        body = Upstream.requests[-1]
        self.assertEqual(len([m for m in body["messages"] if m["role"] == "system"]), 1)
        self.assertIn("STRIX_SYSTEM", body["messages"][0]["content"])
        self.assertIn("SRC_POLICY", body["messages"][0]["content"])
        self.assertEqual(body["model"], "deepseek-flash")
        request_row = [row for row in self.gateway.audit if "policy_injected" in row][-1]
        self.assertTrue(request_row["policy_injected"])
        self.assertTrue(request_row["system_present"])
        self.assertIn("/v1/chat/completions", self.audit.read_text(encoding="utf-8"))

    def test_usage_is_metered_and_priced(self) -> None:
        gateway = Gateway(
            GatewayConfig(
                upstream_url=self.gateway.config.upstream_url,
                policy="",
                api_key="test",
                audit_path=self.audit,
                price_input=0.27,
                price_cached=0.07,
                price_output=1.10,
            )
        )
        gateway.start()
        try:
            httpx.post(
                gateway.base_url + "/v1/chat/completions",
                json={"model": "x", "messages": [{"role": "user", "content": "hi"}]},
                timeout=10,
            )
            self.assertEqual(gateway.usage["prompt_tokens"], 1000)
            self.assertEqual(gateway.usage["cached_tokens"], 800)
            # (200 miss * 0.27 + 800 cached * 0.07 + 100 out * 1.10) / 1e6
            self.assertAlmostEqual(gateway.usage["cost"], (54 + 56 + 110) / 1_000_000, places=9)
        finally:
            gateway.stop()

    def test_budget_blocks_further_requests(self) -> None:
        gateway = Gateway(
            GatewayConfig(
                upstream_url=self.gateway.config.upstream_url,
                policy="",
                api_key="test",
                price_input=1.0,
                price_output=1.0,
                max_cost=0.0002,
            )
        )
        gateway.start()
        try:
            first = httpx.post(
                gateway.base_url + "/v1/chat/completions",
                json={"model": "x", "messages": [{"role": "user", "content": "hi"}]},
                timeout=10,
            )
            self.assertEqual(first.status_code, 200)
            second = httpx.post(
                gateway.base_url + "/v1/chat/completions",
                json={"model": "x", "messages": [{"role": "user", "content": "hi"}]},
                timeout=10,
            )
            self.assertEqual(second.status_code, 429)
            self.assertIn("budget", second.json()["error"])
        finally:
            gateway.stop()

    def test_streaming_usage_is_metered(self) -> None:
        gateway = Gateway(
            GatewayConfig(
                upstream_url=self.gateway.config.upstream_url,
                policy="",
                api_key="test",
                price_input=1.0,
                price_output=1.0,
            )
        )
        gateway.start()
        try:
            httpx.post(
                gateway.base_url + "/v1/chat/completions",
                json={
                    "model": "x",
                    "stream": True,
                    "messages": [{"role": "user", "content": "hi"}],
                },
                timeout=10,
            )
            self.assertEqual(gateway.usage["prompt_tokens"], 500)
            self.assertEqual(gateway.usage["completion_tokens"], 50)
        finally:
            gateway.stop()

    def test_no_system_inserts_one(self) -> None:
        self._post({"model": "x", "messages": [{"role": "user", "content": "scan"}]})
        body = Upstream.requests[-1]
        self.assertEqual(body["messages"][0]["role"], "system")
        self.assertIn("SRC_POLICY", body["messages"][0]["content"])

    def test_tool_result_redaction(self) -> None:
        self._post(
            {
                "model": "x",
                "messages": [
                    {"role": "system", "content": "s"},
                    {"role": "tool", "tool_call_id": "1", "content": "AKIA1234567890ABCDEF"},
                ],
            }
        )
        content = Upstream.requests[-1]["messages"][-1]["content"]
        self.assertNotIn("AKIA", content)
        self.assertIn("REDACTED_", content)

    def test_responses_input_string_gets_policy(self) -> None:
        resp = httpx.post(
            self.gateway.base_url + "/v1/responses",
            json={"model": "x", "input": "scan"},
            timeout=10,
        )
        self.assertEqual(resp.status_code, 200)
        body = Upstream.requests[-1]
        self.assertEqual(body["input"][0]["role"], "system")
        self.assertIn("SRC_POLICY", body["input"][0]["content"])
        self.assertEqual(body["input"][1]["content"], "scan")

    def test_responses_instructions_gets_policy(self) -> None:
        httpx.post(
            self.gateway.base_url + "/v1/responses",
            json={"model": "x", "instructions": "STRIX", "input": []},
            timeout=10,
        )
        body = Upstream.requests[-1]
        self.assertIn("STRIX", body["instructions"])
        self.assertIn("SRC_POLICY", body["instructions"])

    def test_responses_tool_call_and_redaction(self) -> None:
        data = {
            "output": [
                {"type": "function_call", "name": "exec_command", "arguments": "{}"},
                {"type": "function_call_output", "output": "AKIA1234567890ABCDEF"},
            ]
        }
        self.assertEqual(
            Gateway._tool_calls(data), [{"name": "exec_command", "arguments": "{}"}]
        )
        body = {"input": [data["output"][1]]}
        self.assertEqual(self.gateway._redact(body), 1)
        self.assertNotIn("AKIA", body["input"][0]["output"])

    def test_streaming_passthrough(self) -> None:
        with httpx.stream(
            "POST",
            self.gateway.base_url + "/v1/chat/completions",
            json={"model": "x", "stream": True, "messages": [{"role": "user", "content": "s"}]},
            timeout=10,
        ) as resp:
            text = "".join(resp.iter_text())
        self.assertIn("hi", text)
        self.assertIn("[DONE]", text)


if __name__ == "__main__":
    unittest.main()
