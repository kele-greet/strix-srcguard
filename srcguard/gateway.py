"""P1-F8: OpenAI-compatible gateway with policy injection.

The gateway appends a stable policy block to the existing system message (or
inserts one when absent), redacts credential-like tool results, relays streaming
responses, and writes an audit record per request.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx


POLICY_OPEN = "<srcguard_policy>"
POLICY_CLOSE = "</srcguard_policy>"


@dataclass
class GatewayConfig:
    upstream_url: str
    policy: str
    api_key: str = ""
    model_rewrite: str | None = None
    audit_path: Path | None = None
    timeout_s: float = 300.0
    price_input: float = 0.0
    price_cached: float = 0.0
    price_output: float = 0.0
    max_cost: float = 0.0
    max_tokens: int = 0


@dataclass
class Gateway:
    config: GatewayConfig
    audit: list[dict[str, Any]] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = None
    _thread: threading.Thread | None = None
    usage: dict[str, float] = field(
        default_factory=lambda: {
            "requests": 0.0,
            "prompt_tokens": 0.0,
            "cached_tokens": 0.0,
            "completion_tokens": 0.0,
            "cost": 0.0,
        }
    )
    usage_lock: threading.Lock = field(default_factory=threading.Lock)
    budget_block: str | None = None
    port: int = 0

    def _policy_block(self) -> str:
        if not self.config.policy.strip():
            return ""
        return f"{POLICY_OPEN}\n{self.config.policy.strip()}\n{POLICY_CLOSE}"

    def _inject(self, body: dict[str, Any]) -> tuple[bool, bool]:
        block = self._policy_block()
        if not block:
            return False, False
        messages = body.get("messages")
        if isinstance(messages, list):
            system_present = bool(
                messages and isinstance(messages[0], dict) and messages[0].get("role") == "system"
            )
            if system_present:
                content = str(messages[0].get("content") or "")
                if POLICY_OPEN not in content:
                    messages[0]["content"] = f"{content}\n\n{block}"
                return True, True
            messages.insert(0, {"role": "system", "content": block})
            return True, False

        instructions = body.get("instructions")
        if isinstance(instructions, str):
            if POLICY_OPEN not in instructions:
                body["instructions"] = f"{instructions}\n\n{block}"
            return True, True

        payload = body.get("input")
        if isinstance(payload, str):
            body["input"] = [
                {"role": "system", "content": block},
                {"role": "user", "content": payload},
            ]
            return True, False
        if isinstance(payload, list):
            system_present = bool(
                payload and isinstance(payload[0], dict) and payload[0].get("role") == "system"
            )
            if system_present:
                content = str(payload[0].get("content") or "")
                if POLICY_OPEN not in content:
                    payload[0]["content"] = f"{content}\n\n{block}"
                return True, True
            payload.insert(0, {"role": "system", "content": block})
            return True, False
        return False, False

    def _redact(self, body: dict[str, Any]) -> int:
        count = 0

        def redact_text(text: str) -> tuple[str, int]:
            hits = 0
            for marker in ("AKIA", "ASIA", "AIDA", "AROA"):
                if marker in text:
                    text = text.replace(marker, "REDACTED_")
                    hits += 1
            return text, hits

        messages = body.get("messages")
        if isinstance(messages, list):
            for message in messages:
                if not isinstance(message, dict) or message.get("role") != "tool":
                    continue
                content = message.get("content")
                if not isinstance(content, str):
                    continue
                content, hits = redact_text(content)
                message["content"] = content
                count += hits

        payload = body.get("input")
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "function_call_output" and isinstance(item.get("output"), str):
                    item["output"], hits = redact_text(item["output"])
                    count += hits
        return count

    @staticmethod
    def _tool_calls(data: dict[str, Any]) -> list[dict[str, Any]]:
        calls = [
            {
                "name": item.get("function", {}).get("name"),
                "arguments": str(item.get("function", {}).get("arguments"))[:500],
            }
            for choice in (data.get("choices") or [])
            for item in (choice.get("message", {}).get("tool_calls") or [])
            if isinstance(item, dict)
        ]
        calls += [
            {"name": item.get("name"), "arguments": str(item.get("arguments"))[:500]}
            for item in (data.get("output") or [])
            if isinstance(item, dict) and item.get("type") == "function_call"
        ]
        return calls

    def _record_usage(self, usage: dict[str, Any]) -> None:
        prompt = int(usage.get("prompt_tokens") or 0)
        completion = int(usage.get("completion_tokens") or 0)
        details = usage.get("prompt_tokens_details")
        cached = 0
        if isinstance(details, dict):
            cached = int(details.get("cached_tokens") or 0)
        if not cached:
            cached = int(usage.get("cached_tokens") or 0)
        cost = (
            max(0, prompt - cached) * self.config.price_input / 1_000_000.0
            + cached * self.config.price_cached / 1_000_000.0
            + completion * self.config.price_output / 1_000_000.0
        )
        with self.usage_lock:
            self.usage["requests"] += 1
            self.usage["prompt_tokens"] += prompt
            self.usage["cached_tokens"] += cached
            self.usage["completion_tokens"] += completion
            self.usage["cost"] += cost
            row = {
                "event": "usage",
                "prompt_tokens": prompt,
                "cached_tokens": cached,
                "completion_tokens": completion,
                "cost": round(cost, 6),
                "total_cost": round(self.usage["cost"], 6),
                "total_tokens": int(
                    self.usage["prompt_tokens"] + self.usage["completion_tokens"]
                ),
            }
            self._write_audit(row)
            if self.budget_block is None:
                if self.config.max_cost > 0 and self.usage["cost"] >= self.config.max_cost:
                    self.budget_block = f"max_cost {self.config.max_cost:.2f} reached"
                elif self.config.max_tokens > 0 and (
                    self.usage["prompt_tokens"] + self.usage["completion_tokens"]
                ) >= self.config.max_tokens:
                    self.budget_block = f"max_tokens {self.config.max_tokens} reached"
                if self.budget_block:
                    self._write_audit({"event": "budget_blocked", "reason": self.budget_block})

    def _write_audit(self, row: dict[str, Any]) -> None:
        self.audit.append(row)
        if self.config.audit_path is None:
            return
        self.config.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.config.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        gateway = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *args):  # noqa: N802, ANN002
                return

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                except json.JSONDecodeError:
                    self._error(400, "invalid json")
                    return
                if not isinstance(body, dict):
                    self._error(400, "body must be object")
                    return
                if gateway.budget_block:
                    self._error(429, f"srcguard budget: {gateway.budget_block}")
                    return
                injected, system_present = gateway._inject(body)
                redacted = gateway._redact(body)
                if gateway.config.model_rewrite:
                    body["model"] = gateway.config.model_rewrite
                stream = bool(body.get("stream"))
                if stream:
                    options = body.get("stream_options")
                    if not isinstance(options, dict):
                        options = {}
                    options["include_usage"] = True
                    body["stream_options"] = options
                tools = [
                    item.get("name") or item.get("function", {}).get("name")
                    for item in (body.get("tools") or [])
                    if isinstance(item, dict)
                ]
                gateway._write_audit(
                    {
                        "path": self.path,
                        "stream": stream,
                        "policy_injected": injected,
                        "system_present": system_present,
                        "redacted": redacted,
                        "tool_names": tools[:60],
                    }
                )
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {gateway.config.api_key}",
                }
                try:
                    if stream:
                        with httpx.stream(
                            "POST",
                            gateway.config.upstream_url,
                            headers=headers,
                            json=body,
                            timeout=gateway.config.timeout_s,
                        ) as resp:
                            self.send_response(resp.status_code)
                            for key, value in resp.headers.items():
                                if key.lower() in {"content-length", "transfer-encoding", "connection"}:
                                    continue
                                self.send_header(key, value)
                            self.end_headers()
                            buffer = b""
                            for chunk in resp.iter_bytes():
                                self.wfile.write(chunk)
                                self.wfile.flush()
                                buffer += chunk
                                while b"\n" in buffer:
                                    line, buffer = buffer.split(b"\n", 1)
                                    text = line.strip()
                                    if not text.startswith(b"data:"):
                                        continue
                                    payload = text[5:].strip()
                                    if not payload or payload == b"[DONE]":
                                        continue
                                    try:
                                        event = json.loads(payload)
                                    except json.JSONDecodeError:
                                        continue
                                    usage = event.get("usage") if isinstance(event, dict) else None
                                    if isinstance(usage, dict):
                                        gateway._record_usage(usage)
                        return
                    resp = httpx.post(
                        gateway.config.upstream_url,
                        headers=headers,
                        json=body,
                        timeout=gateway.config.timeout_s,
                    )
                    raw = resp.content
                    try:
                        data = json.loads(raw)
                        calls = gateway._tool_calls(data)
                        if gateway.audit:
                            gateway.audit[-1]["response_tool_calls"] = calls
                        usage = data.get("usage") if isinstance(data, dict) else None
                        if isinstance(usage, dict):
                            gateway._record_usage(usage)
                    except (json.JSONDecodeError, AttributeError):
                        pass
                    self.send_response(resp.status_code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except Exception as exc:  # noqa: BLE001
                    self._error(502, f"gateway: {exc}")

            def _error(self, status: int, message: str) -> None:
                raw = json.dumps({"error": message}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        return H

    def start(self, host: str = "127.0.0.1", port: int = 0) -> str:
        self._server = ThreadingHTTPServer((host, port), self._handler())
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}" if self.port else "http://127.0.0.1"

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
