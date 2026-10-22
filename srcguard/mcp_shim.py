"""Minimal stdio MCP server exposing sandbox_exec.

Why: Strix advertises SandboxAgent capability tools (exec_command) to the model
but does not dispatch them through the Chat Completions/Responses path in this
version. MCP tools are normal FunctionTools (call_mcp) and do dispatch, so this
shim executes a command inside the run's sandbox via `docker exec`.

The original cage still applies: docker exec runs inside the sandbox, so all
egress goes through the same nftables rules and Caido proxy.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlsplit

from .method_guard import blocked_method, post_violation
from .secrets import redact


DOCKER = shutil.which("docker") or "/usr/bin/docker"


PROTOCOL_VERSION = "2024-11-05"
MAX_OUTPUT = 8000


def _respond(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _result(request_id: Any, result: dict[str, Any]) -> None:
    _respond({"jsonrpc": "2.0", "id": request_id, "result": result})


def _error(request_id: Any, code: int, message: str) -> None:
    _respond({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


def _container() -> str | None:
    run_id = os.environ.get("STRIX_RUN_ID", "").strip()
    if not run_id:
        return None
    try:
        out = subprocess.run(
            [DOCKER, "ps", "-q", "--filter", f"label=strix-run-id={run_id}"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return None
    return out.splitlines()[0] if out else None


def _log_method(cmd: str, method: str) -> None:
    path = os.environ.get("SRCGUARD_METHOD_LOG", "")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "event": "method_blocked",
                        "method": method,
                        "cmd": redact(cmd)[:500],
                        "ts": time.time(),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    except OSError:
        pass


def _log_egress(cmd: str) -> None:
    path = os.environ.get("SRCGUARD_EGRESS_LOG", "")
    if not path:
        return
    hosts: list[str] = []
    try:
        words = shlex.split(cmd)
    except ValueError:
        words = []
    proxy_next = False
    for word in words:
        if proxy_next:
            proxy_next = False
            continue
        if word in {"-x", "--proxy"}:
            proxy_next = True
            continue
        if not re.match(r"https?://", word):
            continue
        host = (urlsplit(word).hostname or "").lower()
        if host and host not in hosts:
            hosts.append(host)
    if not hosts:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            for host in hosts:
                handle.write(
                    json.dumps(
                        {"host": host, "source": "mcp_exec", "ts": time.time()},
                        ensure_ascii=False,
                    )
                    + "\n"
                )
    except OSError:
        pass


def _debug(text: str) -> None:
    text = redact(text)
    path = os.environ.get("SRCGUARD_MCP_LOG", "")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    except OSError:
        pass


def _command_quota(cmd: str) -> str | None:
    raw = os.environ.get("SRCGUARD_MAX_COMMANDS", "").strip()
    path = os.environ.get("SRCGUARD_COMMAND_COUNT", "")
    if not raw or not path:
        return None
    try:
        limit = int(raw)
    except ValueError:
        return None
    if limit <= 0:
        return None
    count = 0
    try:
        count = int(open(path, encoding="utf-8").read().strip() or "0")
    except (OSError, ValueError):
        count = 0
    count += 1
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(str(count))
    except OSError:
        return None
    if count > limit:
        _log_method(f"command quota exceeded ({count}>{limit})", "QUOTA")
        _debug(f"BLOCKED command quota {count}>{limit} cmd={cmd!r}")
        return f"ERROR: command quota exceeded ({count}>{limit}); no more commands this run"
    return None


def _sandbox_exec(cmd: str) -> str:
    quota = _command_quota(cmd)
    if quota:
        return quota
    denied = {
        item.strip().upper()
        for item in os.environ.get("SRCGUARD_DENY_METHODS", "").split(",")
        if item.strip()
    }
    method = blocked_method(cmd, denied)
    if method:
        _log_method(cmd, method)
        _debug(f"BLOCKED method={method} cmd={cmd!r}")
        return f"ERROR: method {method} blocked by SRCGuard policy"
    post_reason = post_violation(
        cmd,
        mode=(os.environ.get("SRCGUARD_POST_MODE", "allowlist").strip().lower() or "allowlist"),
        deny_keywords=tuple(
            item.strip()
            for item in os.environ.get("SRCGUARD_POST_DENY_KEYWORDS", "").split(",")
            if item.strip()
        ),
        allow_paths=tuple(
            item.strip()
            for item in os.environ.get("SRCGUARD_POST_ALLOW_PATHS", "").split(",")
            if item.strip()
        ),
        deny_paths=tuple(
            item.strip()
            for item in os.environ.get("SRCGUARD_POST_DENY_PATHS", "").split(",")
            if item.strip()
        ),
    )
    if post_reason:
        _log_method(cmd, "POST")
        _debug(f"BLOCKED {post_reason} cmd={cmd!r}")
        return f"ERROR: {post_reason}; POST is limited to the allowed paths"
    cid = _container()
    _log_egress(cmd)
    _debug(f"cmd={cmd!r} container={cid!r}")
    if not cid:
        _debug("ERROR: sandbox container not found")
        return "ERROR: sandbox container not found for STRIX_RUN_ID"
    env_args: list[str] = []
    no_proxy = os.environ.get("SRCGUARD_MCP_NO_PROXY", "").strip()
    if no_proxy:
        value = f"{no_proxy},localhost,127.0.0.1"
        env_args = ["-e", f"NO_PROXY={value}", "-e", f"no_proxy={value}"]
        # The image exports ALL_PROXY/HTTP(S)_PROXY too; NO_PROXY alone still
        # leaves some clients with a proxy. Private lab targets are direct.
        for name in ("ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            env_args += ["-e", f"{name}="]
    try:
        proc = subprocess.run(
            [DOCKER, "exec", *env_args, cid, "sh", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return "ERROR: command timed out after 60s"
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: {exc}"
    out = (proc.stdout or "") + (proc.stderr or "")
    _debug(f"exit={proc.returncode} out={out[:500]!r}")
    if len(out) > MAX_OUTPUT:
        out = out[:MAX_OUTPUT] + "\n[truncated]"
    return f"exit={proc.returncode}\n{out}"


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params") or {}
        if method == "initialize":
            _result(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "srcguard", "version": "0.1.0"},
                },
            )
        elif method in {"notifications/initialized", "initialized"}:
            continue
        elif method == "ping":
            _result(request_id, {})
        elif method == "tools/list":
            _result(
                request_id,
                {
                    "tools": [
                        {
                            "name": "sandbox_exec",
                            "description": (
                                "Run a shell command inside the current Strix sandbox. "
                                "Egress goes through the cage and Caido proxy."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "cmd": {"type": "string", "description": "Shell command"}
                                },
                                "required": ["cmd"],
                                "additionalProperties": False,
                            },
                        }
                    ]
                },
            )
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if name != "sandbox_exec":
                _result(
                    request_id,
                    {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True},
                )
                continue
            cmd = arguments.get("cmd") if isinstance(arguments, dict) else None
            if not isinstance(cmd, str) or not cmd.strip():
                _result(
                    request_id,
                    {"content": [{"type": "text", "text": "cmd is required"}], "isError": True},
                )
                continue
            _result(
                request_id,
                {"content": [{"type": "text", "text": _sandbox_exec(cmd)}], "isError": False},
            )
        elif method in {"resources/list", "prompts/list"}:
            _result(request_id, {"resources": []} if method == "resources/list" else {"prompts": []})
        else:
            _error(request_id, -32601, f"method not found: {method}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
