"""P2-1: Docker API mutation proxy.

Strix talks to the Docker daemon through ``DOCKER_HOST``. This proxy forwards
that API over a TCP socket to the local Unix socket and mutates only
``POST /containers/create``:

- drop ``NET_ADMIN`` from ``HostConfig.CapAdd`` (keep ``NET_RAW``);
- reject privileged containers, host/container network mode, host PID/IPC;
- force ``HostConfig.Dns`` to the SRCGuard resolver when configured;
- mark bind mounts read-only unless the target is the writable workspace root
  (``/workspace`` itself, ``/tmp``, ``/home/pentester``);
- append every mutation/rejection to ``audit/docker.jsonl``.

Everything else is a transparent HTTP/1.1 forwarder. The proxy is opt-in
(``srcguard run --docker-proxy``) because it sits on a critical path.
"""

from __future__ import annotations

import json
import select
import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DOCKER_SOCKET = "/var/run/docker.sock"
MAX_HEADER = 256 * 1024
MAX_BODY = 16 * 1024 * 1024
WRITABLE_TARGETS = ("/workspace", "/tmp", "/home/pentester")
WRITABLE_PREFIXES = ("/tmp", "/home/pentester")


class ProxyError(RuntimeError):
    """The proxy could not start/forward."""


def _is_create_path(path: str) -> bool:
    clean = path.split("?", 1)[0].rstrip("/")
    return clean.endswith("/containers/create")


def _target_writable(target: str) -> bool:
    if target == "/workspace":
        return True
    return any(target == prefix or target.startswith(prefix + "/") for prefix in WRITABLE_PREFIXES)


def _bind_target(value: str) -> tuple[list[str], int] | None:
    """Return (parts, target_index) for a Docker ``Binds`` entry."""
    parts = value.split(":")
    if len(parts) < 2:
        return None
    return parts, 1


def mutate_create(
    payload: dict[str, Any], *, dns_server: str | None = None
) -> tuple[dict[str, Any], list[str], str | None]:
    """Mutate a container-create payload in place.

    Returns (payload, changes, rejection_reason). A rejection reason means the
    request must be answered with 403 and must not be forwarded.
    """
    changes: list[str] = []
    if not isinstance(payload, dict):
        return payload, changes, "body is not a JSON object"
    host = payload.setdefault("HostConfig", {})
    if not isinstance(host, dict):
        return payload, changes, "HostConfig is not an object"

    if host.get("Privileged") is True:
        return payload, changes, "privileged containers are not allowed"
    network_mode = str(host.get("NetworkMode") or "")
    if network_mode in {"host"} or network_mode.startswith("container:"):
        return payload, changes, f"network mode {network_mode!r} is not allowed"
    for key in ("PidMode", "IpcMode", "UTSMode", "UsernsMode"):
        if str(host.get(key) or "") == "host":
            return payload, changes, f"host {key[:-4].upper()} namespace is not allowed"

    if dns_server:
        current = host.get("Dns") or []
        if current != [dns_server]:
            host["Dns"] = [dns_server]
            host["DnsSearch"] = []
            host["DnsOptions"] = []
            changes.append(f"Dns -> {dns_server}")

    cap_add = host.get("CapAdd")
    if isinstance(cap_add, list):
        upper = [str(cap).upper() for cap in cap_add]
        if "ALL" in upper:
            return payload, changes, "CapAdd ALL is not allowed"
        kept = [cap for cap in cap_add if str(cap).upper() not in {"NET_ADMIN", "CAP_NET_ADMIN"}]
        if len(kept) != len(cap_add):
            host["CapAdd"] = kept
            changes.append("dropped CapAdd NET_ADMIN")

    mounts = host.get("Mounts")
    if isinstance(mounts, list):
        for mount in mounts:
            if not isinstance(mount, dict) or mount.get("Type") != "bind":
                continue
            target = str(mount.get("Target") or "")
            if target and not _target_writable(target) and not mount.get("ReadOnly"):
                mount["ReadOnly"] = True
                changes.append(f"mount {target} -> ReadOnly")

    binds = host.get("Binds")
    if isinstance(binds, list):
        new_binds: list[str] = []
        for item in binds:
            if not isinstance(item, str):
                new_binds.append(item)
                continue
            parsed = _bind_target(item)
            if parsed is None:
                new_binds.append(item)
                continue
            parts, idx = parsed
            target = parts[idx]
            if not target or _target_writable(target):
                new_binds.append(item)
                continue
            options = parts[2] if len(parts) > 2 else ""
            if "ro" not in options.split(","):
                if options:
                    options = options.replace("rw", "ro")
                    if "ro" not in options.split(","):
                        options += ",ro"
                else:
                    options = "ro"
                parts = [parts[0], parts[1], options] if len(parts) > 2 else [parts[0], parts[1], options]
                changes.append(f"bind {target} -> ro")
            new_binds.append(":".join(parts))
        host["Binds"] = new_binds

    return payload, changes, None


@dataclass
class DockerProxyConfig:
    socket_path: str = DOCKER_SOCKET
    host: str = "127.0.0.1"
    audit_path: Path | None = None
    timeout_s: float = 30.0
    allow_privileged: bool = False
    dns_server: str | None = None


@dataclass
class DockerMutationProxy:
    config: DockerProxyConfig = field(default_factory=DockerProxyConfig)
    port: int = 0
    _server: socketserver.ThreadingTCPServer | None = None
    _thread: threading.Thread | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _audit(self, row: dict[str, Any]) -> None:
        if self.config.audit_path is None:
            return
        row = {"ts": time.time(), **row}
        with self._lock:
            self.config.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.config.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _handler(self) -> type[socketserver.BaseRequestHandler]:
        proxy = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:  # noqa: C901
                try:
                    self._serve()
                except Exception as exc:  # noqa: BLE001
                    proxy._audit({"event": "proxy_error", "error": str(exc)[:500]})
                    try:
                        self.request.sendall(
                            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    except OSError:
                        pass

            def _serve(self) -> None:
                client: socket.socket = self.request
                head, rest = _read_until(client, b"\r\n\r\n", MAX_HEADER)
                if not head:
                    return
                lines = head.split(b"\r\n")
                try:
                    method, path, _version = lines[0].decode("latin-1").split(" ", 2)
                except ValueError:
                    _send_text(client, 400, "bad request line")
                    return
                headers = _parse_headers(lines[1:])
                body = _read_body(client, headers, rest)
                if body is None:
                    _send_text(client, 400, "bad body")
                    return

                out_body = body
                if method.upper() == "POST" and _is_create_path(path):
                    try:
                        payload = json.loads(body or b"{}")
                    except json.JSONDecodeError:
                        _send_text(client, 400, "invalid create JSON")
                        return
                    payload, changes, reject = mutate_create(
                        payload, dns_server=proxy.config.dns_server
                    )
                    if reject and not proxy.config.allow_privileged:
                        proxy._audit(
                            {"event": "create_rejected", "path": path, "reason": reject, "changes": changes}
                        )
                        _send_text(client, 403, f"srcguard: {reject}")
                        return
                    out_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                    proxy._audit(
                        {
                            "event": "create_mutated",
                            "path": path,
                            "changes": changes,
                            "name": (payload.get("name") if isinstance(payload, dict) else None),
                        }
                    )

                upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                upstream.settimeout(proxy.config.timeout_s)
                try:
                    upstream.connect(proxy.config.socket_path)
                except OSError:
                    _send_text(client, 502, "docker socket unavailable")
                    return
                try:
                    _forward(
                        client,
                        upstream,
                        method=method,
                        path=path,
                        headers=headers,
                        body=out_body,
                    )
                finally:
                    upstream.close()

        return Handler

    def start(self, host: str | None = None, port: int = 0) -> str:
        if self._server is not None:
            return self.base_url
        handler = self._handler()
        server = _ThreadingUnixProxy((host or self.config.host, port), handler)
        self._server = server
        self.port = server.server_address[1]
        self._thread = threading.Thread(target=server.serve_forever, name="srcguard-docker-proxy", daemon=True)
        self._thread.start()
        return self.base_url

    @property
    def base_url(self) -> str:
        return f"tcp://{self.config.host}:{self.port}"

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


class _ThreadingUnixProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _read_until(sock: socket.socket, marker: bytes, limit: int) -> tuple[bytes, bytes]:
    buffer = b""
    while marker not in buffer:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > limit:
            raise ProxyError("header too large")
    head, _, rest = buffer.partition(marker)
    return head, rest


def _parse_headers(lines: list[bytes]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in lines:
        if not line:
            continue
        name, sep, value = line.partition(b":")
        if not sep:
            continue
        out.append((name.decode("latin-1").strip(), value.decode("latin-1").strip()))
    return out


def _read_body(sock: socket.socket, headers: list[tuple[str, str]], rest: bytes) -> bytes | None:
    lower = {name.lower(): value for name, value in headers}
    if lower.get("transfer-encoding", "").lower() == "chunked":
        data = rest
        while b"\r\n0\r\n" not in data and not data.endswith(b"0\r\n\r\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_BODY:
                return None
        return data
    length_text = lower.get("content-length")
    if not length_text:
        return b""
    try:
        length = int(length_text)
    except ValueError:
        return None
    if length < 0 or length > MAX_BODY:
        return None
    data = rest
    while len(data) < length:
        chunk = sock.recv(min(65536, length - len(data)))
        if not chunk:
            break
        data += chunk
    return data[:length]


def _send_text(sock: socket.socket, status: int, message: str) -> None:
    body = message.encode("utf-8")
    reason = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}.get(status, "Error")
    sock.sendall(
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
        + body
    )


def _forward(
    client: socket.socket,
    upstream: socket.socket,
    *,
    method: str,
    path: str,
    headers: list[tuple[str, str]],
    body: bytes,
) -> None:
    lower = {name.lower(): value for name, value in headers}
    wants_upgrade = lower.get("upgrade", "").lower() == "tcp" or "upgrade" in lower.get("connection", "").lower()
    lines = [f"{method} {path} HTTP/1.1", "Host: docker"]
    for name, value in headers:
        if name.lower() in {"host", "connection", "content-length", "transfer-encoding"}:
            continue
        lines.append(f"{name}: {value}")
    lines.append("Connection: Upgrade" if wants_upgrade else "Connection: close")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
    upstream.sendall(raw)

    head, rest = _read_until(upstream, b"\r\n\r\n", MAX_HEADER)
    if not head:
        _send_text(client, 502, "empty docker response")
        return
    header_lines = head.split(b"\r\n")
    upgrade = b"101" in header_lines[0] and b"upgrade" in head.lower()
    if rest:
        client.sendall(head + b"\r\n\r\n" + rest)
    else:
        client.sendall(head + b"\r\n\r\n")
    if upgrade:
        _splice(client, upstream)
        return
    while True:
        chunk = upstream.recv(65536)
        if not chunk:
            break
        client.sendall(chunk)


def _splice(a: socket.socket, b: socket.socket) -> None:
    a_open = b_open = True
    while a_open or b_open:
        readable, _, _ = select.select([a] if a_open else [], [b] if b_open else [], [], 60)
        if not readable:
            return
        for source in readable:
            try:
                data = source.recv(65536)
            except OSError:
                data = b""
            target = b if source is a else a
            if not data:
                if source is a:
                    a_open = False
                else:
                    b_open = False
                try:
                    target.shutdown(socket.SHUT_WR)
                except OSError:
                    return
                continue
            try:
                target.sendall(data)
            except OSError:
                return
