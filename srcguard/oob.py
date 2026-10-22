"""P1-F6: self-hosted OOB callback server (HTTP + optional DNS label).

The server binds locally, advertises a host:port, and writes every callback to
audit/oob.jsonl. For a real SRC run the advertised host must be public (or a
tunnel); for lab use it can be the Docker gateway IP.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit


@dataclass
class OobEvent:
    token: str
    path: str
    query: dict[str, list[str]]
    remote: str
    ts: float
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "path": self.path,
            "query": self.query,
            "remote": self.remote,
            "ts": self.ts,
            "headers": self.headers,
        }


class OobServer:
    def __init__(
        self,
        *,
        run_dir: str | Path,
        run_id: str,
        bind_host: str = "0.0.0.0",
        port: int = 0,
        advertised_host: str | None = None,
        domain: str | None = None,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.run_id = run_id
        self.bind_host = bind_host
        self.port = port
        self.advertised_host = advertised_host or bind_host
        self.domain = (domain or "").strip().rstrip(".")
        self.token = secrets.token_hex(8)
        self.public_url: str | None = None
        self.events: list[OobEvent] = []
        self._events_by_token: dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def out_path(self) -> Path:
        return self.run_dir / "audit" / "oob.jsonl"

    def url(self, token: str | None = None) -> str:
        if self.public_url:
            return f"{self.public_url.rstrip('/')}/{token or self.token}"
        return f"http://{self.advertised_host}:{self.port}/{token or self.token}"

    def dns_name(self, token: str | None = None) -> str:
        token = token or self.token
        return f"{token}.{self.domain}" if self.domain else token

    def start(self) -> str:
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # noqa: N802, ANN002
                return

            def do_GET(self):  # noqa: N802
                server_ref._record(self)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

            def do_POST(self):  # noqa: N802
                server_ref._record(self)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")

        self._server = ThreadingHTTPServer((self.bind_host, self.port), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url()

    def _record(self, handler: BaseHTTPRequestHandler) -> None:
        parts = urlsplit(handler.path)
        token = parts.path.strip("/").split("/", 1)[0] or "unknown"
        event = OobEvent(
            token=token,
            path=parts.path,
            query=parse_qs(parts.query),
            remote=handler.client_address[0] if handler.client_address else "",
            ts=time.time(),
            headers={
                key: handler.headers.get(key, "")
                for key in ("User-Agent", "Referer", "X-Forwarded-For")
                if handler.headers.get(key)
            },
        )
        with self._lock:
            self.events.append(event)
            with self.out_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
            wake = self._events_by_token.get(token)
        if wake is not None:
            wake.set()

    def wait(self, token: str | None = None, timeout: float = 30.0) -> bool:
        token = token or self.token
        with self._lock:
            if any(event.token == token for event in self.events):
                return True
            wake = self._events_by_token.setdefault(token, threading.Event())
        return bool(wake.wait(timeout))

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
