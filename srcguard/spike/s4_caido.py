"""S4: Caido discovery mechanics (project id parsing + guest GraphQL auth shape).

Real Caido integration needs a live Strix sandbox; this checks the two fragile
pieces we control: parsing the project id from strix.log, and the guest login.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

from .common import Result


PROJECT_RE = re.compile(r"Caido project selected:\s*([A-Za-z0-9_-]{8,})")


class _MockCaido(BaseHTTPRequestHandler):
    def log_message(self, *args):  # noqa: N802, ANN002
        return

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        if "loginAsGuest" in body:
            payload = {"data": {"loginAsGuest": {"token": {"accessToken": "guest-token"}}}}
        elif "projects" in body:
            payload = {"data": {"projects": [{"id": "proj-1", "name": "sandbox"}]}}
        else:
            payload = {"data": {}}
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run(root: Path) -> Result:
    evidence: list[str] = []
    try:
        line = "2026-10-19 22:00:00 INFO  scan-1 - strix.runtime.caido_bootstrap: Caido project selected: proj-abc-123"
        match = PROJECT_RE.search(line)
        evidence.append(f"log_parse match={match.group(1) if match else None}")
        assert match and match.group(1) == "proj-abc-123"

        server = ThreadingHTTPServer(("127.0.0.1", 0), _MockCaido)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/graphql"
            resp = httpx.post(
                url,
                json={"query": "mutation { loginAsGuest { token { accessToken } } }"},
                timeout=10,
            )
            token = resp.json()["data"]["loginAsGuest"]["token"]["accessToken"]
            evidence.append(f"guest_login status={resp.status_code} token={token}")
            assert token == "guest-token"
            resp2 = httpx.post(url, json={"query": "{ projects { id name } }"}, timeout=10)
            evidence.append(f"projects={resp2.json()['data']['projects']}")
        finally:
            server.shutdown()

        # The real Caido call requires a live sandbox and is intentionally not
        # faked here; record it as the remaining spike gap.
        return Result(
            "S4",
            "Caido discovery mechanics",
            "PARTIAL",
            "project-id parsing and guest GraphQL shape verified; live Caido needs a Strix sandbox run",
            evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return Result("S4", "Caido discovery mechanics", "FAIL", f"{type(exc).__name__}: {exc}", evidence)
