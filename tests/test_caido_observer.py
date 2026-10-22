from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from srcguard.caido_observer import CaidoObserver


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # noqa: N802, ANN002
        return

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        if "loginAsGuest" in body:
            payload = {"data": {"loginAsGuest": {"token": {"accessToken": "guest"}}}}
        elif "selectProject" in body:
            payload = {"data": {"selectProject": {"currentProject": {"project": {"id": "p1", "name": "sandbox"}}}}}
        elif "projects" in body:
            payload = {"data": {"projects": [{"id": "p1", "name": "sandbox", "temporary": True}]}}
        elif "requests" in body:
            payload = {
                "data": {
                    "requests": {
                        "edges": [
                            {"node": {"id": "r1", "host": "api.example.com", "method": "GET", "path": "/"}},
                            {"node": {"id": "r2", "host": "evil.test", "method": "POST", "path": "/x"}},
                        ]
                    }
                }
            }
        else:
            payload = {"data": {}}
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class PollUpdateTests(unittest.TestCase):
    def test_response_is_written_when_it_arrives(self) -> None:
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "caido.jsonl"
            observer = CaidoObserver("http://127.0.0.1:1")
            first = [
                {"id": "1", "host": "api.example.com", "method": "GET", "path": "/", "createdAt": 1, "response": None},
            ]
            second = [
                {"id": "1", "host": "api.example.com", "method": "GET", "path": "/", "createdAt": 1, "response": {"statusCode": 200}},
            ]
            with (
                mock.patch.object(observer, "select", return_value={}),
                mock.patch.object(observer, "requests", side_effect=[first, second]),
            ):
                observer.poll_to_jsonl("p1", out)
                self.assertIn("null", out.read_text(encoding="utf-8"))
                observer.poll_to_jsonl("p1", out)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["response"], {"statusCode": 200})

    def test_row_survives_leaving_the_window(self) -> None:
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "caido.jsonl"
            observer = CaidoObserver("http://127.0.0.1:1")
            first = [{"id": "1", "host": "a.test", "method": "GET", "path": "/", "createdAt": 1}]
            second = [{"id": "2", "host": "b.test", "method": "GET", "path": "/", "createdAt": 2}]
            with (
                mock.patch.object(observer, "select", return_value={}),
                mock.patch.object(observer, "requests", side_effect=[first, second]),
            ):
                observer.poll_to_jsonl("p1", out)
                observer.poll_to_jsonl("p1", out)
            ids = [json.loads(line)["id"] for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(ids, ["1", "2"])


class ObserverTests(unittest.TestCase):
    def test_default_window_is_large_enough_for_a_run(self) -> None:
        import inspect

        from srcguard.caido_observer import CaidoObserver

        signature = inspect.signature(CaidoObserver.poll_to_jsonl)
        self.assertGreaterEqual(signature.parameters["first"].default, 1000)

    def test_query_includes_url_query_string(self) -> None:
        from srcguard.caido_observer import REQUESTS

        self.assertIn("query", REQUESTS)

    def test_query_uses_caido_statuscode(self) -> None:
        from srcguard.caido_observer import REQUESTS

        self.assertIn("statusCode", REQUESTS)
        self.assertNotIn("response { code }", REQUESTS)

    def test_login_select_requests_poll_jsonl(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            observer = CaidoObserver(f"http://127.0.0.1:{server.server_address[1]}")
            self.assertEqual(observer.login(), "guest")
            self.assertEqual(observer.projects()[0]["id"], "p1")
            self.assertEqual(observer.requests()[0]["host"], "api.example.com")
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "caido.jsonl"
                self.assertEqual(observer.poll_to_jsonl("p1", out), 2)
                self.assertEqual(observer.poll_to_jsonl("p1", out), 0)
                text = out.read_text(encoding="utf-8")
                self.assertIn("r1", text)
                self.assertIn("evil.test", text)
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
