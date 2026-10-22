"""P0-F4: read-only Caido observer (guest token -> requests -> jsonl).

This gives the audit a host list and id->host map without touching the sandbox.
The GraphQL shapes mirror Caido's generated schema (Requests / Projects /
SelectProject).
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import httpx


LOGIN = "mutation { loginAsGuest { token { accessToken } } }"
PROJECTS = "query { projects { id name temporary } }"
SELECT = "mutation SelectProject($id: ID!) { selectProject(id: $id) { currentProject { project { id name } } } }"
REQUESTS = """
query Requests($first: Int) {
  requests(first: $first) {
    edges { node { id host method path query createdAt response { statusCode } } }
  }
}
"""


class CaidoObserver:
    def __init__(self, base_url: str, *, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token: str | None = None

    def _post(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        resp = httpx.post(
            f"{self.base_url}/graphql",
            json={"query": query, "variables": variables or {}},
            headers=headers,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("errors"):
            raise RuntimeError(f"caido graphql errors: {payload['errors']}")
        return payload.get("data") or {}

    def login(self) -> str:
        data = self._post(LOGIN)
        self.token = data["loginAsGuest"]["token"]["accessToken"]
        return self.token

    def projects(self) -> list[dict[str, Any]]:
        return list(self._post(PROJECTS).get("projects") or [])

    def select(self, project_id: str) -> dict[str, Any]:
        data = self._post(SELECT, {"id": project_id})
        return dict(data.get("selectProject") or {})

    def requests(self, *, first: int = 200) -> list[dict[str, Any]]:
        data = self._post(REQUESTS, {"first": first})
        edges = (data.get("requests") or {}).get("edges") or []
        out: list[dict[str, Any]] = []
        for edge in edges:
            node = edge.get("node") if isinstance(edge, dict) else None
            if isinstance(node, dict):
                out.append(node)
        return out

    def poll_to_jsonl(self, project_id: str, out_path: str | Path, *, first: int = 1000) -> int:
        """Rewrite the snapshot, updating rows whose response arrived later.

        Caido records the request before the upstream response exists, so a row
        written on first sight keeps ``response: null`` forever unless it is
        refreshed. Returns the number of rows that changed.
        """
        self.select(project_id)
        rows = self.requests(first=first)
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        existing: dict[str, dict[str, Any]] = {}
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict) and item.get("id"):
                    existing[str(item["id"])] = item
        changed = 0
        for row in rows:
            rid = str(row.get("id") or "")
            if not rid:
                continue
            previous = existing.get(rid)
            merged = dict(previous or {})
            merged.update(row)
            if previous and previous.get("response") is not None:
                merged["response"] = previous["response"]
            if merged != previous or rid not in existing:
                changed += 1
            existing[rid] = merged
        tmp = path.with_name(path.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            for rid in sorted(existing, key=lambda item: (existing[item].get("createdAt") or 0, item)):
                handle.write(json.dumps(existing[rid], ensure_ascii=False) + "\n")
        os.replace(tmp, path)
        return changed


def run_observer_thread(
    base_url: str,
    project_id: str,
    out_path: Path,
    stop: threading.Event,
    *,
    interval_s: float = 2.0,
) -> threading.Thread:
    log_path = out_path.with_suffix(".log")

    def log_error(message: str) -> None:
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{time.time()} {message}\n")
        except OSError:
            pass

    def loop() -> None:
        observer = CaidoObserver(base_url)
        ready = False
        for attempt in range(5):
            if stop.is_set():
                return
            try:
                observer.login()
                observer.select(project_id)
                ready = True
                break
            except Exception as exc:  # noqa: BLE001
                log_error(f"setup attempt {attempt + 1} failed: {exc}")
                stop.wait(1.0)
        if not ready:
            log_error("observer setup failed after retries")
            return
        while not stop.is_set():
            try:
                observer.poll_to_jsonl(project_id, out_path)
            except Exception as exc:  # noqa: BLE001
                log_error(f"poll failed: {exc}")
            stop.wait(interval_s)

    thread = threading.Thread(target=loop, name="srcguard-caido-observer", daemon=True)
    thread.start()
    return thread
