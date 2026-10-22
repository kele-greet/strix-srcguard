"""P2-2: downgrade denied HTTP methods at Caido's MITM layer.

Caido tamper rules can replace the request method before the target sees it.
We create rules ``DELETE -> GET`` (and the same for other denied methods) for
proxy traffic, enable them for the run, and delete the collection on stop.
This is a downgrade, not a drop: the target never receives DELETE, but it may
still process the GET. Intercept/pause is not used (it pauses everything in
this Caido version).
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx


class CaidoTamperError(RuntimeError):
    """The tamper guard could not be installed."""


SOURCE_VALUES = ["INTERCEPT", "REPLAY", "AUTOMATE"]


def httpql_method(code: str) -> str:
    return " or ".join(f'req.method.eq:"{method.upper()}"' for method in sorted(code))


@dataclass
class CaidoTamperConfig:
    base_url: str
    denied: set[str]
    audit_path: Path | None = None
    timeout_s: float = 10.0


class CaidoTamperGuard:
    def __init__(self, config: CaidoTamperConfig) -> None:
        self.config = config
        self.token = ""
        self.collection_id: str | None = None
        self.rules: list[dict[str, Any]] = []
        self._client: httpx.Client | None = None

    def _gql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._client is None:
            raise CaidoTamperError("tamper guard is not started")
        response = self._client.post(
            "/graphql",
            json={"query": query, "variables": variables or {}},
            headers={"Authorization": f"Bearer {self.token}"} if self.token else {},
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("errors"):
            raise CaidoTamperError(str(payload["errors"])[:500])
        return payload.get("data") or {}

    def _login(self) -> None:
        data = self._gql("mutation LoginAsGuest { loginAsGuest { token { accessToken } } }")
        token = data.get("loginAsGuest", {}).get("token", {}).get("accessToken", "")
        if not token:
            raise CaidoTamperError("Caido guest login returned no token")
        self.token = token

    def _ensure_project(self) -> None:
        current = self._gql("{ currentProject { project { id } } }").get("currentProject")
        if current:
            return
        projects = self._gql("{ projects { id } }").get("projects") or []
        if not projects:
            created = self._gql(
                'mutation { createProject(input:{name:"srcguard-tamper", temporary:true}) '
                "{ project { id } error { __typename } } }"
            ).get("createProject", {})
            projects = [created["project"]] if created.get("project") else []
        if not projects:
            raise CaidoTamperError("Caido has no project and could not create one")
        self._gql(
            "mutation($id:ID!){ selectProject(id:$id){ currentProject { project { id } } } }",
            {"id": projects[0]["id"]},
        )

    def _audit(self, row: dict[str, Any]) -> None:
        if self.config.audit_path is None:
            return
        row = {"ts": time.time(), **row}
        self.config.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.config.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def start(self) -> None:
        self._client = httpx.Client(base_url=self.config.base_url, timeout=self.config.timeout_s)
        try:
            self._login()
            self._ensure_project()
            created = self._gql(
                'mutation { createTamperRuleCollection(input:{name:"srcguard-method-guard"}) '
                "{ collection { id name } } }"
            ).get("createTamperRuleCollection", {}).get("collection", {})
            self.collection_id = created.get("id")
            if not self.collection_id:
                raise CaidoTamperError("could not create tamper collection")
            condition = httpql_method(self.config.denied)
            for method in sorted(self.config.denied):
                data = self._gql(
                    "mutation($input:CreateTamperRuleInput!){ createTamperRule(input:$input){ "
                    "rule { id name } error { __typename } } }",
                    {
                        "input": {
                            "collectionId": self.collection_id,
                            "name": f"srcguard-{method.lower()}-to-get",
                            "section": {
                                "requestMethod": {
                                    "operation": {"update": {"replacer": {"term": {"term": "GET"}}}}
                                }
                            },
                            "condition": {"HTTPQL": {"code": condition}},
                            "sources": SOURCE_VALUES,
                        }
                    },
                )
                rule = data.get("createTamperRule", {}).get("rule")
                if not rule:
                    raise CaidoTamperError(f"could not create tamper rule for {method}")
                self._gql(
                    "mutation($id:ID!){ toggleTamperRule(id:$id, enabled:true){ rule { id } "
                    "error { __typename } } }",
                    {"id": rule["id"]},
                )
                self.rules.append({"id": rule["id"], "method": method})
                self._audit(
                    {
                        "event": "method_downgraded",
                        "method": method,
                        "to": "GET",
                        "rule_id": rule["id"],
                        "source": "caido_tamper",
                    }
                )
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        if self._client is not None and self.collection_id:
            try:
                self._gql(
                    "mutation($id:ID!){ deleteTamperRuleCollection(id:$id){ deletedId } }",
                    {"id": self.collection_id},
                )
            except Exception:  # noqa: BLE001
                pass
        if self._client is not None:
            self._client.close()
            self._client = None
        self.collection_id = None
        self.rules = []
