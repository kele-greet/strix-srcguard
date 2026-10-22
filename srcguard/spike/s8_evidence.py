"""S8: evidence host check (http_exchange_ids must resolve to in-scope hosts)."""

from __future__ import annotations

from pathlib import Path

from .common import Result
from srcguard.scope import host_allowed, load_scope


def find_out_of_scope(reports: list[dict], request_hosts: dict[str, str], policy) -> list[str]:
    bad: list[str] = []
    for report in reports:
        for rid in report.get("http_exchange_ids") or []:
            host = request_hosts.get(rid)
            if host is None:
                bad.append(f"{report.get('id')}:{rid}:unknown")
                continue
            allowed, _ = host_allowed(policy, host)
            if not allowed:
                bad.append(f"{report.get('id')}:{rid}:{host}")
    return bad


def run(root: Path) -> Result:
    evidence: list[str] = []
    try:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            scope_path = Path(tmp) / "scope.yaml"
            scope_path.write_text("program: x\nin_scope: ['*.example.com']\n", encoding="utf-8")
            policy = load_scope(scope_path)
            reports = [
                {"id": "v1", "http_exchange_ids": ["req-1", "req-2"]},
                {"id": "v2", "http_exchange_ids": ["req-3"]},
            ]
            hosts = {"req-1": "api.example.com", "req-2": "evil.test", "req-3": "missing.test"}
            bad = find_out_of_scope(reports, hosts, policy)
            evidence.append(f"out_of_scope={bad}")
            assert bad == ["v1:req-2:evil.test", "v2:req-3:missing.test"]
        return Result(
            "S8",
            "evidence host check",
            "PASS",
            "out-of-scope and unknown exchange ids are detected before the report is accepted",
            evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return Result("S8", "evidence host check", "FAIL", f"{type(exc).__name__}: {exc}", evidence)
