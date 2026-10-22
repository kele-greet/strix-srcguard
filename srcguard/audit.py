"""P0-F4 audit: contact/evidence/secret checks and compliance.md."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scope import CompiledPolicy, host_allowed
from .noise import is_browser_telemetry


SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "generic_password": re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"}]{6,}"),
}
PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "card_like": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
}


@dataclass
class AuditReport:
    run_dir: Path
    run_id: str
    status: str
    policy_hash_run: str | None
    policy_hash_expected: str
    policy_match: bool
    reports: int
    contacted: list[str]
    out_of_scope: list[str]
    evidence_issues: list[str]
    secret_hits: list[str]
    pii_hits: list[str]
    oob_events: list[dict[str, Any]] = field(default_factory=list)
    dns_events: list[dict[str, Any]] = field(default_factory=list)
    dns_blocked: list[str] = field(default_factory=list)
    method_blocked: list[dict[str, Any]] = field(default_factory=list)
    dns_oob: list[str] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=dict)
    unmapped_ips: list[str] = field(default_factory=list)
    blocked_attempts: list[str] = field(default_factory=list)
    writes: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_dir": str(self.run_dir),
            "run_id": self.run_id,
            "status": self.status,
            "policy_hash_run": self.policy_hash_run,
            "policy_hash_expected": self.policy_hash_expected,
            "policy_match": self.policy_match,
            "reports": self.reports,
            "contacted": self.contacted,
            "out_of_scope": self.out_of_scope,
            "evidence_issues": self.evidence_issues,
            "secret_hits": self.secret_hits,
            "pii_hits": self.pii_hits,
            "oob_events": self.oob_events,
            "dns_events": self.dns_events,
            "dns_blocked": self.dns_blocked,
            "method_blocked": self.method_blocked,
            "dns_oob": self.dns_oob,
            "usage": self.usage,
            "unmapped_ips": self.unmapped_ips,
            "blocked_attempts": self.blocked_attempts,
            "writes": self.writes,
            "notes": self.notes,
        }


def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def _report_text(report: dict[str, Any]) -> str:
    keys = (
        "title",
        "description",
        "impact",
        "technical_analysis",
        "poc_description",
        "evidence",
        "assumptions",
        "remediation_steps",
    )
    return "\n".join(str(report.get(key) or "") for key in keys)


def _scan(text: str, patterns: dict[str, re.Pattern[str]]) -> list[str]:
    hits: list[str] = []
    for name, pattern in patterns.items():
        for match in pattern.finditer(text):
            preview = match.group(0)[:12]
            hits.append(f"{name}:{preview}")
            if len(hits) >= 20:
                return hits
    return hits


def _resolve_artifact(root: Path) -> Path:
    """Accept either a Strix run dir or an SRCGuard run dir containing strix_runs/."""
    if (root / "run.json").exists():
        return root
    runs = sorted(
        (root / "strix_runs").glob("*") if (root / "strix_runs").is_dir() else [],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for run in runs:
        if (run / "run.json").exists():
            return run
    return root


def _jsonl_any(paths: list[Path]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in paths:
        out.extend(_jsonl(path))
    return out


def build_audit(run_dir: str | Path, compiled: CompiledPolicy) -> AuditReport:
    root = Path(run_dir)
    artifact = _resolve_artifact(root)
    run = _load_json(artifact / "run.json", {})
    reports_raw = _load_json(artifact / "vulnerabilities.json", [])
    reports = [r for r in reports_raw if isinstance(r, dict)] if isinstance(reports_raw, list) else []
    policy_doc = _load_json(root / "policy.json", {}) or _load_json(artifact / "policy.json", {})
    policy_hash_run = policy_doc.get("policy_hash") if isinstance(policy_doc, dict) else None
    policy_match = policy_hash_run == compiled.policy_hash

    egress_paths = [root / "audit" / "egress.jsonl"]
    caido_paths = [root / "audit" / "caido.jsonl"]
    oob_paths = [root / "audit" / "oob.jsonl"]
    dns_paths = [root / "audit" / "dns.jsonl"]
    method_paths = [root / "audit" / "method.jsonl"]
    if artifact != root:
        egress_paths.append(artifact / "audit" / "egress.jsonl")
        caido_paths.append(artifact / "audit" / "caido.jsonl")
        oob_paths.append(artifact / "audit" / "oob.jsonl")
        dns_paths.append(artifact / "audit" / "dns.jsonl")
        method_paths.append(artifact / "audit" / "method.jsonl")

    contacted: list[str] = []
    unmapped_ips: list[str] = []
    request_hosts: dict[str, str] = {}
    telemetry_hosts: set[str] = set()
    resolver_events = 0
    for item in _jsonl_any(egress_paths):
        decision = str(item.get("decision") or "").lower()
        if decision in {"block", "drop"}:
            continue
        if decision == "dns":
            resolver_events += 1
            continue
        mapped = str(item.get("host") or "").strip().lower()
        ip = str(item.get("ip") or "").strip().lower()
        if mapped and is_browser_telemetry(mapped):
            telemetry_hosts.add(mapped)
            continue
        if mapped:
            if mapped not in contacted:
                contacted.append(mapped)
        elif ip and ip not in unmapped_ips:
            unmapped_ips.append(ip)
    for item in _jsonl_any(caido_paths):
        rid = str(item.get("id") or "").strip()
        host = str(item.get("host") or "").strip().lower()
        if rid and host:
            request_hosts[rid] = host
        if host and is_browser_telemetry(host):
            telemetry_hosts.add(host)
            continue
        if host and host not in contacted:
            contacted.append(host)

    write_paths = [root / "audit" / "writes.jsonl"]
    if artifact != root:
        write_paths.append(artifact / "audit" / "writes.jsonl")
    writes: list[dict[str, Any]] = []
    for item in _jsonl_any(write_paths):
        method = str(item.get("method") or "").upper()
        if method in {"GET", "HEAD", ""}:
            continue
        writes.append(
            {
                "host": str(item.get("host") or "").lower(),
                "method": method,
                "path": str(item.get("path") or ""),
                "status": item.get("status"),
                "decision": str(item.get("decision") or ""),
            }
        )

    blocked_attempts: list[str] = []
    blocked_paths = [root / "audit" / "blocked.jsonl"]
    if artifact != root:
        blocked_paths.append(artifact / "audit" / "blocked.jsonl")
    for item in _jsonl_any(blocked_paths):
        host = str(item.get("host") or "").strip().lower()
        if host and host not in blocked_attempts:
            blocked_attempts.append(host)

    out_of_scope: list[str] = []
    for host in contacted:
        allowed, _ = host_allowed(compiled, host)
        if not allowed and host not in blocked_attempts:
            out_of_scope.append(host)

    evidence_issues: list[str] = []
    for report in reports:
        for rid in report.get("http_exchange_ids") or []:
            rid = str(rid)
            host = request_hosts.get(rid)
            if not host:
                evidence_issues.append(f"{report.get('id', '?')}:{rid}:unknown")
                continue
            allowed, _ = host_allowed(compiled, host)
            if not allowed:
                evidence_issues.append(f"{report.get('id', '?')}:{rid}:{host}")

    text = "\n".join(_report_text(report) for report in reports)
    usage = _load_json(root / "usage.json", {})
    if not usage:
        usage = _load_json(artifact / "usage.json", {})
    oob_events = _jsonl_any(oob_paths)
    dns_events = _jsonl_any(dns_paths)
    method_blocked = _jsonl_any(method_paths)
    oob_domain = str((compiled.oob or {}).get("domain") or "").strip().rstrip(".")
    dns_oob = sorted(
        {
            str(item.get("qname"))
            for item in dns_events
            if item.get("allowed")
            and re.match(r"^[0-9a-f]{16}\.", str(item.get("qname")))
            and oob_domain
            and str(item.get("qname")).endswith("." + oob_domain)
        }
    )
    dns_blocked = sorted(
        {
            str(item.get("qname"))
            for item in dns_events
            if item.get("qname")
            and item.get("allowed") is False
            and not str(item.get("qname")).endswith(".invalid")
        }
    )
    secret_hits = _scan(text, SECRET_PATTERNS)
    pii_hits = _scan(text, PII_PATTERNS)

    notes: list[str] = []
    for host in sorted(telemetry_hosts):
        notes.append(f"browser telemetry ignored: {host}")
    if resolver_events:
        notes.append(f"resolver DNS ignored: {resolver_events} allowed port-53 event(s)")
    if not policy_match:
        notes.append("policy hash mismatch between run/policy.json and the supplied scope")
    if not any(path.exists() for path in egress_paths):
        notes.append("no egress.jsonl: contact list may be incomplete (cage/DNS gap)")
    if not request_hosts:
        notes.append("no caido.jsonl: http_exchange_ids cannot be verified against hosts")
    if blocked_attempts:
        notes.append(
            f"blocked attempts (cage dropped, no data left): {', '.join(blocked_attempts)}"
        )

    if out_of_scope or evidence_issues or not policy_match:
        status = "fail"
    elif secret_hits or pii_hits or unmapped_ips or blocked_attempts or writes:
        status = "warn"
    else:
        status = "pass"

    return AuditReport(
        run_dir=root,
        run_id=str(run.get("run_id") or root.name),
        status=status,
        policy_hash_run=policy_hash_run,
        policy_hash_expected=compiled.policy_hash,
        policy_match=policy_match,
        reports=len(reports),
        contacted=contacted,
        out_of_scope=out_of_scope,
        evidence_issues=evidence_issues,
        secret_hits=secret_hits,
        pii_hits=pii_hits,
        oob_events=oob_events,
        dns_events=dns_events,
        dns_blocked=dns_blocked,
        method_blocked=method_blocked,
        dns_oob=dns_oob,
        usage=usage if isinstance(usage, dict) else {},
        unmapped_ips=unmapped_ips,
        blocked_attempts=blocked_attempts,
        writes=writes,
        notes=notes,
    )


def write_compliance(report: AuditReport, path: str | Path | None = None) -> Path:
    out = Path(path) if path else report.run_dir / "compliance.md"
    lines = [
        "# SRCGuard Compliance Report",
        "",
        f"- run: `{report.run_id}`",
        f"- status: **{report.status.upper()}**",
        f"- policy hash (run): `{report.policy_hash_run}`",
        f"- policy hash (expected): `{report.policy_hash_expected}`",
        f"- policy match: `{report.policy_match}`",
        f"- findings: {report.reports}",
        "",
        "## Contacted hosts",
        "",
        *([f"- `{host}`" for host in report.contacted] or ["- (none recorded)"]),
        "",
        "## Out of scope",
        "",
        *([f"- `{host}`" for host in report.out_of_scope] or ["- none"]),
        "",
        "## Write requests (non-GET)",
        "",
        *(
            [
                f"- `{item['method']} {item['host']}{item['path']}` -> {item['status']} ({item['decision']})"
                for item in report.writes
            ]
            or ["- none"]
        ),
        "",
        "## Blocked attempts (cage dropped, no data left)",
        "",
        *([f"- `{host}`" for host in report.blocked_attempts] or ["- none"]),
        "",
        "## Evidence issues",
        "",
        *([f"- `{item}`" for item in report.evidence_issues] or ["- none"]),
        "",
        "## Secret / PII hits",
        "",
        *([f"- {item}" for item in report.secret_hits + report.pii_hits] or ["- none"]),
        "",
        "## Unmapped IPs",
        "",
        *([f"- `{ip}` (could not map to a scope host)" for ip in report.unmapped_ips] or ["- none"]),
        "",
        "## OOB callbacks",
        "",
        *([f"- token `{item.get('token')}` path `{item.get('path')}` from `{item.get('remote')}`" for item in report.oob_events] or ["- none"]),
        "",
        "## DNS queries blocked by guard",
        "",
        *([f"- `{name}`" for name in report.dns_blocked] or ["- none"]),
        "",
        "## DNS OOB labels observed",
        "",
        *([f"- `{name}`" for name in report.dns_oob] or ["- none"]),
        "",
        "## HTTP methods blocked by MCP guard",
        "",
        *(
            [
                f"- `{item.get('method')}`: `{str(item.get('cmd') or '')[:120]}`"
                for item in report.method_blocked
            ]
            or ["- none"]
        ),
        "",
        "## Usage",
        "",
        *([f"- `{key}`: `{value}`" for key, value in report.usage.items()] or ["- none"]),
        "",
        "## Notes",
        "",
        *([f"- {item}" for item in report.notes] or ["- none"]),
        "",
        "## Residual risks (P1)",
        "",
        "- source writable in P1 (read-only is P2)",
        "- DNS exfiltration via Docker embedded DNS (P2)",
        "- host-side web_search is disabled by default, not network-isolated",
        "- child agents do not inherit the instruction file; network is the backstop",
        "",
        "## Incident handling",
        "",
        "- stop, report to the platform, do not self-fix, do not hide, keep the timeline.",
    ]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
