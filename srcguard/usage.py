"""P2-6: per-run usage accounting (not a quota)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def build_usage(run_dir: Path, *, wall_s: float, container_ip: str | None = None) -> dict[str, Any]:
    audit = run_dir / "audit"
    egress = _jsonl(audit / "egress.jsonl")
    hosts = sorted({str(row.get("host") or row.get("ip")) for row in egress if row.get("host") or row.get("ip")})
    commands = 0
    count_path = audit / "commands.count"
    if count_path.exists():
        try:
            commands = int(count_path.read_text(encoding="utf-8").strip() or "0")
        except (OSError, ValueError):
            commands = 0
    if commands == 0:
        mcp = audit / "mcp.log"
        if mcp.exists():
            commands = sum(1 for line in mcp.read_text(encoding="utf-8", errors="replace").splitlines() if line.startswith("cmd="))
    run_json = {}
    for child in sorted((run_dir / "strix_runs").glob("*/run.json")):
        try:
            run_json = json.loads(child.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
    usage = run_json.get("llm_usage") or {}
    return {
        "wall_s": round(wall_s, 2),
        "container_ip": container_ip,
        "commands": commands,
        "egress_events": len(egress),
        "egress_hosts": hosts,
        "input_tokens": usage.get("input_tokens", 0),
        "output_tokens": usage.get("output_tokens", 0),
        "cost": usage.get("cost", 0.0),
    }


def aggregate_usage(root: Path) -> dict[str, Any]:
    totals = {"runs": 0, "wall_s": 0.0, "commands": 0, "egress_events": 0, "input_tokens": 0, "output_tokens": 0, "cost": 0.0}
    rows: list[dict[str, Any]] = []
    for path in sorted(root.glob("**/usage.json")):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(item, dict):
            continue
        rows.append({"run_dir": str(path.parent), **item})
        totals["runs"] += 1
        for key in ("wall_s", "commands", "egress_events", "input_tokens", "output_tokens", "cost"):
            value = item.get(key, 0)
            if isinstance(value, (int, float)):
                totals[key] += value
    return {"totals": totals, "runs": rows}


def write_usage(run_dir: Path, **kwargs: Any) -> Path:
    path = run_dir / "usage.json"
    path.write_text(json.dumps(build_usage(run_dir, **kwargs), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path
