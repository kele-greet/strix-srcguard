"""Shared helpers for the P-1 spike."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Result:
    sid: str
    name: str
    status: str  # PASS | FAIL | BLOCKED | PARTIAL
    detail: str
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "sid": self.sid,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "evidence": self.evidence,
        }


def run_cmd(cmd: list[str], *, timeout: int = 30, env: dict[str, str] | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, **(env or {})},
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out.strip()
    except Exception as exc:  # noqa: BLE001
        return 127, f"{type(exc).__name__}: {exc}"


def env_facts() -> dict[str, str]:
    facts = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "user": str(os.getuid()) if hasattr(os, "getuid") else "n/a",
    }
    for key, cmd in {
        "nft": ["nft", "--version"],
        "docker": ["docker", "--version"],
        "docker_info": ["docker", "info", "--format", "{{.OperatingSystem}} | {{.KernelVersion}}"],
        "sudo": ["sh", "-c", "sudo -n true 2>&1 || true"],
    }.items():
        rc, out = run_cmd(cmd, timeout=15)
        facts[key] = f"rc={rc} {out.splitlines()[0] if out else ''}"
    return facts


def write_report(results: list[Result], facts: dict[str, str], path: Path) -> None:
    lines = ["# SRCGuard P-1 Spike Report", ""]
    lines.append("## Environment")
    lines.append("")
    lines.append("| key | value |")
    lines.append("|---|---|")
    for key, value in facts.items():
        lines.append(f"| {key} | `{value}` |")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append("| id | 测试 | 状态 | 说明 |")
    lines.append("|---|---|---|---|")
    for result in results:
        lines.append(f"| {result.sid} | {result.name} | **{result.status}** | {result.detail} |")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    for result in results:
        lines.append(f"### {result.sid} {result.name} — {result.status}")
        lines.append("")
        for item in result.evidence:
            lines.append(f"- `{item}`")
        lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def jdump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)
