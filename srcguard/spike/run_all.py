"""Run all P-1 spike checks and write spike-report.md."""

from __future__ import annotations

import sys
from pathlib import Path

import os

from . import (
    s1_gateway,
    s2_nftables,
    s3_docker_api,
    s4_caido,
    s5_readonly,
    s6_child_policy,
    s7_api_spec,
    s8_evidence,
    s9_live_strix,
)
from .common import Result, env_facts, write_report


WORKSPACE = Path(__file__).resolve().parents[3]
PROJECT = Path(__file__).resolve().parents[2]
STRIX = WORKSPACE / "strix-main"


def main() -> int:
    results: list[Result] = []
    checks = [
        s1_gateway,
        s2_nftables,
        s3_docker_api,
        s4_caido,
        s5_readonly,
        s6_child_policy,
        s7_api_spec,
        s8_evidence,
    ]
    if os.environ.get("SRCGUARD_LIVE") == "1":
        checks.append(s9_live_strix)
    for module in checks:
        try:
            results.append(module.run(STRIX))
        except Exception as exc:  # noqa: BLE001
            results.append(
                Result(
                    module.__name__.split(".")[-1][:2].upper(),
                    module.__name__,
                    "FAIL",
                    f"{type(exc).__name__}: {exc}",
                )
            )

    facts = env_facts()
    report_path = PROJECT / "spike-report.md"
    write_report(results, facts, report_path)

    print(f"{'id':4} {'status':8} name")
    for result in results:
        print(f"{result.sid:4} {result.status:8} {result.name}")
    print(f"\nreport: {report_path}")
    return 0 if not any(r.status == "FAIL" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
