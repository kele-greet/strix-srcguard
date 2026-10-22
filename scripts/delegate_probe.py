"""Probe: can Strix call exec_command when the root delegates to a child?

Root system prompt says orchestrate, not hands-on test. The previous gate
directive told root to run exec_command itself, which conflicts with that. This
probe instead asks root to spawn a child with a concrete curl task.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

from scripts.ab_gateway import LabServer, _docker_gateway
from srcguard.gateway import Gateway, GatewayConfig
from srcguard.preflight import prepare_run
from srcguard.scope import compile_policy, load_scope
from srcguard.supervisor import launch


PROJECT = Path(__file__).resolve().parents[1]
WORKSPACE = PROJECT.parent
STRIX_BIN = WORKSPACE / "strix-1.7.0-linux-x86_64"
UPSTREAM = "https://api.deepseek.com/v1/chat/completions"


def main() -> int:
    model = sys.argv[1] if len(sys.argv) > 1 else "deepseek-flash"
    route = sys.argv[2] if len(sys.argv) > 2 else "gateway"
    key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if not key:
        print("DEEPSEEK_API_KEY required", file=sys.stderr)
        return 2
    base = PROJECT / "p0-gate" / "delegate-probe"
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    lab = LabServer()
    lab_host = _docker_gateway()
    target = f"http://{lab_host}:{lab.port}/"
    scope = base / "scope.yaml"
    scope.write_text(
        f"program: delegate\nin_scope: ['{lab_host}']\nbudgets:\n  max_turns: 10\n  max_budget_usd: 1\n",
        encoding="utf-8",
    )
    compiled = compile_policy(load_scope(scope))
    gateway = None
    if route == "gateway":
        gateway = Gateway(
            GatewayConfig(
                upstream_url=UPSTREAM,
                policy="",
                api_key=key,
                model_rewrite=model,
                audit_path=base / "audit" / "llm.jsonl",
            )
        )
        gateway.start()
    run_id = f"delegate-probe-{int(time.time())}"
    srcguard_run = base / run_id
    (srcguard_run / "audit").mkdir(parents=True, exist_ok=True)
    mcp_config = base / "mcp-servers.json"
    mcp_config.write_text(
        json.dumps(
            [
                {
                    "name": "srcguard",
                    "transport": "stdio",
                    "command": sys.executable,
                    "args": ["-m", "srcguard.mcp_shim"],
                    "env": {
                        "PYTHONPATH": str(PROJECT),
                        "STRIX_RUN_ID": run_id,
                        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                        "HOME": str(base),
                        "SRCGUARD_MCP_LOG": str(base / "mcp.log"),
                        "SRCGUARD_EGRESS_LOG": str(srcguard_run / "audit" / "egress.jsonl"),
                    },
                    "allowed_tools": ["sandbox_exec"],
                    "notes": "Run shell commands inside the Strix sandbox (cage applies).",
                }
            ]
        ),
        encoding="utf-8",
    )
    spec = prepare_run(
        compiled,
        [target],
        gateway_base=f"{gateway.base_url}/v1" if gateway else None,
        base_dir=base,
        run_id=run_id,
        passthrough=["--mcp-config", str(mcp_config)],
    )
    with spec.instruction_path.open("a", encoding="utf-8") as handle:
        handle.write(
            "\n\n## GATE DIRECTIVE (delegate)\n"
            "You are the root agent. Do not run hands-on tools yourself. "
            "Call create_agent exactly once with name='Lab Probe' and the task: "
            f"'Call call_mcp(connection=\"srcguard\", tool=\"sandbox_exec\", "
            f"arguments={{\"cmd\": \"curl -s -m 5 -o /dev/null -w \\\"%{{http_code}}\\\" {target}\"}}) "
            "exactly once; then call agent_finish with the observed status.' "
            "After the child reports, call finish_scan.\n"
        )
    if route == "direct":
        spec.env["STRIX_LLM"] = f"deepseek/{model}"
        spec.env["LLM_API_KEY"] = key
        spec.env["LLM_API_BASE"] = "https://api.deepseek.com"
    elif route == "responses":
        spec.env["STRIX_LLM"] = f"openai/{model}"
        spec.env["LLM_API_KEY"] = key
        spec.env["LLM_API_BASE"] = "https://api.deepseek.com/v1"
        spec.env["STRIX_API_TYPE"] = "responses"
    else:
        spec.env["STRIX_LLM"] = f"openai/{model}"
        spec.env["LLM_API_KEY"] = "gateway-local"
    spec.env["LLM_DISABLE_STREAMING"] = "1"
    spec.env["HOME"] = str(spec.run_dir)
    spec.env["XDG_CACHE_HOME"] = str(spec.run_dir / ".cache")
    spec.env["XDG_CONFIG_HOME"] = str(spec.run_dir / ".config")
    try:
        result = launch(spec, compiled, strix_bin=str(STRIX_BIN), attach_timeout_s=60, lab_hosts=[lab_host])
        runs = sorted(
            (spec.run_dir / "strix_runs").glob("*"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        run = runs[0] if runs else None
        log = (run / "strix.log").read_text(encoding="utf-8", errors="replace") if run else ""
        caido = list((spec.run_dir / "audit").glob("caido.jsonl"))
        audit = None
        if run:
            from srcguard.audit import build_audit

            shutil.copy2(spec.policy_path, run / "policy.json")
            (run / "audit").mkdir(exist_ok=True)
            if caido:
                shutil.copy2(caido[0], run / "audit" / "caido.jsonl")
            egress_src = spec.run_dir / "audit" / "egress.jsonl"
            if egress_src.exists():
                shutil.copy2(egress_src, run / "audit" / "egress.jsonl")
            audit = build_audit(run, compiled)
        report = {
            "model": model,
            "target": target,
            "exit_code": result.exit_code,
            "container_ip": result.container_ip,
            "project_id": result.project_id,
            "route": route,
            "gateway_requests": len(gateway.audit) if gateway else 0,
            "gateway_audit": gateway.audit if gateway else [],
            "create_agent": log.count("create_agent: spawned"),
            "call_mcp": log.count("Invoking tool call_mcp"),
            "exec_invocations": log.count("Invoking tool exec_command"),
            "agent_finish": log.count("Invoking tool agent_finish"),
            "finish_scan": log.count("Invoking tool finish_scan"),
            "contacted": audit.contacted if audit else [],
            "audit_status": audit.status if audit else None,
            "log_lines": len(log.splitlines()),
        }
        (base / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["exec_invocations"] else 1
    finally:
        if gateway is not None:
            gateway.stop()
        lab.stop()


if __name__ == "__main__":
    sys.exit(main())
