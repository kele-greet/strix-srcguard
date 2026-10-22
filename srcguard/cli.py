"""SRCGuard CLI (P0-F1: scope check/compile)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .audit import build_audit, write_compliance
from .gateway import Gateway, GatewayConfig
from .preflight import (
    PreflightError,
    prepare_resume,
    prepare_run,
    read_target_list,
    resolve_oob,
)
from .session import SessionError, load_session_cookie
from .supervisor import launch
from .scope import ScopeError, load_and_compile, write_policy


def _warnings(compiled, *, specs: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for pattern in compiled.allow:
        if pattern.startswith("*.") and pattern[2:] not in compiled.allow:
            out.append(
                f"wildcard {pattern!r} matches subdomains only, not the apex {pattern[2:]!r}; "
                "add the apex explicitly if it is in scope"
            )
    if compiled.spec_hosts and not specs:
        out.append("spec hosts were detected but no --spec path was supplied")
    if compiled.spec_hosts and not any(host in compiled.allow for host in compiled.spec_hosts):
        out.append("spec hosts were detected but not merged; set allow_spec_hosts: true or add them to in_scope")
    if compiled.web_search:
        out.append("web_search is enabled; it runs host-side and bypasses the network cage")
    return out


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        compiled = load_and_compile(args.scope, spec_paths=tuple(args.spec or ()))
    except (ScopeError, OSError, ValueError) as exc:
        print(f"srcguard: error: {exc}", file=sys.stderr)
        return 2
    if args.policy_out:
        write_policy(args.policy_out, compiled)
    if args.json:
        print(json.dumps(compiled.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"program: {compiled.program}")
        print(f"policy_hash: {compiled.policy_hash}")
        print(f"allow ({len(compiled.allow)}):")
        for item in compiled.allow:
            print(f"  - {item}")
        print(f"deny ({len(compiled.deny)}):")
        for item in compiled.deny:
            print(f"  - {item}")
        if compiled.spec_hosts:
            print(f"spec_hosts ({len(compiled.spec_hosts)}):")
            for item in compiled.spec_hosts:
                print(f"  - {item}")
        print(f"methods: deny={list(compiled.deny_methods)} allow={list(compiled.allow_methods)}")
        print(f"rate: default_rps={compiled.default_rps} burst_rps={compiled.burst_rps}")
        print(f"web_search: {'on' if compiled.web_search else 'off'}")
        for warning in _warnings(compiled, specs=tuple(args.spec or ())):
            print(f"warning: {warning}", file=sys.stderr)
    return 0


def _collect_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.target or [])
    for path in args.target_list or []:
        targets.extend(read_target_list(path))
    rest = list(args.strix_args or [])
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg in {"-t", "--target"} and i + 1 < len(rest):
            targets.append(rest[i + 1])
            i += 2
            continue
        if arg.startswith("--target="):
            targets.append(arg.split("=", 1)[1])
        i += 1
    return list(dict.fromkeys(t for t in targets if t.strip()))


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        session_cookie: str | None = None
        if args.session_cookie_file:
            session_cookie = load_session_cookie(args.session_cookie_file)
        compiled = load_and_compile(args.scope, spec_paths=tuple(args.spec or ()))
        if args.resume:
            if args.target:
                raise PreflightError("--resume cannot be combined with --target (it uses the prior run's targets)")
            spec = prepare_resume(
                compiled,
                resume_run_id=args.resume,
                base_dir=args.out_dir,
                scan_mode=args.scan_mode,
                max_turns=args.max_turns,
                max_budget=args.max_budget,
                gateway_base=args.gateway_base,
                allow_deep=args.allow_deep,
                allow_web_search=args.allow_web_search,
                passthrough=list(args.strix_args or []),
                budget_model=args.budget_model,
            )
        else:
            targets = _collect_targets(args)
            spec = prepare_run(
                compiled,
                targets,
                scan_mode=args.scan_mode,
                max_turns=args.max_turns,
                max_budget=args.max_budget,
                gateway_base=args.gateway_base,
                allow_deep=args.allow_deep,
                allow_web_search=args.allow_web_search,
                passthrough=list(args.strix_args or []),
                base_dir=args.out_dir,
                mcp=not args.no_mcp,
                max_commands=args.max_commands,
                session_cookie=bool(session_cookie),
                budget_model=args.budget_model,
            )
    except (ScopeError, PreflightError, SessionError, OSError, ValueError) as exc:
        print(f"srcguard: error: {exc}", file=sys.stderr)
        return 2

    env_view = {
        "STRIX_RUN_ID": spec.env.get("STRIX_RUN_ID"),
        "STRIX_RUN_TYPE": spec.env.get("STRIX_RUN_TYPE"),
        "STRIX_API_TYPE": spec.env.get("STRIX_API_TYPE"),
        "STRIX_TELEMETRY": spec.env.get("STRIX_TELEMETRY"),
        "LLM_API_BASE": spec.env.get("LLM_API_BASE"),
        "PERPLEXITY_API_KEY": "<cleared>" if spec.env.get("PERPLEXITY_API_KEY") == "" else None,
        "EXA_API_KEY": "<cleared>" if spec.env.get("EXA_API_KEY") == "" else None,
    }
    if args.json:
        print(
            json.dumps(
                {
                    "run_id": spec.run_id,
                    "run_dir": str(spec.run_dir),
                    "policy_hash": compiled.policy_hash,
                    "targets": spec.targets,
                    "argv": spec.argv,
                    "env": env_view,
                    "instruction": str(spec.instruction_path),
                    "policy": str(spec.policy_path),
                    "warnings": spec.warnings,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"run_id: {spec.run_id}")
        print(f"run_dir: {spec.run_dir}")
        print(f"policy_hash: {compiled.policy_hash}")
        print(f"targets: {spec.targets}")
        print(f"instruction: {spec.instruction_path}")
        print(f"argv: {spec.argv}")
        for key, value in env_view.items():
            if value is not None:
                print(f"env {key}={value}")
        for warning in spec.warnings:
            print(f"warning: {warning}", file=sys.stderr)

    if args.launch and not args.dry_run:
        strix_bin = args.strix_bin or os.environ.get("STRIX_BIN") or "strix"
        try:
            oob_host, oob_domain, public_oob = resolve_oob(
                compiled,
                host=args.oob_host,
                domain=args.oob_domain,
                public=args.public_oob,
            )
            result = launch(
                spec,
                compiled,
                strix_bin=strix_bin,
                oob_host=oob_host,
                oob_domain=oob_domain,
                docker_proxy=args.docker_proxy or args.dns_guard,
                dns_guard=args.dns_guard,
                caido_tamper=args.caido_tamper,
                public_oob=public_oob,
                kill_on_oob=args.kill_on_oob,
                max_concurrent_runs=args.max_concurrent_runs,
                lab_hosts=list(args.lab_host or []),
                session_cookie_file=args.session_cookie_file if session_cookie else None,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"srcguard: launch failed: {exc}", file=sys.stderr)
            return 1
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        print(f"launch exit={result.exit_code} container_ip={result.container_ip}")
        return result.exit_code

    if not args.dry_run:
        print(
            "srcguard: F2 only prepares the run; pass --launch for F3 cage+launch, "
            "or --dry-run to prepare only.",
            file=sys.stderr,
        )
        return 3
    return 0


def _cmd_gateway(args: argparse.Namespace) -> int:
    key = args.api_key or os.environ.get(args.api_key_env, "")
    policy = ""
    if args.policy_file:
        policy = Path(args.policy_file).read_text(encoding="utf-8")
    elif args.policy:
        policy = args.policy
    if not policy.strip():
        print("srcguard: gateway needs --policy-file or --policy", file=sys.stderr)
        return 2
    gateway = Gateway(
        GatewayConfig(
            upstream_url=args.upstream,
            policy=policy,
            api_key=key,
            model_rewrite=args.model,
            audit_path=Path(args.audit) if args.audit else None,
            price_input=args.price_input,
            price_cached=args.price_cached,
            price_output=args.price_output,
            max_cost=args.max_cost,
            max_tokens=args.max_tokens,
        )
    )
    base = gateway.start(args.listen_host, args.listen_port)
    print(f"gateway: {base}/v1 -> {args.upstream} (policy injected)")
    try:
        while True:
            import time

            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        gateway.stop()
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    try:
        compiled = load_and_compile(args.scope, spec_paths=tuple(args.spec or ()))
        report = build_audit(args.run, compiled)
    except (ScopeError, OSError, ValueError) as exc:
        print(f"srcguard: error: {exc}", file=sys.stderr)
        return 2
    path = report.run_dir / "compliance.md"
    if not args.no_write:
        write_compliance(report, path)
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"run: {report.run_id}")
        print(f"status: {report.status}")
        print(f"policy_match: {report.policy_match}")
        print(f"reports: {report.reports}")
        print(f"contacted: {report.contacted}")
        print(f"out_of_scope: {report.out_of_scope}")
        print(f"evidence_issues: {report.evidence_issues}")
        print(f"secret_hits: {report.secret_hits}")
        print(f"pii_hits: {report.pii_hits}")
        for note in report.notes:
            print(f"note: {note}")
        if not args.no_write:
            print(f"compliance: {path}")
    return 2 if report.status == "fail" else 0


def _cmd_usage(args: argparse.Namespace) -> int:
    from .usage import aggregate_usage

    root = Path(args.root)
    data = aggregate_usage(root)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        totals = data["totals"]
        print(f"runs: {totals['runs']}")
        print(f"wall_s: {totals['wall_s']:.2f}")
        print(f"commands: {totals['commands']}")
        print(f"egress_events: {totals['egress_events']}")
        print(f"tokens: {totals['input_tokens']}/{totals['output_tokens']}")
        print(f"cost: {totals['cost']}")
        for row in data["runs"]:
            print(f"  {row['run_dir']} wall={row.get('wall_s')} commands={row.get('commands')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="srcguard", description="SRC guardrails for Strix")
    sub = parser.add_subparsers(dest="command", required=True)
    usage = sub.add_parser("usage", help="aggregate per-run usage.json ledgers")
    usage.add_argument("--root", required=True, help="runs directory to scan")
    usage.add_argument("--json", action="store_true")
    usage.set_defaults(func=_cmd_usage)

    check = sub.add_parser("check", help="validate a scope.yaml and compile the policy")
    check.add_argument("--scope", required=True, help="path to scope.yaml")
    check.add_argument("--spec", action="append", default=[], help="OpenAPI/Postman path (repeatable)")
    check.add_argument("--policy-out", help="write the compiled policy JSON here")
    check.add_argument("--json", action="store_true", help="print the compiled policy as JSON")
    check.set_defaults(func=_cmd_check)

    run = sub.add_parser("run", help="prepare a guarded Strix run (dry-run in F2)")
    run.add_argument("--scope", required=True, help="path to scope.yaml")
    run.add_argument(
        "--resume",
        metavar="RUN_ID",
        help="resume a prior run (reuses its run dir, instruction and mcp config; "
        "scope must compile to the same policy hash)",
    )
    run.add_argument("--spec", action="append", default=[], help="OpenAPI/Postman path (repeatable)")
    run.add_argument("--target", action="append", default=[], help="target URL/host (repeatable)")
    run.add_argument("--target-list", action="append", default=[], help="target list file (repeatable)")
    run.add_argument("--scan-mode", choices=["quick", "standard", "deep"], default="quick")
    run.add_argument("--max-turns", type=int)
    run.add_argument("--max-budget", type=float)
    run.add_argument("--gateway-base", help="LLM gateway base URL, e.g. http://127.0.0.1:8787/v1")
    run.add_argument("--allow-deep", action="store_true", help="permit --scan-mode deep")
    run.add_argument("--allow-web-search", action="store_true", help="keep search provider keys")
    run.add_argument("--out-dir", help="base directory for srcguard_runs")
    run.add_argument(
        "--budget-model",
        help="model alias Strix should use for cost accounting (e.g. openai/gpt-4o-mini); "
        "the gateway rewrites the upstream model to the real one, so Strix's --max-budget works",
    )
    run.add_argument("--dry-run", action="store_true", help="prepare only, do not launch")
    run.add_argument("--launch", action="store_true", help="install the cage and launch Strix")
    run.add_argument("--strix-bin", help="Strix executable (default: $STRIX_BIN or 'strix')")
    run.add_argument(
        "--max-commands",
        type=int,
        help="MCP sandbox_exec command quota per run (0/unset = unlimited)",
    )
    run.add_argument(
        "--lab-host",
        action="append",
        default=[],
        help="explicit lab/OOB host exception for the cage (repeatable; e.g. 172.17.0.1)",
    )
    run.add_argument(
        "--max-concurrent-runs",
        type=int,
        default=0,
        help="max concurrent SRCGuard runs for this user (0 = unlimited)",
    )
    run.add_argument(
        "--kill-on-oob",
        action="store_true",
        help="stop the run on the first OOB callback (default: keep scanning)",
    )
    run.add_argument(
        "--public-oob",
        action="store_true",
        help="expose the local HTTP OOB through a Cloudflare quick tunnel",
    )
    run.add_argument(
        "--caido-tamper",
        action="store_true",
        help="rewrite denied methods (e.g. DELETE) to GET at Caido MITM (downgrade, not drop)",
    )
    run.add_argument(
        "--dns-guard",
        action="store_true",
        help="force sandbox DNS to the SRCGuard resolver (implies --docker-proxy; needs bin/srcguard-dnsguard)",
    )
    run.add_argument(
        "--docker-proxy",
        action="store_true",
        help="route Strix Docker API via the P2 mutation proxy (drop NET_ADMIN, reject privileged/host netns, ro bind mounts)",
    )
    run.add_argument("--oob-host", help="advertised host/IP of the self-hosted OOB callback")
    run.add_argument("--oob-domain", help="optional DNS suffix for OOB tokens")
    run.add_argument("--no-mcp", action="store_true", help="disable the srcguard MCP sandbox_exec shim")
    run.add_argument(
        "--session-cookie-file",
        help="0600 file holding a Cookie header value for authenticated runs (never copied into the run dir)",
    )
    run.add_argument("--json", action="store_true", help="print the run spec as JSON")
    run.add_argument("strix_args", nargs=argparse.REMAINDER, help="extra args passed to Strix")
    run.set_defaults(func=_cmd_run)

    gateway = sub.add_parser("gateway", help="run the OpenAI-compatible policy gateway")
    gateway.add_argument("--upstream", required=True, help="full upstream chat/completions URL")
    gateway.add_argument("--policy-file", help="file with the policy text")
    gateway.add_argument("--policy", help="inline policy text")
    gateway.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    gateway.add_argument("--api-key", help="explicit upstream API key (prefer env)")
    gateway.add_argument("--model", help="rewrite the model field")
    gateway.add_argument("--listen-host", default="127.0.0.1")
    gateway.add_argument("--listen-port", type=int, default=8787)
    gateway.add_argument("--audit", help="audit jsonl path")
    gateway.add_argument("--price-input", type=float, default=0.0, help="USD per 1M input tokens (cache miss)")
    gateway.add_argument("--price-cached", type=float, default=0.0, help="USD per 1M cached input tokens")
    gateway.add_argument("--price-output", type=float, default=0.0, help="USD per 1M output tokens")
    gateway.add_argument("--max-cost", type=float, default=0.0, help="stop serving when accumulated cost reaches this USD value")
    gateway.add_argument("--max-tokens", type=int, default=0, help="stop serving when total tokens reach this value")
    gateway.set_defaults(func=_cmd_gateway)

    audit = sub.add_parser("audit", help="audit a run and write compliance.md")
    audit.add_argument("--run", required=True, help="srcguard_runs/<run_id> directory")
    audit.add_argument("--scope", required=True, help="path to scope.yaml used for the run")
    audit.add_argument("--spec", action="append", default=[], help="OpenAPI/Postman path (repeatable)")
    audit.add_argument("--json", action="store_true", help="print the audit report as JSON")
    audit.add_argument("--no-write", action="store_true", help="do not write compliance.md")
    audit.set_defaults(func=_cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
