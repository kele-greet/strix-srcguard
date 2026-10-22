"""P0-F2 preflight: validate targets, render instruction, build Strix argv/env."""

from __future__ import annotations

import json
import os
import secrets
import string
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scope import CompiledPolicy, host_allowed, url_allowed, write_policy
from .session import COOKIE_CONTAINER_PATH


class PreflightError(ValueError):
    """The requested run violates the compiled scope."""


@dataclass
class RunSpec:
    run_id: str
    run_dir: Path
    argv: list[str]
    env: dict[str, str]
    instruction_path: Path
    policy_path: Path
    targets: list[str]
    mcp_config_path: Path | None = None
    warnings: list[str] = field(default_factory=list)


def _is_local_path(target: str) -> bool:
    return target.startswith(("/", "./", "../", "~")) or (
        "/" not in target and "." not in target and not target.startswith("http")
    )


def validate_target(compiled: CompiledPolicy, target: str) -> str:
    """Validate one target against the compiled allow/deny lists."""
    value = target.strip()
    if not value:
        raise PreflightError("empty target")
    if _is_local_path(value):
        raise PreflightError(
            f"local path target is not supported by SRCGuard: {value!r}; "
            "use a URL/host, or run Strix directly for local code review"
        )
    if "://" in value:
        allowed, reason = url_allowed(compiled, value)  # type: ignore[arg-type]
    else:
        host = value.split("/", 1)[0].split("?", 1)[0]
        allowed, reason = host_allowed(compiled, host)  # type: ignore[arg-type]
    if not allowed:
        raise PreflightError(f"target {value!r} is not in scope: {reason}")
    return value


def read_target_list(path: str | Path) -> list[str]:
    targets: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def resolve_oob(
    compiled: CompiledPolicy,
    *,
    host: str | None = None,
    domain: str | None = None,
    public: bool = False,
) -> tuple[str | None, str | None, bool]:
    """Resolve the OOB settings: CLI flags win, then the scope's ``oob`` block.

    ``oob.mode: http`` in scope.yaml turns the callback server on without extra
    flags; ``oob.public: true`` also starts the Cloudflare tunnel.
    """
    cfg = compiled.oob if isinstance(compiled.oob, dict) else {}
    mode = str(cfg.get("mode") or "off").strip().lower()
    resolved_host = (host or "").strip()
    if not resolved_host and mode in {"http", "self_hosted", "local"}:
        resolved_host = str(cfg.get("host") or "127.0.0.1").strip() or "127.0.0.1"
    resolved_domain = (domain or "").strip() or str(cfg.get("domain") or "").strip() or None
    resolved_public = bool(public or cfg.get("public"))
    return (resolved_host or None), resolved_domain, resolved_public


def _bullets(values: tuple[str, ...] | list[str]) -> str:
    return "\n".join(f"  - {value}" for value in values) if values else "  （无）"


def render_instruction(
    compiled: CompiledPolicy,
    targets: list[str],
    *,
    run_id: str,
    max_turns: int,
    max_budget: float,
    web_search: bool,
    oob_mode: str,
    oob_domain: str,
    deny_methods: tuple[str, ...],
    allow_methods: tuple[str, ...],
    max_body_bytes: int,
    default_rps: int,
    burst_rps: int,
) -> str:
    template = (Path(__file__).parent / "templates" / "instruction.md").read_text(encoding="utf-8")
    ssrf = compiled.ssrf
    values = {
        "policy_hash": compiled.policy_hash,
        "allowlist": _bullets([*compiled.allow, *[f"(run target) {t}" for t in targets]]),
        "denylist": _bullets(compiled.deny),
        "ssrf_max": str(ssrf.get("max_requests", 3)),
        "ssrf_methods": ", ".join(ssrf.get("methods", ["GET"])),
        "ssrf_paths": _bullets(ssrf.get("metadata_paths", [])),
        "ssrf_denied": _bullets(ssrf.get("denied_paths", [])),
        "ssrf_bytes": str(ssrf.get("max_response_bytes", 4096)),
        "deny_methods": ", ".join(deny_methods),
        "allow_methods": ", ".join(allow_methods),
        "max_body_bytes": str(max_body_bytes),
        "default_rps": str(default_rps),
        "burst_rps": str(burst_rps),
        "oob_mode": oob_mode,
        "oob_domain": oob_domain,
        "web_search": "开启" if web_search else "关闭",
        "post_mode": compiled.post_mode,
        "post_deny_keywords": ", ".join(compiled.post_deny_keywords) or "（无）",
        "post_allow_paths": _bullets(compiled.post_allow_paths),
        "post_deny_paths": _bullets(compiled.post_deny_paths),
        "run_marker": f"SRCGUARD-{run_id}",
        "max_turns": str(max_turns),
        "max_budget": f"{max_budget:.2f}",
    }
    return string.Template(template).substitute(values)


def _strip_conflicting(args: list[str], warnings: list[str]) -> list[str]:
    """Drop flags SRCGuard owns; warn instead of silently letting them override."""
    owned_with_value = {
        "-t",
        "--target",
        "--target-list",
        "-m",
        "--scan-mode",
        "--max-turns",
        "--max-budget",
        "--max-budget-usd",
        "--instruction-file",
        "--instruction",
    }
    owned_switch = {"-n", "--non-interactive"}
    out: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            i += 1
            continue
        if arg in owned_switch:
            warnings.append(f"dropped {arg}: SRCGuard controls run mode")
            i += 1
            continue
        if arg in owned_with_value:
            warnings.append(f"dropped {arg}: SRCGuard controls this field")
            i += 2
            continue
        if any(arg.startswith(name + "=") for name in owned_with_value):
            warnings.append(f"dropped {arg.split('=', 1)[0]}: SRCGuard controls this field")
            i += 1
            continue
        out.append(arg)
        i += 1
    return out


def _private_targets(targets: list[str]) -> list[str]:
    """Literal private targets must bypass Caido; otherwise lab curls get an empty proxy reply."""
    import ipaddress
    from urllib.parse import urlparse

    out: list[str] = []
    for target in targets:
        host = urlparse(target).hostname if "://" in target else target.split("/", 1)[0].split(":", 1)[0]
        if not host:
            continue
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            continue
        if ip.is_private and host not in out:
            out.append(host)
    return out


def _apply_budget_model(
    env: dict[str, str], budget_model: str, *, gateway_base: str | None, warnings: list[str]
) -> None:
    """Point Strix's cost accounting at a priced model alias.

    LiteLLM has no price for e.g. ``deepseek-flash``, so Strix's own
    ``--max-budget`` would never fire. ``--budget-model`` sets the name Strix sees
    while the gateway rewrites the upstream model to the real one.
    """
    env["STRIX_LLM"] = budget_model
    warnings.append(
        f"budget accounting model: {budget_model} (start the gateway with --model <real model>)"
    )
    if not gateway_base:
        warnings.append(
            "--budget-model without --gateway-base: the upstream will receive the alias model name"
        )


def prepare_run(
    compiled: CompiledPolicy,
    targets: list[str],
    *,
    scan_mode: str = "quick",
    max_turns: int | None = None,
    max_budget: float | None = None,
    gateway_base: str | None = None,
    allow_deep: bool = False,
    allow_web_search: bool = False,
    passthrough: list[str] | None = None,
    base_dir: str | Path | None = None,
    run_id: str | None = None,
    mcp: bool = True,
    max_commands: int | None = None,
    session_cookie: bool = False,
    budget_model: str | None = None,
) -> RunSpec:
    warnings: list[str] = []
    if scan_mode not in {"quick", "standard", "deep"}:
        raise PreflightError(f"unknown scan mode: {scan_mode!r}")
    if scan_mode == "deep" and not allow_deep:
        raise PreflightError("deep mode requires --allow-deep (more intrusive, more turns)")
    if not targets:
        raise PreflightError("at least one target is required")

    validated = [validate_target(compiled, target) for target in targets]
    budgets = compiled.budgets or {}
    if max_turns is None:
        max_turns = int(budgets.get("max_turns", 150))
    if max_turns <= 0:
        raise PreflightError("max_turns must be > 0")
    if max_budget is None:
        max_budget = float(budgets.get("max_budget_usd", 20))
    if max_budget <= 0:
        raise PreflightError("max_budget must be > 0")

    if run_id is None:
        run_id = f"srcguard-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"
    root = Path(base_dir or (Path.cwd() / "srcguard_runs")) / run_id
    root.mkdir(parents=True, exist_ok=True)
    policy_path = write_policy(root / "policy.json", compiled)

    run_targets = list(dict.fromkeys(validated))
    instruction = render_instruction(
        compiled,
        run_targets,
        run_id=run_id,
        max_turns=max_turns,
        max_budget=max_budget,
        web_search=allow_web_search,
        oob_mode=str((compiled.oob or {}).get("mode", "off")),
        oob_domain=str((compiled.oob or {}).get("domain", "")),
        deny_methods=compiled.deny_methods,
        allow_methods=compiled.allow_methods,
        max_body_bytes=compiled.max_body_bytes,
        default_rps=compiled.default_rps,
        burst_rps=compiled.burst_rps,
    )
    if session_cookie:
        instruction += (
            "\n\n## 登录态（已注入）\n"
            f"- Cookie 已写入容器内 `{COOKIE_CONTAINER_PATH}`（0600），内容即 `Cookie:` 头值。\n"
            '- 用法：`curl -H "Cookie: $(cat '
            f'{COOKIE_CONTAINER_PATH})" <url>`；浏览器/代理请求请手动带上同一 Cookie。\n'
            "- 不要 `cat` 该文件、不要把值写进报告或日志、不要发到任何外部服务；\n"
            "- 该会话是操作者提供的授权测试账号，视同你自己的账号：不要注册新账号、不要使用其他账号；\n"
            "- 只允许用它访问授权范围内的 host，发现会话越权立即停止并记录。"
        )
    instruction_path = root / "instruction.md"
    mcp_config_path: Path | None = None
    if mcp:
        (root / "audit").mkdir(parents=True, exist_ok=True)
        mcp_config_path = root / "mcp-servers.json"
        project_root = Path(__file__).resolve().parents[1]
        pythonpath = os.pathsep.join(
            part for part in (str(project_root), os.environ.get("PYTHONPATH", "")) if part
        )
        mcp_config_path.write_text(
            json.dumps(
                [
                    {
                        "name": "srcguard",
                        "transport": "stdio",
                        "command": sys.executable,
                        "args": ["-m", "srcguard.mcp_shim"],
                        "env": {
                            "PYTHONPATH": pythonpath,
                            "STRIX_RUN_ID": run_id,
                            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                            "HOME": str(root),
                            "SRCGUARD_MCP_LOG": str(root / "audit" / "mcp.log"),
                            "SRCGUARD_EGRESS_LOG": str(root / "audit" / "egress.jsonl"),
                            **(
                                {"DOCKER_HOST": os.environ["DOCKER_HOST"]}
                                if os.environ.get("DOCKER_HOST")
                                else {}
                            ),
                            **(
                                {"SRCGUARD_DENY_METHODS": ",".join(compiled.deny_methods)}
                                if compiled.deny_methods
                                else {}
                            ),
                            **{"SRCGUARD_POST_MODE": compiled.post_mode},
                            **(
                                {"SRCGUARD_POST_ALLOW_PATHS": ",".join(compiled.post_allow_paths)}
                                if compiled.post_allow_paths
                                else {}
                            ),
                            **(
                                {
                                    "SRCGUARD_POST_DENY_KEYWORDS": ",".join(
                                        compiled.post_deny_keywords
                                    )
                                }
                                if compiled.post_deny_keywords
                                else {}
                            ),
                            **(
                                {"SRCGUARD_POST_DENY_PATHS": ",".join(compiled.post_deny_paths)}
                                if compiled.post_deny_paths
                                else {}
                            ),
                            **(
                                {
                                    "SRCGUARD_MAX_COMMANDS": str(max_commands),
                                    "SRCGUARD_COMMAND_COUNT": str(root / "audit" / "commands.count"),
                                }
                                if max_commands
                                else {}
                            ),
                        },
                        "allowed_tools": ["sandbox_exec"],
                        "notes": (
                            "Run shell commands inside the Strix sandbox. Prefer this over "
                            "exec_command when that tool is unavailable; egress is caged."
                        ),
                    }
                ]
            ),
            encoding="utf-8",
        )
        instruction = (
            instruction
            + "\n\n## MCP SANDBOX EXEC\n"
            "- Use `call_mcp(connection=\"srcguard\", tool=\"sandbox_exec\", "
            "arguments={\"cmd\": \"<shell command>\"})` when `exec_command` is "
            "unavailable or returns a tool-not-found error.\n"
            "- The command runs inside the sandbox; the same cage, rate limit and "
            "OOB rules apply.\n"
        )
    instruction_path.write_text(instruction, encoding="utf-8")

    passthrough = _strip_conflicting(list(passthrough or []), warnings)
    argv = ["-n"]
    for target in run_targets:
        argv += ["-t", target]
    argv += [
        "--scan-mode",
        scan_mode,
        "--max-turns",
        str(max_turns),
        "--max-budget",
        f"{max_budget:.2f}",
        "--instruction-file",
        str(instruction_path),
    ]
    if mcp_config_path is not None:
        argv += ["--mcp-config", str(mcp_config_path)]
    argv += passthrough

    env = dict(os.environ)
    env.update(
        {
            "STRIX_RUN_ID": run_id,
            "STRIX_RUN_TYPE": "srcguard",
            "STRIX_API_TYPE": "chat_completions",
            "STRIX_TELEMETRY": "false",
            "HOME": str(root),
            "XDG_CACHE_HOME": str(root / ".cache"),
            "XDG_CONFIG_HOME": str(root / ".config"),
        }
    )
    llm = env.get("STRIX_LLM", "").strip()
    if gateway_base:
        env["LLM_API_BASE"] = gateway_base
        warnings.append(f"LLM gateway: {gateway_base}")
    else:
        warnings.append("no --gateway-base: L2 gateway disabled; rely on network + audit")
    if llm.lower().startswith("chatgpt/"):
        warnings.append("chatgpt/ subscription bypasses LLM_API_BASE; gateway will not see it")
    if not allow_web_search:
        env["PERPLEXITY_API_KEY"] = ""
        env["EXA_API_KEY"] = ""
        warnings.append("web_search disabled (keys cleared); pass --allow-web-search to enable")
    if budget_model:
        _apply_budget_model(env, budget_model, gateway_base=gateway_base, warnings=warnings)

    return RunSpec(
        run_id=run_id,
        run_dir=root,
        argv=argv,
        env=env,
        instruction_path=instruction_path,
        policy_path=policy_path,
        targets=run_targets,
        mcp_config_path=mcp_config_path,
        warnings=warnings,
    )


def prepare_resume(
    compiled: CompiledPolicy,
    *,
    resume_run_id: str,
    base_dir: str | Path | None = None,
    scan_mode: str = "quick",
    max_turns: int | None = None,
    max_budget: float | None = None,
    gateway_base: str | None = None,
    allow_deep: bool = False,
    allow_web_search: bool = False,
    passthrough: list[str] | None = None,
    budget_model: str | None = None,
) -> RunSpec:
    """Prepare an argv that resumes a prior Strix run inside an existing run dir.

    The scope must still compile to the same policy hash as the original run,
    so a resumed scan cannot widen its own authorization.
    """
    warnings: list[str] = []
    if scan_mode not in {"quick", "standard", "deep"}:
        raise PreflightError(f"unknown scan mode: {scan_mode!r}")
    if scan_mode == "deep" and not allow_deep:
        raise PreflightError("deep mode requires --allow-deep (more intrusive, more turns)")

    base = Path(base_dir or (Path.cwd() / "srcguard_runs"))
    direct = Path(resume_run_id)
    if direct.is_dir():
        root = direct
    else:
        root = base / resume_run_id
        if not root.is_dir():
            # runs live under <base>/<program>/<run_id>
            matches = sorted(base.glob(f"*/{resume_run_id}"))
            if not matches:
                raise PreflightError(
                    f"--resume {resume_run_id}: run directory not found under {base}"
                )
            root = matches[0]
    policy_path = root / "policy.json"
    if not policy_path.exists():
        raise PreflightError(f"--resume {resume_run_id}: missing policy.json")
    recorded = json.loads(policy_path.read_text(encoding="utf-8"))
    if recorded.get("policy_hash") != compiled.policy_hash:
        raise PreflightError(
            "--resume: scope changed since that run "
            f"({recorded.get('policy_hash')} != {compiled.policy_hash}); start a fresh run instead"
        )
    instruction_path = root / "instruction.md"
    if not instruction_path.exists():
        raise PreflightError(f"--resume {resume_run_id}: missing instruction.md")

    strix_runs = sorted(
        (root / "strix_runs").glob("*/run.json"), key=lambda item: item.stat().st_mtime
    )
    if not strix_runs:
        raise PreflightError(f"--resume {resume_run_id}: no strix run found under strix_runs/")
    record_path = strix_runs[-1]
    strix_run_name = record_path.parent.name
    if not (record_path.parent / ".state" / "agents.json").exists():
        raise PreflightError(
            f"--resume {resume_run_id}: {strix_run_name} has no .state/agents.json to resume"
        )
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PreflightError(f"--resume {resume_run_id}: run.json unreadable: {exc}") from exc

    targets: list[str] = []
    for item in record.get("targets_info") or []:
        if not isinstance(item, dict):
            continue
        original = str(item.get("original") or "").strip()
        if original and original not in targets:
            targets.append(original)
    if not targets:
        raise PreflightError(f"--resume {resume_run_id}: run.json has no targets")
    validated = [validate_target(compiled, target) for target in targets]

    budgets = compiled.budgets or {}
    if max_turns is None:
        max_turns = int(budgets.get("max_turns", 150))
    if max_budget is None:
        max_budget = float(budgets.get("max_budget_usd", 20))
    if max_turns <= 0 or max_budget <= 0:
        raise PreflightError("max_turns and max_budget must be > 0")

    mcp_config_path = root / "mcp-servers.json"
    mcp_arg: list[str] = []
    if mcp_config_path.exists():
        mcp_arg = ["--mcp-config", str(mcp_config_path)]
    else:
        mcp_config_path = None

    passthrough = _strip_conflicting(list(passthrough or []), warnings)
    # strix refuses -t/--target together with --resume: the target comes from run.json
    argv = [
        "-n",
        "--resume",
        strix_run_name,
        "--scan-mode",
        scan_mode,
        "--max-turns",
        str(max_turns),
        "--max-budget",
        f"{max_budget:.2f}",
        "--instruction-file",
        str(instruction_path),
    ]
    argv += mcp_arg
    argv += passthrough

    env = dict(os.environ)
    env.update(
        {
            "STRIX_RUN_ID": resume_run_id,
            "STRIX_RUN_TYPE": "srcguard",
            "STRIX_API_TYPE": "chat_completions",
            "STRIX_TELEMETRY": "false",
            "HOME": str(root),
            "XDG_CACHE_HOME": str(root / ".cache"),
            "XDG_CONFIG_HOME": str(root / ".config"),
        }
    )
    if gateway_base:
        env["LLM_API_BASE"] = gateway_base
        warnings.append(f"LLM gateway: {gateway_base}")
    else:
        warnings.append("no --gateway-base: L2 gateway disabled; rely on network + audit")
    if not allow_web_search:
        env["PERPLEXITY_API_KEY"] = ""
        env["EXA_API_KEY"] = ""
        warnings.append("web_search disabled (keys cleared); pass --allow-web-search to enable")
    warnings.append(f"resuming strix run {strix_run_name} in {root}")
    if budget_model:
        _apply_budget_model(env, budget_model, gateway_base=gateway_base, warnings=warnings)

    return RunSpec(
        run_id=resume_run_id,
        run_dir=root,
        argv=argv,
        env=env,
        instruction_path=instruction_path,
        policy_path=policy_path,
        targets=validated,
        mcp_config_path=mcp_config_path,
        warnings=warnings,
    )
