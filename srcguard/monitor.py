"""P0-F4: background violation monitor (Caido/egress -> kill)."""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from pathlib import Path

from .kill import KillSwitch
from .method_guard import normalize_path
from .rate import HostRateLimiter
from .noise import is_browser_telemetry
from .scope import CompiledPolicy, host_allowed


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def resolve_ips(host: str) -> list[str]:
    """Resolve a host for the scope check; failures return an empty list."""
    if not host:
        return []
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError:
        return []
    out: list[str] = []
    for info in infos:
        value = str(info[4][0])
        if value not in out:
            out.append(value)
    return out


def _destinations(entries: set[str]) -> tuple[list[ipaddress.IPv4Address | ipaddress.IPv6Address], list]:
    addrs: list = []
    networks: list = []
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if network.num_addresses == 1:
            addrs.append(network.network_address)
        else:
            networks.append(network)
    return addrs, networks


def destinations_reachable(ips: list[str], allowed: set[str]) -> bool:
    """True when any resolved address sits inside the cage's allow set."""
    addrs, networks = _destinations(allowed)
    for value in ips:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if ip in addrs:
            return True
        for network in networks:
            if ip.version == network.version and ip in network:
                return True
    return False


def watch(
    run_dir: Path,
    compiled: CompiledPolicy,
    proc,
    kill: KillSwitch,
    stop: threading.Event,
    *,
    interval_s: float = 1.0,
    limiter: HostRateLimiter | None = None,
    kill_on_oob: bool = False,
    allowed_ips: set[str] | None = None,
    deny_methods: tuple[str, ...] | list[str] = (),
    post_mode: str = "open",
    post_allow_paths: tuple[str, ...] | list[str] = (),
    post_deny_paths: tuple[str, ...] | list[str] = (),
    post_deny_keywords: tuple[str, ...] | list[str] = (),
) -> str | None:
    """Return the violation reason if the process was tripped.

    ``allowed_ips`` is the cage's allow set (in-scope destinations plus the
    guard's own OOB/lab/DNS addresses). An out-of-scope host that cannot resolve
    into that set was dropped by the cage, so it is recorded as a blocked
    attempt instead of killing the run; data never left the sandbox.
    """
    caido = run_dir / "audit" / "caido.jsonl"
    egress = run_dir / "audit" / "egress.jsonl"
    oob = run_dir / "audit" / "oob.jsonl"
    blocked_path = run_dir / "audit" / "blocked.jsonl"
    writes_path = run_dir / "audit" / "writes.jsonl"
    seen: set[str] = set()
    resolved: dict[str, list[str]] = {}
    while not stop.is_set():
        if kill_on_oob:
            for row in _rows(oob):
                token = str(row.get("token") or "").strip()
                key = f"oob:{token}:{row.get('ts')}"
                if key in seen:
                    continue
                seen.add(key)
                if token:
                    reason = f"oob_callback:{token}"
                    kill.trip(reason, proc)
                    return reason
        for path in (egress, caido):
            # The per-host rate limit counts HTTP requests, so only Caido rows
            # feed it; nft rows are per-packet and would trip it instantly.
            counts_for_rate = path == caido
            rows = _rows(path)
            if counts_for_rate:
                # Requests are replayed in the order the proxy saw them, otherwise
                # a late-arriving backlog would all be charged to "now".
                rows.sort(key=lambda item: item.get("createdAt") or 0)
            for row in rows:
                key = str(row.get("id") or f"{path.name}:{row.get('ts')}:{row.get('host')}")
                if key in seen:
                    continue
                seen.add(key)
                decision = str(row.get("decision") or "").lower()
                if decision in {"block", "drop"}:
                    # Already denied by nft; a blocked DNS/resolver packet is
                    # not a successful out-of-scope contact.
                    continue
                if decision == "dns":
                    # Resolver traffic the cage allowed on port 53 (host stub or
                    # DNS guard). It carries no target data and is never a scope
                    # violation by itself.
                    continue
                host = str(row.get("host") or row.get("ip") or "").strip().lower()
                if not host:
                    continue
                if is_browser_telemetry(host):
                    continue
                allowed, _ = host_allowed(compiled, host)
                if not allowed:
                    if allowed_ips is not None:
                        if host not in resolved:
                            resolved[host] = resolve_ips(host)
                        ips = resolved[host]
                        # No resolved address inside the cage allow set => the
                        # packet was dropped; nothing left the sandbox.
                        if not ips or not destinations_reachable(ips, allowed_ips):
                            # Unresolvable or outside the cage allow set: the
                            # packet never reached the target, so record it.
                            _record_blocked(blocked_path, host, ips)
                            continue
                    reason = f"out_of_scope_contact:{host}"
                    kill.trip(reason, proc)
                    return reason
                if counts_for_rate:
                    method = str(row.get("method") or "").upper()
                    path = normalize_path(str(row.get("path") or "/"))
                    query = str(row.get("query") or "").strip()
                    full = f"{path}?{query}" if query else path
                    denied = {item.upper() for item in deny_methods}
                    if method and method in denied:
                        _record_write(
                            writes_path, row, host, path, method, decision="denied_method"
                        )
                        reason = f"denied_method:{method}:{path}"
                        kill.trip(reason, proc)
                        return reason
                    if method in {"POST", "PUT", "PATCH"}:
                        hit = _post_denied(full, post_deny_paths, post_deny_keywords)
                        if not hit and method == "POST" and post_mode == "allowlist":
                            if post_allow_paths and not any(
                                path.startswith(prefix) for prefix in post_allow_paths
                            ):
                                hit = "path not allowed"
                        if hit:
                            _record_write(
                                writes_path, row, host, full, method, decision=f"denied:{hit}"
                            )
                            reason = f"post_blocked:{path}"
                            kill.trip(reason, proc)
                            return reason
                        _record_write(
                            writes_path, row, host, full, method, decision="allowed"
                        )
                if limiter is not None and counts_for_rate:
                    status = None
                    response = row.get("response")
                    if isinstance(response, dict):
                        status = response.get("code")
                    if status is None:
                        status = row.get("status")
                    if status is None and isinstance(response, dict):
                        status = response.get("statusCode")
                    created = row.get("createdAt")
                    when = (
                        float(created) / 1000.0
                        if isinstance(created, (int, float)) and created
                        else None
                    )
                    reason = limiter.check(
                        host, now=when, status=status if isinstance(status, int) else None
                    )
                    if reason:
                        kill.trip(reason, proc)
                        return reason
        if proc.poll() is not None:
            return None
        stop.wait(interval_s)
    return None


def _post_denied(path: str, deny_paths, deny_keywords) -> str | None:
    for prefix in deny_paths:
        if path.startswith(prefix):
            return f"deny path {prefix}"
    low = path.lower()
    for word in deny_keywords:
        token = str(word).strip().lower()
        if token and token in low:
            return f"deny keyword {token}"
    return None


def _record_write(
    path: Path,
    row: dict,
    host: str,
    request_path: str,
    method: str,
    *,
    decision: str,
) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        status = None
        response = row.get("response")
        if isinstance(response, dict):
            status = response.get("statusCode")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "host": host,
                        "method": method,
                        "path": request_path,
                        "status": status,
                        "decision": decision,
                        "ts": time.time(),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    except OSError:
        pass


def _record_blocked(path: Path, host: str, ips: list[str]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "host": host,
                        "ips": ips,
                        "reason": "cage_blocked",
                        "ts": time.time(),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    except OSError:
        pass


def start_monitor(
    run_dir: Path,
    compiled: CompiledPolicy,
    proc,
    kill: KillSwitch,
    stop: threading.Event,
    *,
    interval_s: float = 1.0,
    limiter: HostRateLimiter | None = None,
    kill_on_oob: bool = False,
    allowed_ips: set[str] | None = None,
    deny_methods: tuple[str, ...] | list[str] = (),
    post_mode: str = "open",
    post_allow_paths: tuple[str, ...] | list[str] = (),
    post_deny_paths: tuple[str, ...] | list[str] = (),
    post_deny_keywords: tuple[str, ...] | list[str] = (),
) -> tuple[threading.Thread, list[str]]:
    reasons: list[str] = []

    def loop() -> None:
        reason = watch(
            run_dir,
            compiled,
            proc,
            kill,
            stop,
            interval_s=interval_s,
            limiter=limiter,
            kill_on_oob=kill_on_oob,
            allowed_ips=allowed_ips,
            deny_methods=deny_methods,
            post_mode=post_mode,
            post_allow_paths=post_allow_paths,
            post_deny_paths=post_deny_paths,
            post_deny_keywords=post_deny_keywords,
        )
        if reason:
            reasons.append(reason)

    thread = threading.Thread(target=loop, name="srcguard-monitor", daemon=True)
    thread.start()
    return thread, reasons
