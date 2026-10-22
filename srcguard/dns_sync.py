"""P2-4 (partial): add DNS-derived IPs for allowed wildcard names to the cage."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol


class CageLike(Protocol):
    def allow_ip(self, ip: str) -> bool: ...


Resolver = Callable[[str], list[str]]
CnameResolver = Callable[[str], list[str]]
AllowCheck = Callable[[str], bool]


@dataclass
class DnsAnswer:
    ips: list[str]
    cnames: list[str]
    ttl: int = 60


def dig_answer(name: str, server: str = "", timeout: int = 5) -> DnsAnswer:
    args = ["dig", "+noall", "+answer"]
    if server:
        args.append(f"@{server}")
    args.append(name)
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return DnsAnswer([], [], 0)
    ips: list[str] = []
    cnames: list[str] = []
    ttls: list[int] = []
    for line in (proc.stdout or "").splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        try:
            ttl = int(fields[1])
        except ValueError:
            continue
        kind = fields[3].upper()
        ttls.append(ttl)
        if kind == "CNAME" and len(fields) >= 5:
            value = fields[4].rstrip(".").lower()
            if value not in cnames:
                cnames.append(value)
        elif kind in {"A", "AAAA"} and len(fields) >= 5:
            value = fields[4]
            if value not in ips:
                ips.append(value)
    return DnsAnswer(ips, cnames, min(ttls) if ttls else 0)


def dig_cname_chain(name: str) -> list[str]:
    try:
        proc = subprocess.run(
            ["dig", "+short", "CNAME", name], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    out: list[str] = []
    for line in (proc.stdout or "").splitlines():
        value = line.strip().lower().rstrip(".")
        if value and value not in out:
            out.append(value)
    return out


def _default_resolver(name: str) -> list[str]:
    out: list[str] = []
    for info in socket.getaddrinfo(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
        ip = str(info[4][0])
        if ip not in out:
            out.append(ip)
    return out


def sync_once(
    path: Path,
    *,
    offset: int,
    seen: set[str],
    cage: CageLike,
    resolver: Resolver = _default_resolver,
    oob_path: Path | None = None,
    oob_domain: str = "",
    resolved: dict[str, set[str]] | None = None,
    cname_resolver: CnameResolver | None = None,
    cname_allowed: AllowCheck | None = None,
    answer_resolver: Callable[[str], DnsAnswer] | None = None,
    ttl_map: dict[str, int] | None = None,
    allowed_cidrs: tuple[str, ...] = (),
) -> int:
    """Process new allowed DNS events; return new file offset."""
    if not path.exists():
        return offset
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not event.get("allowed"):
                continue
            qname = str(event.get("qname") or "").strip().lower().rstrip(".")
            if not qname or qname in seen:
                continue
            seen.add(qname)
            if oob_path is not None and oob_domain:
                domain = oob_domain.strip().lower().rstrip(".")
                label = qname[: -len(domain) - 1] if qname.endswith("." + domain) else ""
                if re.fullmatch(r"[0-9a-f]{16}", label):
                    row = {
                        "token": label,
                        "path": "dns",
                        "query": {"qname": [qname]},
                        "remote": str(event.get("client") or ""),
                        "ts": time.time(),
                        "headers": {},
                    }
                    oob_path.parent.mkdir(parents=True, exist_ok=True)
                    with oob_path.open("a", encoding="utf-8") as out:
                        out.write(json.dumps(row, ensure_ascii=False) + "\n")
            answer = answer_resolver(qname) if answer_resolver is not None else None
            cnames = answer.cnames if answer is not None else (
                cname_resolver(qname) if cname_resolver is not None else []
            )
            if cname_allowed is not None and any(not cname_allowed(name) for name in cnames):
                continue
            if answer is not None and answer.ips:
                ips = answer.ips
                if ttl_map is not None and answer.ttl:
                    ttl_map[qname] = max(5, min(3600, answer.ttl))
            else:
                try:
                    ips = resolver(qname)
                except OSError:
                    continue
            for ip in ips:
                if allowed_cidrs:
                    try:
                        addr = ipaddress.ip_address(ip)
                        if not any(addr in ipaddress.ip_network(cidr, strict=False) for cidr in allowed_cidrs):
                            continue
                    except ValueError:
                        continue
                try:
                    cage.allow_ip(ip)
                except Exception:  # noqa: BLE001
                    continue
            if resolved is not None:
                resolved[qname] = set(ips)
        return handle.tell()


@dataclass
class DnsSync:
    log_path: Path
    cage: CageLike
    interval_s: float = 0.3
    resolver: Resolver = _default_resolver
    oob_path: Path | None = None
    oob_domain: str = ""
    refresh_s: float = 60.0
    cname_resolver: CnameResolver | None = None
    cname_allowed: AllowCheck | None = None
    dns_server: str = ""
    allowed_cidrs: tuple[str, ...] = ()
    ttl: dict[str, int] = field(default_factory=dict)
    resolved: dict[str, set[str]] = field(default_factory=dict)
    last_refresh: dict[str, float] = field(default_factory=dict)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None
    seen: set[str] = field(default_factory=set)
    offset: int = 0

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="srcguard-dns-sync", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.offset = sync_once(
                self.log_path,
                offset=self.offset,
                seen=self.seen,
                cage=self.cage,
                resolver=self.resolver,
                oob_path=self.oob_path,
                oob_domain=self.oob_domain,
                resolved=self.resolved,
                cname_resolver=self.cname_resolver,
                cname_allowed=self.cname_allowed,
                answer_resolver=(
                    (lambda name: dig_answer(name, self.dns_server))
                    if self.dns_server
                    else None
                ),
                ttl_map=self.ttl,
                allowed_cidrs=self.allowed_cidrs,
            )
            self.refresh()
            self._stop.wait(self.interval_s)

    def refresh(self) -> None:
        """Re-resolve allowed names and withdraw IPs that disappeared (TTL/rebinding)."""
        now = time.monotonic()
        for qname, old in list(self.resolved.items()):
            interval = self.ttl.get(qname, self.refresh_s)
            if now - self.last_refresh.get(qname, 0.0) < interval:
                continue
            try:
                new = set(self.resolver(qname))
            except OSError:
                continue
            for ip in new - old:
                try:
                    self.cage.allow_ip(ip)
                except Exception:  # noqa: BLE001
                    continue
            self.resolved[qname] = new
            self.last_refresh[qname] = now
            still_used: set[str] = set()
            for ips in self.resolved.values():
                still_used.update(ips)
            for ip in old - new:
                if ip in still_used:
                    continue
                remove = getattr(self.cage, "remove_ip", None)
                if remove is not None:
                    try:
                        remove(ip)
                    except Exception:  # noqa: BLE001
                        continue

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
