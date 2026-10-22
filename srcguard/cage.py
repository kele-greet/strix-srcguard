"""P0-F3: nftables egress cage for one Strix run.

The host shell has no root in this environment; rules are applied by a
short-lived privileged helper container that shares the host network namespace
and runs the host's nft binary. The cage is a per-run table:

    table inet srcguard_<id>
      set containers / containers6   source IPs of the run's sandbox
      set allow4 / allow6            explicit IPs/CIDRs from scope
      chain forward (priority -10)
        established/related accept
        blocked ranges drop (metadata/RFC1918/link-local/ULA)
        containers -> allow set accept
        containers -> anything else drop
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .scope import CompiledPolicy


class CageError(RuntimeError):
    """nftables helper failed."""


VOLUME_PATHS = [
    ("/usr/sbin/nft", "/usr/sbin/nft"),
    ("/lib/x86_64-linux-gnu/libnftables.so.1", "/lib/x86_64-linux-gnu/libnftables.so.1"),
    ("/lib/x86_64-linux-gnu/libedit.so.2", "/lib/x86_64-linux-gnu/libedit.so.2"),
    ("/lib/x86_64-linux-gnu/libmnl.so.0", "/lib/x86_64-linux-gnu/libmnl.so.0"),
    ("/lib/x86_64-linux-gnu/libnftnl.so.11", "/lib/x86_64-linux-gnu/libnftnl.so.11"),
    ("/lib/x86_64-linux-gnu/libxtables.so.12", "/lib/x86_64-linux-gnu/libxtables.so.12"),
    ("/lib/x86_64-linux-gnu/libjansson.so.4", "/lib/x86_64-linux-gnu/libjansson.so.4"),
    ("/lib/x86_64-linux-gnu/libgmp.so.10", "/lib/x86_64-linux-gnu/libgmp.so.10"),
    ("/lib/x86_64-linux-gnu/libtinfo.so.6", "/lib/x86_64-linux-gnu/libtinfo.so.6"),
    ("/lib/x86_64-linux-gnu/libbsd.so.0", "/lib/x86_64-linux-gnu/libbsd.so.0"),
    ("/lib/x86_64-linux-gnu/libmd.so.0", "/lib/x86_64-linux-gnu/libmd.so.0"),
]

BLOCK4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
BLOCK6 = ("::1/128", "fe80::/10", "fc00::/7", "ff00::/8")


def _helper_cmd(script: str) -> list[str]:
    cmd = ["docker", "run", "--rm", "-i", "--privileged", "--network", "host"]
    for host, container in VOLUME_PATHS:
        if Path(host).exists():
            cmd += ["-v", f"{host}:{container}:ro"]
    if Path("/usr/lib/x86_64-linux-gnu/xtables").is_dir():
        cmd += ["-v", "/usr/lib/x86_64-linux-gnu/xtables:/usr/lib/x86_64-linux-gnu/xtables:ro"]
    cmd += ["debian:bookworm-slim", "sh", "-c", script]
    return cmd


def _nft(script: str, *, timeout: int = 30) -> str:
    try:
        proc = subprocess.run(
            _helper_cmd("nft -f /dev/stdin"),
            input=script,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        raise CageError(f"nft helper failed to start: {exc}") from exc
    if proc.returncode != 0:
        raise CageError(f"nft failed rc={proc.returncode}: {(proc.stderr or proc.stdout).strip()[:800]}")
    return (proc.stdout or "").strip()


def _nft_json(table: str) -> dict:
    try:
        proc = subprocess.run(
            _helper_cmd(f"nft -j list table inet {table}"),
            capture_output=True,
            text=True,
            timeout=20,
        )
    except Exception as exc:  # noqa: BLE001
        raise CageError(f"nft json helper failed: {exc}") from exc
    if proc.returncode != 0:
        raise CageError(f"nft json failed: {(proc.stderr or proc.stdout).strip()[:500]}")
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise CageError(f"nft json parse failed: {exc}") from exc


def _hosts_from_target(target: str) -> list[str]:
    if "://" in target:
        host = urlparse(target).hostname or ""
    else:
        host = target.split("/", 1)[0].split(":", 1)[0]
    return [host.lower().rstrip(".")] if host else []


def resolve_allow_ips(
    compiled: CompiledPolicy,
    targets: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Return (ips_v4, ips_v6, warnings).

    Wildcards cannot be resolved to IPs; they are reported as warnings and must
    be covered by a DNS-aware layer later. CIDRs are passed through.
    """
    v4: list[str] = []
    v6: list[str] = []
    warnings: list[str] = []

    def add(value: str) -> None:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return
        text = str(network.network_address) if network.num_addresses == 1 else str(network)
        if network.version == 4:
            if text not in v4:
                v4.append(text)
        else:
            if text not in v6:
                v6.append(text)

    for pattern in compiled.allow:
        if "/" in pattern:
            add(pattern)
            continue
        if pattern.startswith("*."):
            warnings.append(f"wildcard {pattern!r} cannot be resolved to IPs; use exact hosts or DNS-aware P1")
            continue
        if pattern.count(":") >= 2:
            add(pattern)
            continue
        try:
            infos = socket.getaddrinfo(pattern, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as exc:
            warnings.append(f"cannot resolve {pattern!r}: {exc}")
            continue
        for info in infos:
            add(info[4][0])

    for target in targets:
        for host in _hosts_from_target(target):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                try:
                    infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                except OSError as exc:
                    warnings.append(f"cannot resolve run target {host!r}: {exc}")
                    continue
                for info in infos:
                    add(info[4][0])
            else:
                add(host)
    return v4, v6, warnings


def resolve_ip_hosts(compiled: CompiledPolicy, targets: list[str]) -> dict[str, str]:
    """Best-effort destination IP -> scope host mapping for the egress log."""
    mapping: dict[str, str] = {}

    def add(host: str) -> None:
        host = host.strip().lower().rstrip(".")
        if not host or host.startswith("*.") or "/" in host:
            return
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError:
            return
        for info in infos:
            mapping.setdefault(str(info[4][0]), host)

    for pattern in compiled.allow:
        if pattern.count(":") >= 2:
            continue
        add(pattern)
    for target in targets:
        for host in _hosts_from_target(target):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                add(host)
            else:
                mapping.setdefault(host, host)
    return mapping


@dataclass
class NftCage:
    run_id: str
    table: str
    installed: bool = False
    _dynamic_ips: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._dynamic_ips is None:
            self._dynamic_ips = set()

    @classmethod
    def for_run(cls, run_id: str) -> "NftCage":
        safe = re.sub(r"[^A-Za-z0-9_]", "_", run_id)[:40]
        return cls(run_id=run_id, table=f"srcguard_{safe}")

    def _base_script(
        self,
        allow4: list[str],
        allow6: list[str],
        oob4: list[str] | None = None,
        oob6: list[str] | None = None,
        lab4: list[str] | None = None,
        lab6: list[str] | None = None,
        dns4: list[str] | None = None,
        new_rate: int = 0,
        new_burst: int = 0,
        host_rate: int = 0,
        host_burst: int = 0,
        host_ips: list[str] | None = None,
        host_limits: dict[str, int] | None = None,
    ) -> str:
        t = self.table
        host_ips = host_ips or []
        host_limits = host_limits or {}
        dns4 = dns4 or []

        LOG_LIMIT = "limit rate 50/second"

        def accept(selector: str, *, log: str = "allow") -> list[str]:
            """Log (throttled) and accept, in two rules.

            nft's ``limit`` is an expression, so ``log ... limit rate X accept``
            stops accepting once the log burst is spent. Logging and the verdict
            must be separate rules for the verdict to stay unconditional.
            """
            return [
                f"add rule inet {t} {selector} log prefix \"srcguard-{t}-{log} \" {LOG_LIMIT}",
                f"add rule inet {t} {selector} accept",
            ]

        def drop(selector: str, *, log: str = "drop") -> list[str]:
            return [
                f"add rule inet {t} {selector} log prefix \"srcguard-{t}-{log} \" {LOG_LIMIT}",
                f"add rule inet {t} {selector} drop",
            ]

        def accept_new(
            selector: str,
            *,
            rate: int,
            burst: int,
            log: str = "allow",
            rate_log: str = "rate",
        ) -> list[str]:
            """Allow a destination, capping new connections at ``rate``/second."""
            if rate <= 0:
                return accept(selector, log=log)
            gate = f"ct state new limit rate {rate}/second burst {burst} packets"
            return [
                f"add rule inet {t} {selector} {gate} log prefix \"srcguard-{t}-{log} \" {LOG_LIMIT}",
                f"add rule inet {t} {selector} {gate} accept",
                *drop(f"{selector} ct state new", log=rate_log),
                *accept(selector, log=log),
            ]

        input_rules: list[str] = []
        for iface in ("docker0", "br-*"):
            base = f'input iifname "{iface}" ip saddr @containers'
            input_rules.append(
                f'add rule inet {t} input iifname "{iface}" ct state established,related accept'
            )
            for ip in host_ips:
                input_rules += accept_new(
                    f"{base} ip daddr {ip}", rate=host_rate, burst=host_burst
                )
            input_rules += accept(f"{base} ip daddr @oob4")
            input_rules += accept(f"{base} ip daddr @lab4")
            input_rules += accept(f"{base} ip daddr @dns4 udp dport 53", log="dns")
            input_rules += accept(f"{base} ip daddr @dns4 tcp dport 53", log="dns")
            input_rules += drop(f"{base} ip daddr @block4", log="block")
            input_rules += accept(f"{base} ip daddr @allow4")
            input_rules += drop(f"{base}", log="drop")

        lines = [
            f"add table inet {t}",
            f"add set inet {t} containers {{ type ipv4_addr; flags interval; }}",
            f"add set inet {t} allow4 {{ type ipv4_addr; flags interval; }}",
            f"add set inet {t} oob4 {{ type ipv4_addr; flags interval; }}",
            f"add set inet {t} lab4 {{ type ipv4_addr; flags interval; }}",
            f"add set inet {t} dns4 {{ type ipv4_addr; flags interval; }}",
            f"add set inet {t} block4 {{ type ipv4_addr; flags interval; }}",
            f"add set inet {t} containers6 {{ type ipv6_addr; flags interval; }}",
            f"add set inet {t} allow6 {{ type ipv6_addr; flags interval; }}",
            f"add set inet {t} oob6 {{ type ipv6_addr; flags interval; }}",
            f"add set inet {t} lab6 {{ type ipv6_addr; flags interval; }}",
            f"add set inet {t} block6 {{ type ipv6_addr; flags interval; }}",
            f"add chain inet {t} forward {{ type filter hook forward priority -10; policy accept; }}",
            *accept("forward ip saddr @containers ip daddr @dns4 udp dport 53", log="dns"),
            *accept("forward ip saddr @containers ip daddr @dns4 tcp dport 53", log="dns"),
            *[
                f"add rule inet {t} forward ip saddr @containers ip daddr {ip} ct state new "
                f"counter comment \"srcguard-host:{ip}\""
                for ip, limit in host_limits.items()
                if limit > 0
            ],
            *[
                rule
                for ip in host_ips
                for rule in accept_new(
                    f"forward ip saddr @containers ip daddr {ip}",
                    rate=host_rate,
                    burst=host_burst,
                )
            ],
            *accept_new("forward ip saddr @containers ip daddr @oob4", rate=new_rate, burst=new_burst),
            *accept_new("forward ip saddr @containers ip daddr @lab4", rate=new_rate, burst=new_burst),
            *drop("forward ip saddr @containers ip daddr @block4", log="block"),
            *accept_new("forward ip saddr @containers ip daddr @allow4", rate=new_rate, burst=new_burst),
            *drop("forward ip saddr @containers", log="drop"),
            f"add rule inet {t} forward ip6 saddr @containers6 ip6 daddr @oob6 accept",
            f"add rule inet {t} forward ip6 saddr @containers6 ip6 daddr @lab6 accept",
            f"add rule inet {t} forward ip6 saddr @containers6 ip6 daddr @block6 drop",
            f"add rule inet {t} forward ip6 saddr @containers6 ip6 daddr @allow6 accept",
            f"add rule inet {t} forward ip6 saddr @containers6 log prefix \"srcguard-drop6 \" {LOG_LIMIT}",
            f"add rule inet {t} forward ip6 saddr @containers6 drop",
            f"add chain inet {t} input {{ type filter hook input priority -10; policy accept; }}",
            *input_rules,
            f"add element inet {t} block4 {{ {', '.join(BLOCK4)} }}",
            f"add element inet {t} block6 {{ {', '.join(BLOCK6)} }}",
        ]
        if allow4:
            lines.append(f"add element inet {t} allow4 {{ {', '.join(allow4)} }}")
        if allow6:
            lines.append(f"add element inet {t} allow6 {{ {', '.join(allow6)} }}")
        if oob4:
            lines.append(f"add element inet {t} oob4 {{ {', '.join(oob4)} }}")
        if oob6:
            lines.append(f"add element inet {t} oob6 {{ {', '.join(oob6)} }}")
        if lab4:
            lines.append(f"add element inet {t} lab4 {{ {', '.join(lab4)} }}")
        if dns4:
            lines.append(f"add element inet {t} dns4 {{ {', '.join(dns4)} }}")
        if lab6:
            lines.append(f"add element inet {t} lab6 {{ {', '.join(lab6)} }}")
        return "\n".join(lines) + "\n"

    def install(
        self,
        allow4: list[str],
        allow6: list[str],
        *,
        oob4: list[str] | None = None,
        oob6: list[str] | None = None,
        lab4: list[str] | None = None,
        lab6: list[str] | None = None,
        dns4: list[str] | None = None,
        new_rate: int = 0,
        new_burst: int = 0,
        host_rate: int = 0,
        host_burst: int = 0,
        host_ips: list[str] | None = None,
        host_limits: dict[str, int] | None = None,
    ) -> None:
        self.cleanup(ignore_missing=True)
        _nft(
            self._base_script(
                allow4,
                allow6,
                oob4=oob4,
                oob6=oob6,
                lab4=lab4,
                lab6=lab6,
                dns4=dns4,
                new_rate=new_rate,
                new_burst=new_burst,
                host_rate=host_rate,
                host_burst=host_burst,
                host_ips=host_ips,
                host_limits=host_limits,
            )
        )
        self.installed = True

    def allow_ip(self, ip: str) -> bool:
        """Add a DNS-derived destination to the allow set (P2-4 wildcard)."""
        if not self.installed:
            raise CageError("cage is not installed")
        network = ipaddress.ip_address(ip)
        text = network.compressed
        if text in self._dynamic_ips:
            return False
        set_name = "allow4" if network.version == 4 else "allow6"
        _nft(f"add element inet {self.table} {set_name} {{ {text} }}\n")
        self._dynamic_ips.add(text)
        return True

    def remove_ip(self, ip: str) -> bool:
        """Remove a DNS-derived destination from the allow set."""
        if not self.installed:
            raise CageError("cage is not installed")
        network = ipaddress.ip_address(ip)
        text = network.compressed
        if text not in self._dynamic_ips:
            return False
        set_name = "allow4" if network.version == 4 else "allow6"
        _nft(f"delete element inet {self.table} {set_name} {{ {text} }}\n")
        self._dynamic_ips.discard(text)
        return True

    def host_counters(self) -> dict[str, int]:
        if not self.installed:
            return {}
        data = _nft_json(self.table)
        out: dict[str, int] = {}
        for item in data.get("nftables", []):
            rule = item.get("rule") if isinstance(item, dict) else None
            if not isinstance(rule, dict):
                continue
            comment = str(rule.get("comment") or "")
            if not comment.startswith("srcguard-host:"):
                continue
            ip = comment.split(":", 1)[1]
            packets = 0
            for expr in rule.get("expr") or []:
                if isinstance(expr, dict) and "counter" in expr:
                    packets = int((expr.get("counter") or {}).get("packets", 0))
            out[ip] = packets
        return out

    def attach(self, ip: str) -> None:
        if not self.installed:
            raise CageError("cage is not installed")
        network = ipaddress.ip_address(ip)
        set_name = "containers" if network.version == 4 else "containers6"
        _nft(f"add element inet {self.table} {set_name} {{ {network.compressed} }}\n")
        self.installed = True

    def detach(self, ip: str) -> None:
        if not self.installed:
            return
        network = ipaddress.ip_address(ip)
        set_name = "containers" if network.version == 4 else "containers6"
        _nft(f"delete element inet {self.table} {set_name} {{ {network.compressed} }}\n")

    def cleanup(self, *, ignore_missing: bool = False) -> None:
        try:
            _nft(f"delete table inet {self.table}\n")
        except CageError:
            if not ignore_missing:
                raise
        self.installed = False

    def show(self) -> str:
        return _nft(f"list table inet {self.table}\n")
