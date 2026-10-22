"""P2-1: controlled DNS resolver for the Strix sandbox.

The sandbox gets ``HostConfig.Dns = [guard_ip]``. A tiny static C helper
(``srcguard/dnsguard/dnsguard.c``) runs in a host-network Debian container,
binds the Docker gateway on port 53, returns NXDOMAIN for names outside the
scope allowlist, forwards allowed queries to the host resolver, and logs every
query to ``audit/dns.jsonl``.

It is opt-in because it needs the host-network DNS port and an extra helper.
"""

from __future__ import annotations

import json
import os
import re
import socket
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


GUARD_IMAGE = "debian:bookworm-slim"


class DnsGuardError(RuntimeError):
    """The DNS guard could not start or answer."""


def _safe_name(run_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", run_id)[:48]


def _default_upstream() -> str:
    override = os.environ.get("SRCGUARD_DNS_UPSTREAM", "").strip()
    if override:
        return override if ":" in override else f"{override}:53"
    try:
        for line in Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                server = parts[1].strip()
                if server and not server.startswith("127.0.0.53"):
                    return f"{server}:53"
    except OSError:
        pass
    return "10.255.255.254:53"


def _dns_query(name: str) -> bytes:
    tid = 0x5352
    q = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def _dns_ready(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_dns_query("srcguard-readiness.invalid"), (ip, port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return len(data) >= 12
    except OSError:
        return False


@dataclass
class DnsGuardConfig:
    binary: Path
    run_dir: Path
    allow: list[str]
    listen_ip: str = "172.17.0.1"
    listen_port: int = 53
    upstream: str = ""
    image: str = GUARD_IMAGE
    timeout_s: float = 3.0


@dataclass
class DnsGuard:
    config: DnsGuardConfig
    ip: str = ""
    cid: str | None = None
    name: str = ""
    _tmpdir: tempfile.TemporaryDirectory | None = field(default=None, repr=False)

    def start(self) -> str:
        binary = Path(self.config.binary)
        if not binary.is_file():
            raise DnsGuardError(f"dnsguard binary missing: {binary}; run scripts/build_dnsguard.sh")
        self.name = f"srcguard-dns-{_safe_name(self.config.run_dir.name)}"
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, text=True)
        self.config.run_dir.mkdir(parents=True, exist_ok=True)
        audit_dir = (self.config.run_dir / "audit").resolve()
        audit_dir.mkdir(parents=True, exist_ok=True)
        allow_file = (self.config.run_dir / "dns-allow.txt").resolve()
        patterns = sorted({item.strip().lower().rstrip(".") for item in self.config.allow if item.strip()})
        if not patterns:
            raise DnsGuardError("dnsguard allowlist is empty; refusing to start")
        allow_file.write_text("\n".join(patterns) + "\n", encoding="utf-8")
        upstream = self.config.upstream or _default_upstream()
        cmd = [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            self.name,
            "--network",
            "host",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_BIND_SERVICE",
            "--cap-add",
            "DAC_OVERRIDE",  # audit dir is owned by the host user
            "--read-only",
            "-v",
            f"{binary.resolve()}:/dnsguard:ro",
            "-v",
            f"{allow_file}:/allow.txt:ro",
            "-v",
            f"{audit_dir}:/audit:rw",
            self.config.image,
            "/dnsguard",
            "-listen",
            f"{self.config.listen_ip}:{self.config.listen_port}",
            "-upstream",
            upstream,
            "-allow",
            "/allow.txt",
            "-log",
            "/audit/dns.jsonl",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        cid = (proc.stdout or "").strip().splitlines()
        if proc.returncode != 0 or not cid:
            raise DnsGuardError(f"dnsguard failed to start: {(proc.stderr or proc.stdout).strip()[:500]}")
        self.cid = cid[-1]
        self.ip = self.config.listen_ip
        deadline = time.time() + self.config.timeout_s
        while time.time() < deadline:
            if _dns_ready(self.ip, self.config.listen_port):
                return self.ip
            time.sleep(0.15)
        self.stop()
        raise DnsGuardError(f"dnsguard did not answer on {self.ip}:{self.config.listen_port}")

    def stop(self) -> None:
        if self.name:
            subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, text=True)
        self.cid = None

    def audit_path(self) -> Path:
        return self.config.run_dir / "audit" / "dns.jsonl"

    def events(self) -> list[dict]:
        path = self.audit_path()
        if not path.exists():
            return []
        rows: list[dict] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows
