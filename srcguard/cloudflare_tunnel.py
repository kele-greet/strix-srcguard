"""P2-3: expose the local HTTP OOB server through a Cloudflare quick tunnel."""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass


class TunnelError(RuntimeError):
    pass


URL_RE = re.compile(r"https://[a-zA-Z0-9.-]+\.trycloudflare\.com")


def parse_tunnel_url(logs: str) -> str | None:
    match = URL_RE.search(logs or "")
    return match.group(0) if match else None


@dataclass
class CloudflareQuickTunnel:
    image: str = "cloudflare/cloudflared:latest"
    name: str = ""
    port: int = 0
    url: str | None = None

    def start(self, port: int, *, name: str = "srcguard-oob-tunnel", timeout_s: float = 30.0) -> str:
        self.port = port
        self.name = name
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        proc = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "--network",
                "host",
                self.image,
                "tunnel",
                "--url",
                f"http://127.0.0.1:{port}",
                "--no-autoupdate",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise TunnelError((proc.stderr or proc.stdout).strip()[:500])
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            logs = subprocess.run(
                ["docker", "logs", name], capture_output=True, text=True, timeout=10
            ).stdout + subprocess.run(
                ["docker", "logs", name], capture_output=True, text=True, timeout=10
            ).stderr
            url = parse_tunnel_url(logs)
            if url:
                self.url = url
                return url
            time.sleep(0.5)
        self.stop()
        raise TunnelError("cloudflared did not print a trycloudflare URL")

    def stop(self) -> None:
        if self.name:
            subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        self.url = None
