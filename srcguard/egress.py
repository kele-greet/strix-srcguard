"""P1-F11: nftables log -> audit/egress.jsonl.

nft `log` writes IN=... SRC=... DST=... lines to the kernel ring buffer. A
privileged helper container (`dmesg -w`) streams them; this collector maps the
destination IP back to the scope host when possible and appends JSONL events.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


LOG_RE = re.compile(
    r"srcguard-(?P<tag>[A-Za-z0-9_]+)-(?P<decision>allow|block|drop|rate|dns)"
    r".*?SRC=(?P<src>[0-9a-fA-F:.]+).*?DST=(?P<dst>[0-9a-fA-F:.]+)"
)
PROTO_RE = re.compile(r"\bPROTO=(?P<proto>[A-Z0-9]+)")
PORT_RE = re.compile(r"\bDPT=(?P<dpt>\d+)")


@dataclass
class EgressEvent:
    ip: str
    host: str
    decision: str
    source: str = "nft"
    port: int | None = None
    proto: str | None = None
    ts: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "host": self.host,
            "decision": self.decision,
            "source": self.source,
            "port": self.port,
            "proto": self.proto,
            "ts": self.ts,
        }


def parse_line(line: str, *, tag: str, ip_hosts: dict[str, str]) -> EgressEvent | None:
    if f"srcguard-{tag}-" not in line:
        return None
    match = LOG_RE.search(line)
    if match is None or match.group("tag") != tag:
        return None
    dst = match.group("dst").strip("[]")
    proto = PROTO_RE.search(line)
    port = PORT_RE.search(line)
    return EgressEvent(
        ip=dst,
        host=ip_hosts.get(dst, ""),
        decision=match.group("decision"),
        port=int(port.group("dpt")) if port else None,
        proto=proto.group("proto") if proto else None,
        ts=time.time(),
    )


class EgressCollector:
    def __init__(
        self,
        *,
        tag: str,
        out_path: str | Path,
        ip_hosts: dict[str, str] | None = None,
        image: str = "alpine:3.20",
        dedupe_window_s: float = 2.0,
    ) -> None:
        self.tag = tag
        self.dedupe_window_s = dedupe_window_s
        self.out_path = Path(out_path)
        self.ip_hosts = ip_hosts or {}
        self.image = image
        self._proc: subprocess.Popen[str] | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self._proc = subprocess.Popen(
            [
                "docker",
                "run",
                "--rm",
                "--privileged",
                "--network",
                "host",
                "--pid=host",
                self.image,
                "sh",
                "-c",
                "while true; do dmesg; sleep 1; done",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self._thread = threading.Thread(target=self._loop, name="srcguard-egress", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        seen: set[str] = set()
        recent: dict[tuple[str, int | None, str | None, str], float] = {}
        for line in self._proc.stdout:
            if self._stop.is_set():
                break
            key = line.strip()
            if os.environ.get("SRCGUARD_EGRESS_DEBUG"):
                with (self.out_path.parent / "egress.debug").open("a", encoding="utf-8") as handle:
                    handle.write(line)
            if key in seen:
                continue
            seen.add(key)
            event = parse_line(line, tag=self.tag, ip_hosts=self.ip_hosts)
            if event is None:
                continue
            # nft logs every matching packet (SYN, ACK, data...). Collapse the
            # burst into one row per destination+port so counts reflect contacts,
            # not packets.
            marker = (event.ip, event.port, event.proto, event.decision)
            last = recent.get(marker)
            if last is not None and event.ts - last < self.dedupe_window_s:
                continue
            recent[marker] = event.ts
            with self.out_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    def stop(self) -> None:
        self._stop.set()
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            if proc.stdout is not None:
                proc.stdout.close()
        if self._thread is not None:
            self._thread.join(timeout=2)
