"""S3: Docker API discovery (label -> container -> published port)."""

from __future__ import annotations

import http.client
import json
import socket
from pathlib import Path

from .common import Result, run_cmd


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost", timeout=10)
        self.unix_path = path

    def connect(self) -> None:  # type: ignore[override]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(self.unix_path)
        self.sock = sock


def get(path: str) -> tuple[int, dict | list]:
    conn = UnixHTTPConnection("/var/run/docker.sock")
    conn.request("GET", path)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, json.loads(raw)


def run(root: Path) -> Result:
    evidence: list[str] = []
    name = "srcguard-spike-api"
    run_cmd(["docker", "rm", "-f", name], timeout=15)
    try:
        status, version = get("/version")
        evidence.append(f"docker_api /version status={status} version={version.get('Version')}")
        assert status == 200 and isinstance(version, dict)

        rc, cid = run_cmd(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "--label",
                "strix-run-id=spike",
                "-p",
                "127.0.0.1::48080",
                "alpine:3.20",
                "sleep",
                "30",
            ],
            timeout=30,
        )
        evidence.append(f"container_start rc={rc} id={cid[:16]}")
        if rc != 0:
            return Result("S3", "Docker API discovery", "FAIL", "could not start test container", evidence)

        status, inspect = get(f"/containers/{cid}/json")
        ports = inspect.get("NetworkSettings", {}).get("Ports", {})
        labels = inspect.get("Config", {}).get("Labels", {})
        evidence.append(f"inspect status={status} labels={json.dumps(labels)} ports={json.dumps(ports)}")
        assert status == 200
        assert labels.get("strix-run-id") == "spike"
        binding = (ports.get("48080/tcp") or [{}])[0]
        host_port = binding.get("HostPort")
        evidence.append(f"published_host_port={host_port}")
        assert host_port
        rc, out = run_cmd(["docker", "port", cid, "48080/tcp"], timeout=15)
        evidence.append(f"docker_port rc={rc} out={out}")
        return Result(
            "S3",
            "Docker API discovery",
            "PASS",
            "label -> container -> published port works; caido port can be discovered from the API",
            evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return Result("S3", "Docker API discovery", "FAIL", f"{type(exc).__name__}: {exc}", evidence)
    finally:
        run_cmd(["docker", "rm", "-f", name], timeout=15)
