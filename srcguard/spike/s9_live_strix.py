"""S9 (live, optional): run the real Strix binary against a mock LLM gateway.

Proves LLM gateway visibility end-to-end and tries live Caido discovery.

Run with:
    cd srcguard && PYTHONPATH=. SRCGUARD_LIVE=1 python3 -m srcguard.spike.s9_live_strix

It starts a mock upstream + gateway, runs the PyInstaller binary headless with
`openai/test`, and inspects the resulting strix_runs/ and Docker container.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import httpx

from .common import Result, run_cmd
from .s1_gateway import _Gateway, _Upstream, _serve


PROJECT_RE = re.compile(r"Caido project selected:\s*([A-Za-z0-9_-]{8,})")


def _newest_run(base: Path) -> Path | None:
    runs = sorted((base / "strix_runs").glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    return runs[0] if runs else None


def _container_for_label(label: str) -> str | None:
    rc, out = run_cmd(
        ["docker", "ps", "-aq", "--filter", f"label=strix-run-id={label}"], timeout=15
    )
    if rc != 0 or not out.strip():
        return None
    return out.strip().splitlines()[0]


def _docker_port(cid: str, port: str = "48080/tcp") -> str | None:
    rc, out = run_cmd(["docker", "port", cid, port], timeout=15)
    if rc != 0 or not out.strip():
        return None
    return out.strip().splitlines()[0]


def run(root: Path) -> Result:
    evidence: list[str] = []
    if os.environ.get("SRCGUARD_LIVE") != "1":
        return Result("S9", "live Strix + gateway/Caido", "BLOCKED", "set SRCGUARD_LIVE=1 to run", evidence)

    up_server = gw_server = None
    proc: subprocess.Popen | None = None
    try:
        _Upstream.calls = 0
        _Upstream.requests = []
        up_server, up_port = _serve(_Upstream.handler())
        gateway = _Gateway(f"http://127.0.0.1:{up_port}")
        gw_server, gw_port = _serve(gateway.make_handler())
        evidence.append(f"mock upstream={up_port} gateway={gw_port}")

        work = Path(tempfile.mkdtemp(prefix="srcguard-live-"))
        bin_path = root.parent / "strix-1.7.0-linux-x86_64"
        env = {
            **os.environ,
            "STRIX_LLM": "openai/test",
            "LLM_API_KEY": "dummy",
            "LLM_API_BASE": f"http://127.0.0.1:{gw_port}/v1",
            "STRIX_API_TYPE": "chat_completions",
            "STRIX_TELEMETRY": "false",
            "STRIX_RUN_ID": "spike-live",
            "STRIX_RUN_TYPE": "spike",
            "STRIX_DEBUG": "1",
            "HOME": str(work),
            "XDG_CACHE_HOME": str(work / ".cache"),
            "XDG_CONFIG_HOME": str(work / ".config"),
        }
        cmd = [
            str(bin_path),
            "-n",
            "-t",
            "http://127.0.0.1:9/",
            "--scan-mode",
            "quick",
            "--max-turns",
            "3",
            "--max-budget",
            "0.01",
        ]
        log_path = work / "strix-live.log"
        log = log_path.open("w", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            cwd=str(work),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        evidence.append(f"started pid={proc.pid} cwd={work}")

        deadline = time.time() + 90
        while time.time() < deadline and not gateway.audit:
            if proc.poll() is not None:
                break
            time.sleep(0.5)
        evidence.append(f"gateway_requests={len(gateway.audit)}")
        evidence.append(f"gateway_audit={json.dumps(gateway.audit[:3], ensure_ascii=False)}")
        if not gateway.audit:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-1200:]
            evidence.append(f"strix_log_tail={tail}")
            return Result(
                "S9",
                "live Strix + gateway/Caido",
                "FAIL",
                "binary did not reach the gateway (preflight or Docker failed)",
                evidence,
            )

        # Give the sandbox a little time to start and write strix.log.
        run_dir = None
        deadline = time.time() + 60
        while time.time() < deadline:
            run_dir = _newest_run(work)
            if run_dir and (run_dir / "strix.log").exists():
                break
            time.sleep(0.5)
        evidence.append(f"run_dir={run_dir}")
        project_id = None
        cid = None
        caido_login_ok = False
        caido_attempted = False
        deadline = time.time() + 90
        while time.time() < deadline and proc.poll() is None:
            if run_dir and (run_dir / "strix.log").exists():
                log_text = (run_dir / "strix.log").read_text(encoding="utf-8", errors="replace")
                m = PROJECT_RE.search(log_text)
                if m and not project_id:
                    project_id = m.group(1)
                    evidence.append(f"project_id={project_id}")
                    evidence.append(f"strix_log_lines={len(log_text.splitlines())}")
            cid = _container_for_label("spike-live")
            if cid and not caido_attempted:
                caido_attempted = True
                port = _docker_port(cid)
                evidence.append(f"live_container={cid} caido_port={port}")
                if port:
                    for attempt in range(1, 4):
                        try:
                            resp = httpx.post(
                                f"http://{port}/graphql",
                                json={"query": "mutation { loginAsGuest { token { accessToken } } }"},
                                timeout=2,
                            )
                            evidence.append(f"live_caido_login attempt={attempt} status={resp.status_code} body={resp.text[:120]}")
                            if resp.status_code == 200:
                                caido_login_ok = True
                                break
                        except Exception as exc:  # noqa: BLE001
                            evidence.append(f"live_caido_login attempt={attempt} error={type(exc).__name__}: {exc}")
                        time.sleep(0.3)
            if project_id:
                break
            time.sleep(0.5)
        evidence.append(f"container={cid} caido_login_ok={caido_login_ok}")
        if cid and not caido_login_ok:
            port = _docker_port(cid)
            evidence.append(f"caido_port={port}")
            if port:
                last_error = None
                for attempt in range(1, 6):
                    try:
                        url = f"http://{port}/graphql"
                        resp = httpx.post(
                            url,
                            json={"query": "mutation { loginAsGuest { token { accessToken } } }"},
                            timeout=5,
                        )
                        evidence.append(
                            f"caido_login attempt={attempt} status={resp.status_code} body={resp.text[:180]}"
                        )
                        if resp.status_code == 200:
                            caido_login_ok = True
                            break
                    except Exception as exc:  # noqa: BLE001
                        last_error = f"{type(exc).__name__}: {exc}"
                        evidence.append(f"caido_login attempt={attempt} error={last_error}")
                    time.sleep(2)

        if project_id and caido_login_ok:
            status, detail = "PASS", "gateway saw live Strix traffic; live Caido login + project id confirmed"
        elif caido_login_ok:
            status, detail = "PARTIAL", "live gateway + Caido guest login confirmed; project id not captured"
        elif project_id:
            status, detail = "PARTIAL", "project id captured; Caido login incomplete"
        else:
            status, detail = "PARTIAL", "gateway saw live Strix traffic; Caido not confirmed"
        return Result("S9", "live Strix + gateway/Caido", status, detail, evidence)
    except Exception as exc:  # noqa: BLE001
        return Result("S9", "live Strix + gateway/Caido", "FAIL", f"{type(exc).__name__}: {exc}", evidence)
    finally:
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                time.sleep(2)
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        rc, out = run_cmd(["docker", "ps", "-aq", "--filter", "label=strix-run-id=spike-live"], timeout=15)
        if out.strip():
            run_cmd(["docker", "rm", "-f", *out.split()], timeout=60)
        for server in (up_server, gw_server):
            if server is not None:
                server.shutdown()


if __name__ == "__main__":
    import json
    import sys

    result = run(Path(__file__).resolve().parents[3] / "strix-main")
    print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
    sys.exit(0 if result.status in {"PASS", "PARTIAL"} else 1)
