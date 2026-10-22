"""P0-F3 launch: install the nftables cage, start Strix, attach the sandbox, clean up."""

from __future__ import annotations

import platform
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .caido_observer import run_observer_thread
from .caido_tamper_guard import CaidoTamperConfig, CaidoTamperGuard
from .cloudflare_tunnel import CloudflareQuickTunnel
from .cage import CageError, NftCage, resolve_allow_ips, resolve_ip_hosts
from .session import COOKIE_CONTAINER_PATH, copy_into_container
from .docker_proxy import DockerMutationProxy, DockerProxyConfig
from .dns_guard import DnsGuard, DnsGuardConfig
from .dns_sync import DnsSync, dig_cname_chain
from .kill import KillSwitch
from .quota import start_quota_watcher
from .registry import RunRegistry
from .usage import write_usage
from .egress import EgressCollector
from .monitor import start_monitor
from .oob import OobServer
from .rate import HostRateLimiter, global_new_connection_rate
from .preflight import RunSpec
from .scope import CompiledPolicy, host_allowed


@dataclass
class LaunchResult:
    exit_code: int
    container_ip: str | None
    warnings: list[str] = field(default_factory=list)
    caido_url: str | None = None
    project_id: str | None = None
    oob_url: str | None = None
    oob_token: str | None = None


def _docker(args: list[str], *, timeout: int = 15) -> str:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    return (proc.stdout or "").strip()


def _container_for_run(run_id: str) -> str | None:
    try:
        out = _docker(["ps", "-q", "--filter", f"label=strix-run-id={run_id}"])
    except Exception:  # noqa: BLE001
        return None
    return out.splitlines()[0] if out.strip() else None


def _caido_port(cid: str) -> str | None:
    try:
        out = _docker(["port", cid, "48080/tcp"])
    except Exception:  # noqa: BLE001
        return None
    line = out.splitlines()[0] if out.strip() else ""
    return line.rsplit(":", 1)[-1] if ":" in line else None


PROJECT_RE = re.compile(r"Caido project selected:\s*([A-Za-z0-9_-]{8,})")


def _project_id(run_dir: Path) -> str | None:
    runs = sorted((run_dir / "strix_runs").glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for run in runs:
        log = run / "strix.log"
        if not log.exists():
            continue
        text = log.read_text(encoding="utf-8", errors="replace")
        match = PROJECT_RE.search(text)
        if match:
            return match.group(1)
    return None


def _container_ip(cid: str) -> str | None:
    try:
        out = _docker(
            ["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", cid]
        )
    except Exception:  # noqa: BLE001
        return None
    return out.split()[0] if out.strip() else None


def _system_dns_ips() -> list[str]:
    """Host resolvers the container must reach for public DNS (port 53 only)."""
    out: list[str] = []
    try:
        for line in Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                value = parts[1].strip()
                if value and not value.startswith("127.") and value not in out:
                    out.append(value)
    except OSError:
        pass
    return out


def ensure_supported_platform() -> None:
    """Fail closed instead of pretending the nftables cage works off Linux."""
    if platform.system() != "Linux":
        raise CageError(
            f"SRCGuard's nftables cage requires Linux; current platform is {platform.system()!r}. "
            "Do not run real SRC targets without a network boundary."
        )


def launch(
    spec: RunSpec,
    compiled: CompiledPolicy,
    *,
    strix_bin: str,
    attach_timeout_s: float = 45.0,
    oob_host: str | None = None,
    oob_domain: str | None = None,
    lab_hosts: list[str] | None = None,
    docker_proxy: bool = False,
    dns_guard: bool = False,
    caido_tamper: bool = False,
    public_oob: bool = False,
    kill_on_oob: bool = False,
    max_concurrent_runs: int = 0,
    session_cookie_file: str | None = None,
) -> LaunchResult:
    ensure_supported_platform()
    launch_started = time.time()
    warnings = list(spec.warnings)
    allow4, allow6, resolve_warnings = resolve_allow_ips(compiled, spec.targets)
    warnings.extend(resolve_warnings)
    cage = NftCage.for_run(spec.run_id)
    kill = KillSwitch(run_dir=spec.run_dir, run_id=spec.run_id)
    collector: EgressCollector | None = None
    limiter = HostRateLimiter(
        default_rps=compiled.default_rps,
        burst_rps=compiled.burst_rps,
        max_blocked=compiled.max_blocked,
        log_path=spec.run_dir / "audit" / "rate.jsonl",
    )
    new_rate, new_burst = global_new_connection_rate(compiled.default_rps, compiled.burst_rps)
    host_rate = max(1, int(round(compiled.default_rps)))
    host_burst = max(host_rate, int(round(compiled.burst_rps)))
    host_ips = [ip for ip in allow4 if "/" not in ip]
    host_limits = {
        ip: compiled.max_requests_per_host
        for ip in host_ips
        if compiled.max_requests_per_host > 0
    }
    oob: OobServer | None = None
    oob_ip4: list[str] = []
    oob_ip6: list[str] = []
    lab4: list[str] = []
    lab6: list[str] = []
    dns_guard_obj: DnsGuard | None = None
    dns_sync_obj: DnsSync | None = None
    tamper_guard: CaidoTamperGuard | None = None
    oob_tunnel: CloudflareQuickTunnel | None = None
    dns_ip: list[str] = []
    if dns_guard:
        import ipaddress
        import urllib.parse

        patterns = list(compiled.allow)
        for target in spec.targets:
            parsed = urllib.parse.urlparse(target if "://" in target else "//" + target)
            if parsed.hostname:
                patterns.append(parsed.hostname)
        oob_domain = compiled.oob.get("domain") if isinstance(compiled.oob, dict) else ""
        if oob_domain:
            patterns.append(oob_domain)
            patterns.append(f"*.{oob_domain}")
        binary = Path(__file__).resolve().parents[1] / "bin" / "srcguard-dnsguard"
        try:
            dns_guard_obj = DnsGuard(
                DnsGuardConfig(
                    binary=binary,
                    run_dir=spec.run_dir,
                    allow=patterns,
                    listen_ip="172.17.0.1",
                )
            )
            ip = dns_guard_obj.start()
            dns_ip = [ip]
            warnings.append(f"dns guard: {ip}:53 (allowlist {len(set(patterns))})")
        except Exception as exc:  # noqa: BLE001
            if dns_guard_obj is not None:
                dns_guard_obj.stop()
            raise CageError(f"dns guard failed: {exc}") from exc
    else:
        # Must be known before cage.install(): the resolver lives on the host (often
        # a private address, e.g. 10.255.255.254), so it is inside BLOCK4. Without
        # the dns4 element the block4 rule swallows every DNS query and the sandbox
        # cannot resolve any hostname.
        dns_ip = _system_dns_ips()
        if dns_ip:
            warnings.append(f"system DNS allowed on port 53: {', '.join(dns_ip)}")
    try:
        if oob_host:
            oob = OobServer(
                run_dir=spec.run_dir,
                run_id=spec.run_id,
                advertised_host=oob_host,
                domain=oob_domain,
            )
            oob_url = oob.start()
            if public_oob:
                oob_tunnel = CloudflareQuickTunnel()
                try:
                    public_url = oob_tunnel.start(
                        oob.port, name=f"srcguard-oob-{str(spec.run_id)[:24]}"
                    )
                    oob.public_url = public_url
                    oob_url = oob.url()
                    warnings.append(f"public OOB tunnel: {public_url}")
                except Exception as exc:  # noqa: BLE001
                    warnings.append(f"public OOB tunnel failed, using local URL: {exc}")
                    oob_tunnel = None
            try:
                import ipaddress

                ip = ipaddress.ip_address(oob_host)
                (oob_ip4 if ip.version == 4 else oob_ip6).append(ip.compressed)
            except ValueError:
                import socket

                try:
                    for info in socket.getaddrinfo(oob_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
                        ip = ipaddress.ip_address(info[4][0])
                        (oob_ip4 if ip.version == 4 else oob_ip6).append(ip.compressed)
                except OSError:
                    pass
            with spec.instruction_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    "\n\n## OOB CALLBACK\n"
                    f"Blind-callback URL: {oob_url}\n"
                    f"Callback token: {oob.token}\n"
                    "Use this URL only for blind SSRF/XXE/XSS; do not send target data beyond the token.\n"
                )
            warnings.append(f"oob: {oob_url}")
        import ipaddress
        import socket

        for host in lab_hosts or []:
            try:
                ip = ipaddress.ip_address(host)
                (lab4 if ip.version == 4 else lab6).append(ip.compressed)
            except ValueError:
                try:
                    for info in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
                        ip = ipaddress.ip_address(info[4][0])
                        (lab4 if ip.version == 4 else lab6).append(ip.compressed)
                except OSError:
                    warnings.append(f"cannot resolve lab host {host!r}")
        cage.install(
            allow4,
            allow6,
            oob4=oob_ip4,
            oob6=oob_ip6,
            lab4=lab4,
            lab6=lab6,
            dns4=dns_ip,
            new_rate=new_rate,
            new_burst=new_burst,
            host_rate=host_rate,
            host_burst=host_burst,
            host_ips=host_ips,
            host_limits=host_limits,
        )
        if dns_guard_obj is not None and any(pattern.startswith("*.") for pattern in compiled.allow):
            try:
                oob_domain_effective = oob_domain or (
                    str(compiled.oob.get("domain") or "") if isinstance(compiled.oob, dict) else ""
                )
                dns_sync_obj = DnsSync(
                    dns_guard_obj.audit_path(),
                    cage,
                    oob_path=spec.run_dir / "audit" / "oob.jsonl" if oob_domain_effective else None,
                    oob_domain=oob_domain_effective,
                    cname_resolver=dig_cname_chain,
                    cname_allowed=lambda name: host_allowed(compiled, name)[0],
                    dns_server=dns_guard_obj.ip,
                    allowed_cidrs=tuple(p for p in compiled.allow if "/" in p),
                )
                dns_sync_obj.start()
                warnings.append("dns sync: wildcard allow IPs added from allowed queries")
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"dns sync unavailable: {exc}")
        try:
            collector = EgressCollector(
                tag=cage.table,
                out_path=spec.run_dir / "audit" / "egress.jsonl",
                ip_hosts=resolve_ip_hosts(compiled, spec.targets),
            )
            collector.start()
            warnings.append("egress collector: dmesg -w (nft log)")
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"egress collector unavailable: {exc}")
    except CageError as exc:
        if collector is not None:
            collector.stop()
        if dns_guard_obj is not None:
            dns_guard_obj.stop()
        raise CageError(f"cannot install cage: {exc}") from exc

    proc: subprocess.Popen | None = None
    container_ip: str | None = None
    caido_url: str | None = None
    project_id: str | None = None
    oob_url: str | None = None
    oob_token: str | None = None
    docker_proxy_obj: DockerMutationProxy | None = None
    docker_proxy = docker_proxy or dns_guard
    if docker_proxy:
        try:
            docker_proxy_obj = DockerMutationProxy(
                DockerProxyConfig(
                    audit_path=spec.run_dir / "audit" / "docker.jsonl",
                    dns_server=dns_ip[0] if dns_ip else None,
                )
            )
            docker_proxy_obj.start()
            spec.env["DOCKER_HOST"] = docker_proxy_obj.base_url
            warnings.append(f"docker mutation proxy: {docker_proxy_obj.base_url}")
        except Exception as exc:  # noqa: BLE001
            if collector is not None:
                collector.stop()
            cage.cleanup(ignore_missing=True)
            if dns_guard_obj is not None:
                dns_guard_obj.stop()
            raise CageError(f"docker proxy failed: {exc}") from exc
    observer_stop = threading.Event()
    quota_stop = threading.Event()
    quota_reasons: list[str] = []
    monitor_reasons: list[str] = []
    registry = RunRegistry()
    leased = False
    if not registry.acquire(spec.run_id, max_concurrent_runs):
        if collector is not None:
            collector.stop()
        if docker_proxy_obj is not None:
            docker_proxy_obj.stop()
        if dns_guard_obj is not None:
            dns_guard_obj.stop()
        cage.cleanup(ignore_missing=True)
        raise CageError(f"max concurrent runs reached ({max_concurrent_runs})")
    leased = max_concurrent_runs > 0
    try:
        proc = subprocess.Popen(
            [strix_bin, *spec.argv], env=spec.env, start_new_session=True, cwd=spec.run_dir
        )
        allow_destinations = set(allow4) | set(oob_ip4) | set(lab4) | set(dns_ip)
        monitor_thread, monitor_reasons = start_monitor(
            spec.run_dir,
            compiled,
            proc,
            kill,
            observer_stop,
            limiter=limiter,
            kill_on_oob=kill_on_oob,
            allowed_ips=allow_destinations,
            deny_methods=compiled.deny_methods,
            post_mode=compiled.post_mode,
            post_allow_paths=compiled.post_allow_paths,
            post_deny_paths=compiled.post_deny_paths,
            post_deny_keywords=compiled.post_deny_keywords,
        )
        quota_thread = None
        if host_limits:
            quota_thread, quota_reasons = start_quota_watcher(
                cage, host_limits, proc, kill, quota_stop
            )
        deadline = time.time() + attach_timeout_s
        while proc.poll() is None and time.time() < deadline:
            cid = _container_for_run(spec.run_id)
            if cid:
                container_ip = _container_ip(cid)
                if container_ip:
                    cage.attach(container_ip)
                    if session_cookie_file:
                        try:
                            copy_into_container(cid, session_cookie_file)
                            warnings.append(
                                f"session cookie injected at {COOKIE_CONTAINER_PATH} (0600)"
                            )
                            session_cookie_file = None
                        except Exception as exc:  # noqa: BLE001
                            warnings.append(f"session cookie injection failed: {exc}")
                    port = _caido_port(cid)
                    if port:
                        caido_url = f"http://127.0.0.1:{port}"
                    for _ in range(40):
                        project_id = _project_id(spec.run_dir)
                        if project_id or proc.poll() is not None:
                            break
                        time.sleep(0.25)
                    if caido_url and project_id:
                        run_observer_thread(
                            caido_url,
                            project_id,
                            spec.run_dir / "audit" / "caido.jsonl",
                            observer_stop,
                        )
                        if caido_tamper:
                            try:
                                tamper_guard = CaidoTamperGuard(
                                    CaidoTamperConfig(
                                        base_url=caido_url,
                                        denied=set(compiled.deny_methods),
                                        audit_path=spec.run_dir / "audit" / "caido_tamper.jsonl",
                                    )
                                )
                                tamper_guard.start()
                                warnings.append(
                                    f"caido tamper: {','.join(sorted(compiled.deny_methods))} -> GET"
                                )
                            except Exception as exc:  # noqa: BLE001
                                kill.trip("caido_tamper_failed", proc)
                                warnings.append(f"caido tamper failed, killed: {exc}")
                        warnings.append(f"caido observer: {caido_url} project={project_id}")
                    else:
                        warnings.append("caido observer not started (missing port or project id)")
                    break
            time.sleep(0.1)
        if container_ip is None:
            warnings.append("sandbox container/IP not observed; cage allowed set is empty")
        exit_code = proc.wait()
        warnings.extend(monitor_reasons)
        warnings.extend(quota_reasons)
        return LaunchResult(
            exit_code=exit_code,
            container_ip=container_ip,
            warnings=warnings,
            caido_url=caido_url,
            project_id=project_id,
            oob_url=oob.url() if oob else None,
            oob_token=oob.token if oob else None,
        )
    except KeyboardInterrupt:
        kill.trip("keyboard_interrupt", proc)
        warnings.append("interrupted; kill.json written")
        return LaunchResult(
            exit_code=130,
            container_ip=container_ip,
            warnings=warnings,
            caido_url=caido_url,
            project_id=project_id,
            oob_url=oob.url() if oob else None,
            oob_token=oob.token if oob else None,
        )
    finally:
        observer_stop.set()
        quota_stop.set()
        if "quota_thread" in locals() and quota_thread is not None:
            quota_thread.join(timeout=2)
        if "monitor_thread" in locals():
            monitor_thread.join(timeout=2)
        if collector is not None:
            collector.stop()
        if oob_tunnel is not None:
            oob_tunnel.stop()
        if oob is not None:
            oob.stop()
        if docker_proxy_obj is not None:
            docker_proxy_obj.stop()
        if tamper_guard is not None:
            tamper_guard.stop()
        if dns_sync_obj is not None:
            dns_sync_obj.stop()
        if dns_guard_obj is not None:
            dns_guard_obj.stop()
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if leased:
            registry.release(spec.run_id)
        try:
            write_usage(
                spec.run_dir,
                wall_s=time.time() - launch_started,
                container_ip=container_ip,
            )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"usage accounting failed: {exc}")
        cage.cleanup(ignore_missing=True)
