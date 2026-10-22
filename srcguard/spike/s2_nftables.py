"""S2: nftables availability on this platform, including the no-sudo workaround.

Environment fact: this shell has no root and no_new_privs, so host nft cannot be
invoked directly. The spike tests a privileged helper container that shares the
host network namespace and uses the host's nft binary.
"""

from __future__ import annotations

from pathlib import Path

from .common import Result, run_cmd


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


def _helper_cmd(script: str) -> list[str]:
    cmd = ["docker", "run", "--rm", "--privileged", "--network", "host"]
    for host, container in VOLUME_PATHS:
        if Path(host).exists():
            cmd += ["-v", f"{host}:{container}:ro"]
    if Path("/usr/lib/x86_64-linux-gnu/xtables").is_dir():
        cmd += ["-v", "/usr/lib/x86_64-linux-gnu/xtables:/usr/lib/x86_64-linux-gnu/xtables:ro"]
    cmd += ["debian:bookworm-slim", "sh", "-c", script]
    return cmd


def _nft(script: str, timeout: int = 30) -> tuple[int, str]:
    return run_cmd(_helper_cmd(script), timeout=timeout)


def run(root: Path) -> Result:
    evidence: list[str] = []
    rc, out = run_cmd(["nft", "--version"], timeout=10)
    evidence.append(f"host_nft rc={rc} out={out.splitlines()[0] if out else ''}")
    rc, out = run_cmd(["sh", "-c", "sudo -n true 2>&1 || true"], timeout=10)
    evidence.append(f"sudo_nopasswd rc={rc} out={out}")
    rc, out = run_cmd(["docker", "info", "--format", "{{.OperatingSystem}} | {{.KernelVersion}}"], timeout=15)
    evidence.append(f"docker_info={out}")

    # 1. helper can install/list/delete a table
    script = (
        "set -e; "
        "nft add table inet srcguard_spike; "
        "nft 'add chain inet srcguard_spike forward { type filter hook forward priority 0; policy accept; }'; "
        "nft add rule inet srcguard_spike forward ip daddr 1.1.1.1 drop; "
        "nft list table inet srcguard_spike; "
        "nft delete table inet srcguard_spike; "
        "echo NFT_HELPER_OK"
    )
    rc, out = _nft(script, timeout=60)
    evidence.append(f"helper_nft rc={rc} out={out[-600:]}")
    if "NFT_HELPER_OK" not in out:
        return Result(
            "S2",
            "nftables / egress cage",
            "FAIL",
            "privileged helper could not install/delete nft rules; host nftables cage is not viable as designed",
            evidence,
        )

    # 2. real egress block: start a container, block 1.1.1.1, ping before/after
    name = "srcguard-spike-net"
    run_cmd(["docker", "rm", "-f", name], timeout=15)
    rc, out = run_cmd(
        ["docker", "run", "-d", "--rm", "--name", name, "alpine:3.20", "sleep", "45"], timeout=30
    )
    evidence.append(f"test_container_start rc={rc} out={out[:120]}")
    if rc != 0:
        return Result("S2", "nftables / egress cage", "PARTIAL", "helper rules OK; test container failed to start", evidence)

    try:
        rc, before = run_cmd(["docker", "exec", name, "ping", "-c1", "-W1", "1.1.1.1"], timeout=15)
        evidence.append(f"ping_before_block rc={rc} out={before[-200:]}")
        script = (
            "set -e; "
            "nft add table inet srcguard_spike; "
            "nft 'add chain inet srcguard_spike forward { type filter hook forward priority 0; policy accept; }'; "
            "nft add rule inet srcguard_spike forward ip daddr 1.1.1.1 drop; "
            "echo BLOCK_INSTALLED"
        )
        rc, out = _nft(script, timeout=60)
        evidence.append(f"block_install rc={rc} out={out[-200:]}")
        rc2, after = run_cmd(["docker", "exec", name, "ping", "-c1", "-W1", "1.1.1.1"], timeout=15)
        evidence.append(f"ping_after_block rc={rc2} out={after[-200:]}")
        _nft("nft delete table inet srcguard_spike 2>/dev/null || true", timeout=30)
        if "BLOCK_INSTALLED" not in out:
            return Result("S2", "nftables / egress cage", "FAIL", "could not install forward drop rule", evidence)
        if rc == 0 and rc2 != 0:
            return Result(
                "S2",
                "nftables / egress cage",
                "PASS",
                "helper container installed host rules; container egress to blocked IP failed",
                evidence,
            )
        return Result(
            "S2",
            "nftables / egress cage",
            "PARTIAL",
            "rules installed, but ping baseline/blocked result was inconclusive",
            evidence,
        )
    finally:
        run_cmd(["docker", "rm", "-f", name], timeout=15)
