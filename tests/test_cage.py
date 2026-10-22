from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from srcguard.cage import NftCage, resolve_allow_ips
from srcguard.scope import compile_policy, load_scope


SCOPE = """
program: cage
in_scope: ["203.0.113.0/24", "2001:db8::/32", "*.example.com", "1.1.1.1"]
"""


class CageUnitTests(unittest.TestCase):
    def test_resolve_allow_ips_passes_cidrs_and_warns_wildcards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.yaml"
            path.write_text(SCOPE, encoding="utf-8")
            compiled = compile_policy(load_scope(path))
            v4, v6, warnings = resolve_allow_ips(compiled, ["https://1.1.1.1"])
            self.assertIn("203.0.113.0/24", v4)
            self.assertIn("1.1.1.1", v4)
            self.assertIn("2001:db8::/32", v6)
            self.assertTrue(any("wildcard" in w for w in warnings))

    def test_base_script_includes_rate_rule(self) -> None:
        cage = NftCage.for_run("rate")
        script = cage._base_script([], [], new_rate=10, new_burst=20)
        gate = "ip daddr @allow4 ct state new limit rate 10/second burst 20 packets"
        gate_lines = [line for line in script.splitlines() if gate in line]
        # nft's limit matches while the bucket has room, so the under-limit
        # packets must be accepted and a separate rule drops the excess.
        self.assertTrue(any(line.rstrip().endswith("accept") for line in gate_lines), gate_lines)
        self.assertFalse(any("drop" in line for line in gate_lines), gate_lines)
        self.assertIn("ip daddr @allow4 ct state new drop", script)
        self.assertIn("srcguard-srcguard_rate-rate", script)

    def test_no_verdict_is_gated_by_a_log_throttle(self) -> None:
        """'log ... limit rate N accept' stops accepting once the burst is spent."""
        cage = NftCage.for_run("throttle")
        script = cage._base_script(
            ["1.1.1.1"],
            [],
            lab4=["172.17.0.1"],
            dns4=["172.17.0.1"],
            new_rate=10,
            new_burst=20,
            host_rate=5,
            host_burst=10,
            host_ips=["1.1.1.1"],
        )
        for line in script.splitlines():
            if not line.rstrip().endswith(("accept", "drop")):
                continue
            if "log prefix" not in line:
                continue
            self.fail(f"log throttle gates the verdict: {line}")

    def test_base_script_includes_per_host_rate_rules(self) -> None:
        cage = NftCage.for_run("hostrate")
        script = cage._base_script([], [], host_rate=5, host_burst=10, host_ips=["1.1.1.1"])
        self.assertIn(
            "ip saddr @containers ip daddr 1.1.1.1 ct state new "
            "limit rate 5/second burst 10 packets",
            script,
        )
        self.assertIn("srcguard-srcguard_hostrate-rate", script)
        self.assertIn("ip daddr 1.1.1.1 ct state new log prefix", script)
        # The drop rule must come after the accept rule for the same host.
        accept = script.index("ip daddr 1.1.1.1 ct state new")
        drop = script.index("srcguard-srcguard_hostrate-rate")
        self.assertLess(accept, drop)
        # No generic allow rule may sit before the per-host rate rules.
        generic = script.index("ip daddr @allow4")
        self.assertLess(accept, generic)

    def test_base_script_includes_docker0_input_chain(self) -> None:
        cage = NftCage.for_run("input")
        script = cage._base_script([], [], host_rate=5, host_burst=10, host_ips=["172.17.0.3"])
        self.assertIn("chain inet srcguard_input input", script)
        self.assertIn('iifname "docker0" ip saddr @containers ip daddr @block4', script)
        self.assertIn('iifname "docker0" ip saddr @containers log prefix', script)
        self.assertIn('iifname "br-*" ip saddr @containers ip daddr @block4', script)

    def test_base_script_allows_only_dns_guard_on_port_53(self) -> None:
        cage = NftCage.for_run("dns")
        script = cage._base_script([], [], dns4=["172.17.0.1"])
        self.assertIn("forward ip saddr @containers ip daddr @dns4 udp dport 53", script)
        self.assertIn("forward ip saddr @containers ip daddr @dns4 tcp dport 53", script)
        self.assertIn("input iifname \"docker0\" ip saddr @containers ip daddr @dns4 udp dport 53", script)
        self.assertIn("add element inet srcguard_dns dns4 { 172.17.0.1 }", script)

    def test_table_name_is_sanitized(self) -> None:
        cage = NftCage.for_run("run id/with:bad*chars")
        self.assertTrue(cage.table.startswith("srcguard_"))
        self.assertNotIn(" ", cage.table)
        self.assertNotIn("/", cage.table)


@unittest.skipUnless(shutil.which("docker"), "docker not installed")
class CageIntegrationTests(unittest.TestCase):
    def test_rate_limiter_still_allows_allowed_destination(self) -> None:
        """Regression: ``limit ... drop`` used to drop every new connection."""
        server = "srcguard-rate-server"
        client = "srcguard-rate-client"
        for name in (server, client):
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        cid = subprocess.run(
            [
                "docker", "run", "-d", "--rm", "--name", server, "alpine:3.20",
                "sh", "-c",
                'while true; do printf "HTTP/1.0 200 OK\\r\\nContent-Length: 5\\r\\n\\r\\nhello" '
                "| nc -l -p 8080; done",
            ],
            capture_output=True,
            text=True,
        ).stdout.strip()
        cli = subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", client, "alpine:3.20", "sleep", "30"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not cid or not cli:
            self.skipTest("docker run failed")
        time.sleep(1.0)
        try:
            server_ip = subprocess.run(
                ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid],
                capture_output=True,
                text=True,
            ).stdout.strip()
            client_ip = subprocess.run(
                ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cli],
                capture_output=True,
                text=True,
            ).stdout.strip()
            if not server_ip or not client_ip:
                self.skipTest("container ip missing")
            cage = NftCage.for_run("rate-live")
            try:
                cage.install(["172.17.0.1"], [], lab4=[server_ip], new_rate=5, new_burst=10)
                cage.attach(client_ip)
                got = subprocess.run(
                    ["docker", "exec", cli, "wget", "-q", "-T", "5", "-O", "-", f"http://{server_ip}:8080/"],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(got.stdout.strip(), "hello", got.stderr)
                cage.detach(client_ip)
            finally:
                cage.cleanup(ignore_missing=True)
        finally:
            for name in (server, client):
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    def test_attach_allow_and_block(self) -> None:
        name = "srcguard-cage-test"
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        cid = subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", name, "alpine:3.20", "sleep", "30"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        if not cid:
            self.skipTest("docker run failed")
        time.sleep(0.8)
        try:
            ip = subprocess.run(
                ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid],
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertTrue(ip)
            cage = NftCage.for_run("integration")
            try:
                cage.install(["172.17.0.1"], [], lab4=["172.17.0.1"])
                cage.attach(ip)
                ok = subprocess.run(["docker", "exec", cid, "ping", "-c1", "-W1", "172.17.0.1"], capture_output=True)
                blocked = subprocess.run(["docker", "exec", cid, "ping", "-c1", "-W1", "8.8.8.8"], capture_output=True)
                self.assertEqual(ok.returncode, 0)
                self.assertNotEqual(blocked.returncode, 0)
                cage.detach(ip)
            finally:
                cage.cleanup(ignore_missing=True)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(shutil.which("docker"), "docker not installed")
class MultiRunCageTests(unittest.TestCase):
    def test_two_runs_do_not_share_allow_sets(self) -> None:
        names = ["srcguard-multi-a", "srcguard-multi-b", "srcguard-multi-target"]
        cids: list[str] = []
        for name in names:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            cid = subprocess.run(
                ["docker", "run", "-d", "--rm", "--name", name, "alpine:3.20", "sleep", "40"],
                capture_output=True,
                text=True,
            ).stdout.strip()
            if not cid:
                self.skipTest("docker run failed")
            cids.append(cid)
        time.sleep(1)
        ips = [
            subprocess.run(
                ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid],
                capture_output=True,
                text=True,
            ).stdout.strip()
            for cid in cids
        ]
        target_ip = ips[2]
        gateway = "172.17.0.1"
        cage_a = NftCage.for_run("multi-a")
        cage_b = NftCage.for_run("multi-b")
        try:
            cage_a.install([target_ip], [], lab4=[target_ip])
            cage_b.install([gateway], [], lab4=[gateway])
            cage_a.attach(ips[0])
            cage_b.attach(ips[1])
            a_allowed = subprocess.run(
                ["docker", "exec", cids[0], "ping", "-c1", "-W1", target_ip], capture_output=True
            )
            a_blocked = subprocess.run(
                ["docker", "exec", cids[0], "ping", "-c1", "-W1", gateway], capture_output=True
            )
            b_allowed = subprocess.run(
                ["docker", "exec", cids[1], "ping", "-c1", "-W1", gateway], capture_output=True
            )
            b_blocked = subprocess.run(
                ["docker", "exec", cids[1], "ping", "-c1", "-W1", target_ip], capture_output=True
            )
            self.assertEqual(a_allowed.returncode, 0)
            self.assertNotEqual(a_blocked.returncode, 0)
            self.assertEqual(b_allowed.returncode, 0)
            self.assertNotEqual(b_blocked.returncode, 0)
        finally:
            cage_a.cleanup(ignore_missing=True)
            cage_b.cleanup(ignore_missing=True)
            for name in names:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)
