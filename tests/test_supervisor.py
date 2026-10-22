from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from srcguard.cage import NftCage
from srcguard.preflight import prepare_run
from srcguard.scope import compile_policy, load_scope
from srcguard.supervisor import launch


@unittest.skipUnless(shutil.which("docker"), "docker not installed")
class SupervisorTests(unittest.TestCase):
    def test_launch_installs_and_cleans_cage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text("program: x\nin_scope: ['1.1.1.1']\nbudgets:\n  max_turns: 1\n", encoding="utf-8")
            compiled = compile_policy(load_scope(scope))
            spec = prepare_run(
                compiled,
                ["https://1.1.1.1"],
                base_dir=base / "runs",
                run_id="launch-test",
            )
            fake = base / "fake-strix"
            fake.write_text("#!/bin/sh\nsleep 1\nexit 0\n", encoding="utf-8")
            fake.chmod(0o755)
            result = launch(spec, compiled, strix_bin=str(fake), attach_timeout_s=2)
            self.assertEqual(result.exit_code, 0)
            self.assertIsNone(result.container_ip)
            with self.assertRaises(Exception):
                NftCage.for_run("launch-test").show()


if __name__ == "__main__":
    unittest.main()


class SystemDnsTests(unittest.TestCase):
    """The host resolver often sits inside BLOCK4 (e.g. 10.255.255.254).

    If ``dns4`` is empty at install time the block4 rule drops every DNS query,
    the sandbox cannot resolve the target, and every Caido request comes back
    with a null response.
    """

    def test_system_resolver_is_installed_in_cage(self) -> None:
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            scope = base / "scope.yaml"
            scope.write_text(
                "program: x\nin_scope: ['1.1.1.1']\nbudgets:\n  max_turns: 1\n",
                encoding="utf-8",
            )
            compiled = compile_policy(load_scope(scope))
            spec = prepare_run(
                compiled,
                ["https://1.1.1.1"],
                base_dir=base / "runs",
                run_id="dns-test",
            )
            fake = base / "fake-strix"
            fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake.chmod(0o755)
            cage = mock.MagicMock()
            with (
                mock.patch("srcguard.supervisor._system_dns_ips", return_value=["10.255.255.254"]),
                mock.patch("srcguard.supervisor.NftCage.for_run", return_value=cage),
                mock.patch("srcguard.supervisor._container_for_run", return_value=None),
                mock.patch("srcguard.supervisor.EgressCollector", side_effect=RuntimeError("no dmesg")),
            ):
                result = launch(spec, compiled, strix_bin=str(fake), attach_timeout_s=0.5)

            self.assertEqual(result.exit_code, 0)
            kwargs = cage.install.call_args.kwargs
            self.assertEqual(kwargs["dns4"], ["10.255.255.254"])
            self.assertTrue(
                any("system DNS allowed" in w for w in result.warnings), result.warnings
            )
            cage.cleanup.assert_called()


class PlatformTests(unittest.TestCase):
    def test_non_linux_fails_closed(self) -> None:
        from unittest import mock

        from srcguard.cage import CageError
        from srcguard.supervisor import ensure_supported_platform

        with mock.patch("srcguard.supervisor.platform.system", return_value="Darwin"):
            with self.assertRaises(CageError):
                ensure_supported_platform()
        with mock.patch("srcguard.supervisor.platform.system", return_value="Linux"):
            ensure_supported_platform()
