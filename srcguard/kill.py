"""P0-F4 kill switch: stop the Strix process group and remove its sandbox."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class KillSwitch:
    run_dir: Path
    run_id: str
    triggered: bool = False

    def _write(self, reason: str, signal_name: str) -> Path:
        root = self.run_dir / "audit"
        root.mkdir(parents=True, exist_ok=True)
        path = root / "kill.json"
        path.write_text(
            json.dumps(
                {"run_id": self.run_id, "reason": reason, "signal": signal_name, "ts": time.time()},
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def trip(self, reason: str, proc: subprocess.Popen | None = None, *, grace_s: float = 5.0) -> Path:
        """Stop the process group, remove labeled containers, write kill.json."""
        if self.triggered:
            return self.run_dir / "audit" / "kill.json"
        self.triggered = True
        path = self._write(reason, "SIGTERM")
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=grace_s)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=grace_s)
                except subprocess.TimeoutExpired:
                    pass
        try:
            out = subprocess.run(
                ["docker", "ps", "-aq", "--filter", f"label=strix-run-id={self.run_id}"],
                capture_output=True,
                text=True,
                timeout=15,
            ).stdout.strip()
            if out:
                subprocess.run(
                    ["docker", "rm", "-f", *out.split()],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
        except Exception:  # noqa: BLE001
            pass
        return path
