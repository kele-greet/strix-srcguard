"""S5: read-only source mount + writable scratch."""

from __future__ import annotations

import tempfile
from pathlib import Path

from .common import Result, run_cmd


def run(root: Path) -> Result:
    evidence: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / "app.py").write_text("print('hi')\n", encoding="utf-8")
        rc, out = run_cmd(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{base}:/src:ro",
                "alpine:3.20",
                "sh",
                "-c",
                "echo x > /src/x",
            ],
            timeout=30,
        )
        evidence.append(f"write_to_ro rc={rc} out={out[-160:]}")
        assert rc != 0 and not (base / "x").exists()

        rc2, out2 = run_cmd(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{base}:/scratch",
                "alpine:3.20",
                "sh",
                "-c",
                "echo ok > /scratch/ok.txt",
            ],
            timeout=30,
        )
        evidence.append(f"write_to_scratch rc={rc2} out={out2[-80:]}")
        assert rc2 == 0 and (base / "ok.txt").exists()
        return Result(
            "S5",
            "read-only source + scratch",
            "PASS",
            "source can be mounted ro and still leave a writable scratch path",
            evidence,
        )
    return Result("S5", "read-only source + scratch", "FAIL", "unexpected", evidence)
