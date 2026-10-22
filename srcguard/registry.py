"""P2-6: cross-process run lease registry for max concurrent runs."""

from __future__ import annotations

import fcntl
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path


class RegistryError(RuntimeError):
    pass


@dataclass
class RunRegistry:
    path: Path = field(
        default_factory=lambda: Path(os.environ.get("SRCGUARD_STATE_DIR", str(Path.home() / ".srcguard")))
        / "runs.json"
    )
    lock_path: Path | None = None

    def __post_init__(self) -> None:
        if self.lock_path is None:
            self.lock_path = self.path.with_suffix(".lock")

    def _read(self) -> dict[str, dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, data: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    @staticmethod
    def _alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _prune(self, data: dict[str, dict]) -> dict[str, dict]:
        return {
            run_id: item
            for run_id, item in data.items()
            if isinstance(item, dict) and self._alive(int(item.get("pid", 0)))
        }

    def acquire(self, run_id: str, max_runs: int) -> bool:
        if max_runs <= 0:
            return True
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                data = self._prune(self._read())
                if run_id in data:
                    return True
                if len(data) >= max_runs:
                    return False
                data[run_id] = {"pid": os.getpid(), "ts": time.time()}
                self._write(data)
                return True
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def release(self, run_id: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                data = self._prune(self._read())
                data.pop(run_id, None)
                self._write(data)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
