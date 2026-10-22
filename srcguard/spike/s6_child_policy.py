"""S6: static confirmation that child agents do not inherit the instruction file."""

from __future__ import annotations

from pathlib import Path

from .common import Result


def run(root: Path) -> Result:
    evidence: list[str] = []
    try:
        inputs = (root / "strix" / "core" / "inputs.py").read_text(encoding="utf-8")
        graph = (root / "strix" / "tools" / "agents_graph" / "tools.py").read_text(encoding="utf-8")
        runner = (root / "strix" / "core" / "runner.py").read_text(encoding="utf-8")

        child_start = inputs.index("def child_initial_input(")
        next_start = inputs.find("\ndef ", child_start + 1)
        child_end = next_start if next_start != -1 else len(inputs)
        child_body = inputs[child_start:child_end]
        evidence.append(f"child_initial_input_has_user_instructions={'user_instructions' in child_body}")
        evidence.append(f"child_initial_input_mentions_parent_history={'parent_history' in child_body}")
        assert "user_instructions" not in child_body
        assert "parent_history" in child_body

        has_parent_history = "parent_history = list(ctx.turn_input)" in graph
        evidence.append(f"create_agent_parent_history={has_parent_history}")
        assert "parent_history = list(ctx.turn_input)" in graph

        uses_scope = "system_prompt_context=scope_context" in runner
        evidence.append(f"child_factory_uses_scope_context={uses_scope}")
        assert "system_prompt_context=scope_context" in runner

        return Result(
            "S6",
            "child policy propagation",
            "PASS",
            "confirmed: child gets task + turn_input only; instruction file is root-only (L1 must use gateway or network)",
            evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return Result("S6", "child policy propagation", "FAIL", f"{type(exc).__name__}: {exc}", evidence)
