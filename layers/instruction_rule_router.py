"""Version-aware routing for instruction signals; default remains frozen v1."""
from __future__ import annotations

from config.rules_config import RULES_VERSION


def instruction_signals(text: str, *, version: str | None = None, variant: str = "BROAD") -> list[str]:
    selected = (version or RULES_VERSION).lower()
    if selected == "v1":
        from layers.instruction_rules import instruction_signals as signals_v1
        return signals_v1(text)
    if selected == "v2":
        from layers.instruction_rules_v2 import instruction_signals_v2
        return instruction_signals_v2(text, variant=variant)
    raise ValueError(f"Unsupported RULES_VERSION: {selected}")


def is_instruction_like(text: str, *, version: str | None = None, variant: str = "BROAD") -> bool:
    return bool(instruction_signals(text, version=version, variant=variant))
