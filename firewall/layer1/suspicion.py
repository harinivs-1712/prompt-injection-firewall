"""Configurable, graded suspicion assessment from detector signals."""
from __future__ import annotations

from typing import Any

from config import threat_config


def _matches(when: dict[str, Any], state: dict[str, Any]) -> bool:
    return all(state.get(key) == expected for key, expected in when.items())


def assess_suspicion(
    *,
    rules_flag: bool,
    piguard_flag: bool,
    judge_ran: bool,
    judge_flag: bool | None,
    judge_error: bool,
    table_name: str | None = None,
) -> dict[str, Any]:
    """Return suspicion_level and reasons using the selected config table.

    With both deterministic detectors signaling and no judge result, the
    default assigns medium because two independent screening signals agree.
    """
    name = table_name or threat_config.ACTIVE_LEVEL_TABLE
    if name not in threat_config.LEVEL_TABLES:
        raise KeyError(f"Unknown suspicion table: {name}")
    table = threat_config.LEVEL_TABLES[name]
    if "rules" in table:
        state = {
            "rules_flag": bool(rules_flag),
            "piguard_flag": bool(piguard_flag),
            "judge_ran": bool(judge_ran),
            "judge_flag": judge_flag,
            "judge_error": bool(judge_error),
        }
        match = next((rule for rule in table["rules"] if _matches(rule["when"], state)), None)
        if match is None:
            raise ValueError(f"No {name!r} suspicion rule matches state {state}")
        base_level = match["level"]
        reasons = list(match["reasons"])
    else:
        parent = table.get("base", "default")
        base = assess_suspicion(
            rules_flag=rules_flag,
            piguard_flag=piguard_flag,
            judge_ran=judge_ran,
            judge_flag=judge_flag,
            judge_error=judge_error,
            table_name=parent,
        )
        base_level = base["suspicion_level"]
        reasons = base["level_reasons"]
    level = table.get("level_map", {}).get(base_level, base_level)
    return {"suspicion_level": level, "level_reasons": reasons}


def apply_suspicion(record: dict[str, Any], table_name: str | None = None) -> dict[str, Any]:
    """Derive inputs from a scored/judged segment and attach suspicion fields."""
    from config.judge_config import PIGUARD_THRESHOLD

    result = assess_suspicion(
        rules_flag=bool(record.get("is_instruction_like")),
        piguard_flag=float(record.get("piguard_injection_score") or 0.0) >= PIGUARD_THRESHOLD,
        judge_ran=bool(record.get("judge_ran")),
        judge_flag=record.get("judge_flag"),
        judge_error=bool(record.get("judge_error")),
        table_name=table_name,
    )
    return {**record, **result}
