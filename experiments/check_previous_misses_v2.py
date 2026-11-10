"""Offline rescore of the six v1 cascade misses using active v2 + PIGuard."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.judge_config import PIGUARD_THRESHOLD
from layers.instruction_rule_router import instruction_signals

SOURCE = ROOT / "data" / "results" / "hard_eval_segments_scored.json"
OUT_JSON = ROOT / "data" / "results" / "previous_misses_v2_rescore.json"
OUT_MD = ROOT / "data" / "results" / "previous_misses_v2_rescore.md"
MISSES = (
    "hard_single_statement_style_02",
    "hard_single_statement_style_04",
    "hard_single_authority_claim_01",
    "hard_single_authority_claim_04",
    "hard_single_authority_claim_05",
    "hard_single_concealment_04",
)


def rescore() -> list[dict]:
    rows = json.loads(SOURCE.read_text(encoding="utf-8"))
    results = []
    for doc_id in MISSES:
        full_segments = [
            row for row in rows
            if row["doc_id"] == doc_id and row["ground_truth"] == "attack"
        ]
        if not full_segments:
            raise ValueError(f"No fully containing attack segments found for {doc_id}")
        for row in full_segments:
            reasons = instruction_signals(row["text"], version="v2", variant="BROAD")
            score = float(row["piguard_injection_score"])
            piguard_flag = score >= PIGUARD_THRESHOLD
            results.append({
                "doc_id": doc_id,
                "segment_id": row["segment_id"],
                "start": row["start"],
                "end": row["end"],
                "text": row["text"],
                "instruction_rules_version": "v2",
                "instruction_reasons": reasons,
                "instruction_flag": bool(reasons),
                "piguard_score": score,
                "piguard_threshold": PIGUARD_THRESHOLD,
                "piguard_flag": piguard_flag,
                "cascade_selected_for_judge": bool(reasons) or piguard_flag,
                "judge_ran": False,
            })
    return results


def main() -> int:
    results = rescore()
    OUT_JSON.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    selected = sum(row["cascade_selected_for_judge"] for row in results)
    docs_selected = {row["doc_id"] for row in results if row["cascade_selected_for_judge"]}
    lines = [
        "# Rescore of the six previous cascade misses with rules v2",
        "",
        "This is an offline rescore of the cached PIGuard values and cached hard-evaluation segments. The cascade selects a segment when v2 instruction rules flag it OR its PIGuard score meets the frozen threshold of 0.50. No judge/API calls were made, so ‘selected’ means it would be sent to the judge, not that the judge confirmed an attack.",
        "",
        f"**Result:** {len(docs_selected)}/6 attack cases now have a fully containing segment selected; {selected}/{len(results)} fully containing attack segments are selected.",
        "",
        "| Previously missed attack | Fully containing segments checked | V2 instruction rule flags | PIGuard flags (≥ 0.50) | Combo selects for judge |",
        "|---|---:|---:|---:|---:|",
    ]
    for doc_id in MISSES:
        group = [row for row in results if row["doc_id"] == doc_id]
        selected_group = sum(row["cascade_selected_for_judge"] for row in group)
        rule_group = sum(row["instruction_flag"] for row in group)
        pig_group = sum(row["piguard_flag"] for row in group)
        lines.append(f"| `{doc_id}` | {len(group)} | {rule_group}/{len(group)} | {pig_group}/{len(group)} | {selected_group}/{len(group)} |")
    lines.extend(["", "## Segment-level results", ""])
    for row in results:
        reasons = ", ".join(row["instruction_reasons"]) or "none"
        lines.extend([
            f"### `{row['segment_id']}`",
            f"- V2 rules: **{row['instruction_flag']}** ({reasons})",
            f"- PIGuard: **{row['piguard_flag']}** (score {row['piguard_score']:.4f}; threshold {PIGUARD_THRESHOLD:.2f})",
            f"- Combo: **{'selected for judge' if row['cascade_selected_for_judge'] else 'not selected'}**",
            f"- Segment text: {row['text'].replace(chr(10), ' ')}",
            "",
        ])
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"V2 combo selected {selected}/{len(results)} full attack segments across {len(docs_selected)}/6 cases.")
    print(f"Wrote {OUT_MD} and {OUT_JSON}; no judge/API calls made.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
