"""Analyze v1 development misses using only the already-cached judge-all output."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.judge_config import PIGUARD_THRESHOLD
from experiments.filter_v2_common import ROOT as PROJECT_ROOT, V2_RESULTS, load_heldout, segment_truth

DEV = PROJECT_ROOT / "data" / "hard_eval"
SCORED = V2_RESULTS / "hard_eval_segments_scored.json"
JUDGED_ALL = V2_RESULTS / "hard_eval_segments_judged_all.json"
JUDGED_CASCADE = V2_RESULTS / "hard_eval_segments_judged_cascade.json"
REPORT = V2_RESULTS / "filter_v2_dev_analysis.md"
REVIEW_CSV = DEV / "label_review.csv"


def main() -> int:
    # The immutable held-out hash is verified before every later phase.
    held_labels, _ = load_heldout()
    del held_labels
    labels = json.loads((DEV / "labels.json").read_text(encoding="utf-8"))
    scored = json.loads(SCORED.read_text(encoding="utf-8"))
    judged = json.loads(JUDGED_ALL.read_text(encoding="utf-8"))
    cascade = json.loads(JUDGED_CASCADE.read_text(encoding="utf-8"))
    scored_by_id = {row["segment_id"]: row for row in scored}
    judged_by_id = {row["segment_id"]: row for row in judged}
    cascade_by_id = {row["segment_id"]: row for row in cascade}
    docs = {item["doc_id"]: item for item in labels["documents"]}
    rows: list[str] = [
        "# Rules v2 dev-miss analysis (offline cached judge answers)",
        "",
        "No API calls were made. Attack labels use full containment; partial overlaps are not counted as attack segments.",
        "",
        "## Attacks with no filter-selected fully-containing segment",
        "",
    ]
    missed_ids: set[str] = set()
    for item in labels["documents"]:
        if not item.get("attack_text"):
            continue
        containing = [
            row for row in scored
            if row["doc_id"] == item["doc_id"]
            and row["start"] <= item["attack_start"]
            and row["end"] >= item["attack_end"]
        ]
        selected = [
            row for row in containing
            if row.get("is_instruction_like")
            or float(row.get("piguard_injection_score", 0.0)) >= PIGUARD_THRESHOLD
        ]
        if selected:
            continue
        missed_ids.add(item["doc_id"])
        rows.append(f"- **{item['doc_id']}** ({item.get('attack_type', item.get('attack_category', item.get('category')))}): {item['attack_text']}")
        if containing:
            for seg in containing:
                answer = judged_by_id[seg["segment_id"]]
                rows.append(
                    f"  - {seg['segment_id']}: judge_flag={answer.get('judge_flag')}; "
                    f"reason={answer.get('judge_reason')}"
                )
        else:
            rows.append("  - No segment fully contained the labeled attack span.")
    rows += ["", "## Judge-on-all flags absent from the cascade view", ""]
    flagged_missing = []
    for row in judged:
        c = cascade_by_id[row["segment_id"]]
        if row.get("judge_flag") and not c.get("judge_ran"):
            item = docs[row["doc_id"]]
            status = segment_truth(row, item)
            flagged_missing.append((row, status))
    if not flagged_missing:
        rows.append("None.")
    else:
        for row, status in flagged_missing:
            rows.append(
                f"- `{row['segment_id']}` — **{status}**; judge reason: {row.get('judge_reason')}\n"
                f"  Segment: {row['text']}"
            )
    rows += ["", "## Split-attack window diagnostic", ""]
    for item in labels["documents"]:
        if item.get("attack_type") != "split_attack" and item.get("category") != "split_attack":
            continue
        containing = [
            row for row in judged
            if row["doc_id"] == item["doc_id"]
            and row["start"] <= item["attack_start"]
            and row["end"] >= item["attack_end"]
        ]
        rows.append(f"- **{item['doc_id']}**: full attack span inside one window: {'yes' if containing else 'no'}.")
        for row in containing:
            rows.append(f"  - `{row['segment_id']}` judge_flag={row.get('judge_flag')}; reason: {row.get('judge_reason')}")
    rows.append("")
    REPORT.write_text("\n".join(rows), encoding="utf-8")

    with REVIEW_CSV.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["attack_id", "text", "category", "reviewer_label"])
        for item in labels["documents"]:
            if item.get("attack_text"):
                writer.writerow([
                    item["doc_id"], item["attack_text"],
                    item.get("attack_type", item.get("attack_category", item.get("category"))),
                    "",
                ])
    print(f"Wrote {REPORT} and {REVIEW_CSV}; no judge/API calls made.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
