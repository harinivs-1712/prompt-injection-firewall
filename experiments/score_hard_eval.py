"""Segment held-out hard documents and run the frozen rules/PIGuard signals."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import judge_config
from experiments.hard_eval_common import (
    HARD_EVAL_DIR, HARD_LABELS_PATH, HARD_TASKS_PATH, SCORE_METADATA_PATH,
    SCORED_PATH, SEGMENTER_SETTINGS, verify_frozen_manifest, validate_hard_dataset,
)
from layers.instruction_rules import instruction_signals
from layers.segmenter import make_segments
from layers.piguard_scorer import BATCH_SIZE, MODEL_NAME, PIGuardScorer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score the held-out synthetic hard-evaluation documents.")
    parser.add_argument("--allow-changed", action="store_true", help="Continue with a manifest warning if frozen Layer 1 differs.")
    args = parser.parse_args(argv)
    try:
        manifest_status = verify_frozen_manifest(allow_changed=args.allow_changed)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    labels = json.loads(HARD_LABELS_PATH.read_text(encoding="utf-8"))
    tasks = json.loads(HARD_TASKS_PATH.read_text(encoding="utf-8"))
    errors = validate_hard_dataset(labels, tasks)
    if errors:
        print("Hard dataset validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    records = []
    doc_by_id = {item["doc_id"]: item for item in labels["documents"]}
    for doc in labels["documents"]:
        text = (HARD_EVAL_DIR / f"{doc['doc_id']}.txt").read_text(encoding="utf-8")
        for segment in make_segments(doc["doc_id"], text, **SEGMENTER_SETTINGS):
            if doc["attack_start"] is None:
                ground_truth = "harmless"
            elif segment["start"] <= doc["attack_start"] and segment["end"] >= doc["attack_end"]:
                ground_truth = "attack"
            elif segment["start"] < doc["attack_end"] and segment["end"] > doc["attack_start"]:
                ground_truth = "partial"
            else:
                ground_truth = "harmless"
            records.append({
                **segment,
                "category": doc["category"],
                "attack_category": doc["attack_category"],
                "control_type": doc["control_type"],
                "ground_truth": ground_truth,
                "split": doc["split"],
                "is_instruction_like": False,
                "instruction_reasons": [],
            })
    if len(records) > 450:
        print(f"STOP: {len(records)} segment calls would exceed the approximately 450-call budget. Shorten documents; none were skipped.", file=sys.stderr)
        return 1
    for row in records:
        reasons = instruction_signals(row["text"])
        row["instruction_reasons"] = reasons
        row["is_instruction_like"] = bool(reasons)
    scorer = PIGuardScorer(batch_size=BATCH_SIZE)
    scores = scorer.score([row["text"] for row in records])
    if len(scores) != len(records):
        raise RuntimeError("PIGuard score count did not match hard-eval segment count")
    for row, result in zip(records, scores):
        row.update(result)
    SCORED_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCORED_PATH.write_text(json.dumps(records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    SCORE_METADATA_PATH.write_text(json.dumps({
        "manifest_sha256": manifest_status["manifest_sha256"],
        "changed_components": manifest_status["changed_components"],
        "warning": manifest_status.get("warning"),
        "rule_model": "instruction_rules.py",
        "piguard_model": MODEL_NAME,
        "piguard_threshold": judge_config.PIGUARD_THRESHOLD,
        "segmenter_settings": SEGMENTER_SETTINGS,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Scored {len(records)} segments with rules and PIGuard; threshold {judge_config.PIGUARD_THRESHOLD}.")
    print(f"Saved {SCORED_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
