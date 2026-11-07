"""Evaluate Layer 1 rules and PIGuard on the fixed document-level splits."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from layers.instruction_rules import instruction_signals
from layers.piguard_scorer import BATCH_SIZE, MODEL_NAME, PIGuardScorer
from layers.segmenter import make_segments

LABELED_DIR = ROOT / "data" / "labeled"
RESULTS_DIR = ROOT / "data" / "results"
DEFAULT_PIGUARD_THRESHOLD = 0.5
THRESHOLD_SWEEP = (0.1, 0.3, 0.5, 0.7, 0.9)
REQUIRED_FIELDS = (
    "segment_id", "doc_id", "start", "end", "text", "is_instruction_like",
    "instruction_reasons", "piguard_label", "piguard_injection_score",
    "truncated", "ground_truth", "split",
)


def _overlaps(start: int, end: int, attack_start: int | None, attack_end: int | None) -> bool:
    return attack_start is not None and attack_end is not None and start < attack_end and end > attack_start


def _binary_counts(records: list[dict[str, Any]], flags: list[bool]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for record, flagged in zip(records, flags):
        attack = record["ground_truth"] == "attack"
        if attack and flagged:
            tp += 1
        elif attack:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn}


def _metrics(records: list[dict[str, Any]], detector: str, threshold: float = DEFAULT_PIGUARD_THRESHOLD) -> dict[str, Any]:
    def flagged(record: dict[str, Any]) -> bool:
        rules = bool(record["instruction_reasons"])
        model = record["piguard_injection_score"] >= threshold
        return {"rules": rules, "piguard": model, "either": rules or model}[detector]

    flags = [flagged(r) for r in records]
    counts = _binary_counts(records, flags)
    attacks = [i for i, r in enumerate(records) if r["ground_truth"] == "attack"]
    harmless = [i for i, r in enumerate(records) if r["ground_truth"] == "harmless"]
    recall = counts["TP"] / len(attacks) if attacks else 0.0
    fpr = counts["FP"] / len(harmless) if harmless else 0.0
    by_type: dict[str, float | None] = {}
    for attack_type in ("classic", "action_only"):
        ids = [i for i in attacks if records[i]["attack_type"] == attack_type]
        by_type[attack_type] = sum(flags[i] for i in ids) / len(ids) if ids else None
    return {"recall": recall, "fpr": fpr, "counts": counts, "by_type": by_type}


def _render_table(metrics: dict[str, dict[str, dict[str, Any]]]) -> str:
    lines = [
        "| Split | Detector | Recall | Classic recall | Action-only recall | Harmless flag rate (FPR) | TP / FP / TN / FN |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for split in ("tuning", "test"):
        for detector in ("rules", "piguard", "either"):
            m = metrics[split][detector]
            c = m["counts"]
            fmt = lambda v: "n/a" if v is None else f"{v:.3f}"
            lines.append(
                f"| {split} | {detector} | {fmt(m['recall'])} | {fmt(m['by_type']['classic'])} | "
                f"{fmt(m['by_type']['action_only'])} | {fmt(m['fpr'])} | "
                f"{c['TP']} / {c['FP']} / {c['TN']} / {c['FN']} |"
            )
    return "\n".join(lines)


def compare() -> dict[str, Any]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    labels = json.loads((LABELED_DIR / "labels.json").read_text(encoding="utf-8"))
    docs = {record["doc_id"]: record for record in labels["documents"]}
    segment_records: list[dict[str, Any]] = []
    for doc_id, doc in docs.items():
        text = (LABELED_DIR / f"{doc_id}.txt").read_text(encoding="utf-8")
        for segment in make_segments(doc_id, text, window=3, stride=1):
            reasons = instruction_signals(segment["text"])
            segment_records.append({
                "segment_id": segment["segment_id"],
                "doc_id": doc_id,
                "start": segment["start"],
                "end": segment["end"],
                "text": segment["text"],
                "is_instruction_like": bool(reasons),
                "instruction_reasons": reasons,
                "ground_truth": "attack" if _overlaps(segment["start"], segment["end"], doc["attack_start"], doc["attack_end"]) else "harmless",
                "attack_type": doc["attack_type"],
                "split": doc["split"],
            })

    scorer = PIGuardScorer(batch_size=BATCH_SIZE)
    model_results = scorer.score([record["text"] for record in segment_records])
    if len(model_results) != len(segment_records):
        raise RuntimeError("PIGuard scoring output count does not match segment count")
    for record, scored in zip(segment_records, model_results):
        record.update(scored)

    # Keep the downstream interface fixed; evaluation-only metadata stays in reports.
    scored_output = [{key: record[key] for key in REQUIRED_FIELDS} for record in segment_records]
    (RESULTS_DIR / "segments_scored.json").write_text(
        json.dumps(scored_output, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    metrics: dict[str, dict[str, dict[str, Any]]] = {}
    for split in ("tuning", "test"):
        rows = [r for r in segment_records if r["split"] == split]
        metrics[split] = {name: _metrics(rows, name) for name in ("rules", "piguard", "either")}

    tuning_rows = [r for r in segment_records if r["split"] == "tuning"]
    sweep = [(threshold, _metrics(tuning_rows, "piguard", threshold)) for threshold in THRESHOLD_SWEEP]
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError("matplotlib is required to create the threshold tradeoff chart") from exc
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot([m["fpr"] for _, m in sweep], [m["recall"] for _, m in sweep], marker="o")
    for threshold, m in sweep:
        ax.annotate(f"{threshold:.1f}", (m["fpr"], m["recall"]), xytext=(5, 5), textcoords="offset points")
    ax.set(xlabel="Harmless segment flag rate (FPR)", ylabel="Attack segment recall", title="PIGuard threshold tradeoff (tuning split)")
    ax.set_xlim(left=0)
    ax.set_ylim(0, 1.05)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "threshold_tradeoff.png", dpi=160)
    plt.close(fig)

    table = _render_table(metrics)
    comparison = [
        "# Detector comparison", "",
        f"PIGuard model: `{MODEL_NAME}`; threshold `{DEFAULT_PIGUARD_THRESHOLD:.1f}`; batch size `{BATCH_SIZE}`.",
        "The rules output is a screening signal, not a security verdict. The test split was not used for threshold selection.", "",
        table, "", "## PIGuard threshold sweep (tuning split)", "",
        "| Threshold | Recall | Classic recall | Action-only recall | FPR | TP / FP / TN / FN |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for threshold, m in sweep:
        c = m["counts"]
        comparison.append(f"| {threshold:.1f} | {m['recall']:.3f} | {m['by_type']['classic'] or 0:.3f} | {m['by_type']['action_only'] or 0:.3f} | {m['fpr']:.3f} | {c['TP']} / {c['FP']} / {c['TN']} / {c['FN']} |")
    (RESULTS_DIR / "comparison.md").write_text("\n".join(comparison) + "\n", encoding="utf-8")

    misses: list[str] = ["# Missed attack segments", ""]
    for detector in ("rules", "piguard", "either"):
        misses.extend([f"## {detector}", ""])
        count = 0
        for record in segment_records:
            if record["ground_truth"] != "attack":
                continue
            is_flagged = {
                "rules": bool(record["instruction_reasons"]),
                "piguard": record["piguard_injection_score"] >= DEFAULT_PIGUARD_THRESHOLD,
                "either": bool(record["instruction_reasons"]) or record["piguard_injection_score"] >= DEFAULT_PIGUARD_THRESHOLD,
            }[detector]
            if not is_flagged:
                count += 1
                misses.append(f"- **{record['doc_id']} / {record['segment_id']}** (`{record['split']}`, `{record['attack_type']}`): {record['text']}")
        if not count:
            misses.append("- None.")
        misses.append("")
    (RESULTS_DIR / "misses.md").write_text("\n".join(misses), encoding="utf-8")

    print(table)
    print(f"\nWrote results to {RESULTS_DIR}")
    return {"metrics": metrics, "sweep": sweep, "segments": scored_output}


if __name__ == "__main__":
    compare()
