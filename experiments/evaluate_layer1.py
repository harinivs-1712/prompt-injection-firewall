"""Evaluate Day 3 judge results and run an optional three-pass consistency check."""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import judge_config as cfg
from experiments.run_judge import JUDGE_OUTPUT_FIELDS, JudgeCache, load_tasks
from layers.judge import GeminiJudge, ModelUnavailableError


def _overlaps(start: int, end: int, span: dict[str, Any] | None) -> bool:
    return span is not None and start < span["end"] and end > span["start"]


def detector_flags(record: dict[str, Any]) -> dict[str, bool]:
    """Return four detector outputs; judge errors are review flags only in combined."""
    rules = bool(record.get("is_instruction_like"))
    piguard = float(record.get("piguard_injection_score", 0.0)) >= cfg.PIGUARD_THRESHOLD
    judge = record.get("judge_flag") is True
    return {
        "rules": rules,
        "piguard": piguard,
        "judge": judge,
        "combined": rules or piguard or judge or bool(record.get("judge_error")),
    }


def confusion(rows: list[dict[str, Any]], flags: list[bool]) -> dict[str, int]:
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for row, flag in zip(rows, flags):
        attack = row["ground_truth"] == "attack"
        if attack and flag:
            counts["TP"] += 1
        elif attack:
            counts["FN"] += 1
        elif flag:
            counts["FP"] += 1
        else:
            counts["TN"] += 1
    return counts


def detector_metrics(rows: list[dict[str, Any]], detector: str) -> dict[str, Any]:
    flags = [detector_flags(row)[detector] for row in rows]
    counts = confusion(rows, flags)
    attacks = [i for i, row in enumerate(rows) if row["ground_truth"] == "attack"]
    harmless = [i for i, row in enumerate(rows) if row["ground_truth"] == "harmless"]
    recall = counts["TP"] / len(attacks) if attacks else None
    false_flag_rate = counts["FP"] / len(harmless) if harmless else None
    type_recall: dict[str, float | None] = {}
    for attack_type in ("classic", "action_only"):
        selected = [i for i in attacks if rows[i].get("attack_type") == attack_type]
        type_recall[attack_type] = sum(flags[i] for i in selected) / len(selected) if selected else None
    return {
        "recall": recall,
        "classic_recall": type_recall["classic"],
        "action_only_recall": type_recall["action_only"],
        "false_flag_rate": false_flag_rate,
        "confusion": counts,
    }


def load_main_rows() -> list[dict[str, Any]]:
    day2 = json.loads(cfg.SCORED_SEGMENTS_PATH.read_text(encoding="utf-8"))
    labels = json.loads(cfg.LABELS_PATH.read_text(encoding="utf-8"))
    label_by_doc = {item["doc_id"]: item for item in labels["documents"]}
    if cfg.JUDGED_OUTPUT_PATH.exists():
        judged = json.loads(cfg.JUDGED_OUTPUT_PATH.read_text(encoding="utf-8"))
        judged_by_id = {item["segment_id"]: item for item in judged}
    else:
        judged_by_id = {}
    rows: list[dict[str, Any]] = []
    for base in day2:
        doc = label_by_doc[base["doc_id"]]
        record = dict(base)
        record.update({key: value for key, value in JUDGE_OUTPUT_FIELDS.items()})
        record.update(judged_by_id.get(base["segment_id"], {}))
        attack_span = None
        if doc.get("attack_start") is not None:
            attack_span = {"start": doc["attack_start"], "end": doc["attack_end"]}
        record["ground_truth"] = "attack" if _overlaps(base["start"], base["end"], attack_span) else "harmless"
        record["attack_type"] = doc["attack_type"]
        record["split"] = doc["split"]
        rows.append(record)
    return rows


def _cache_cost(rows: list[dict[str, Any]], cache: JudgeCache, tasks: dict[str, dict[str, str]]) -> dict[str, Any]:
    calls = total_ms = prompt_tokens = output_tokens = 0
    for row in rows:
        if not row.get("judge_ran"):
            continue
        task = tasks[row["doc_id"]]["user_task"]
        key = (cfg.MODEL_NAME, cfg.PROMPT_VERSION, row["segment_id"], task)
        item = cache.get(key)
        if item is None:
            continue
        calls += int(item.get("api_call_count", 0))
        total_ms += int(row.get("judge_latency_ms") or 0)
        usage = item.get("token_usage", {})
        prompt_tokens += int(usage.get("prompt_tokens", 0))
        output_tokens += int(usage.get("candidate_tokens", 0))
    return {
        "calls": calls,
        "total_ms": total_ms,
        "prompt_tokens": prompt_tokens,
        "candidate_tokens": output_tokens,
        "fraction": sum(bool(r.get("judge_ran")) for r in rows) / len(rows) if rows else 0.0,
    }


def _fmt(value: float | int | None) -> str:
    return "n/a" if value is None else f"{value:.3f}" if isinstance(value, float) else str(value)


def _format_metrics(rows: list[dict[str, Any]], cache: JudgeCache, tasks: dict[str, dict[str, str]]) -> str:
    lines = [
        "| Split | Detector | Recall | Classic recall | Action-only recall | False-flag rate | TP / FP / TN / FN | Judge API calls | Judge time (s) | Judge coverage |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for split in ("tuning", "test"):
        subset = [row for row in rows if row["split"] == split]
        cost = _cache_cost(subset, cache, tasks)
        for detector in ("rules", "piguard", "judge", "combined"):
            m = detector_metrics(subset, detector)
            c = m["confusion"]
            lines.append(
                f"| {split} | {detector} | {_fmt(m['recall'])} | {_fmt(m['classic_recall'])} | "
                f"{_fmt(m['action_only_recall'])} | {_fmt(m['false_flag_rate'])} | "
                f"{c['TP']} / {c['FP']} / {c['TN']} / {c['FN']} | {cost['calls']} | "
                f"{cost['total_ms'] / 1000:.2f} | {cost['fraction']:.3f} |"
            )
    return "\n".join(lines)


def _misses_report(rows: list[dict[str, Any]]) -> str:
    lines = ["# Day 3 misses and harmless judge flags", ""]
    for detector in ("rules", "piguard", "judge", "combined"):
        lines.extend([f"## Attack segments missed by {detector}", ""])
        misses = [
            row for row in rows
            if row["ground_truth"] == "attack" and not detector_flags(row)[detector]
        ]
        if misses:
            for row in misses:
                lines.append(
                    f"- **{row['doc_id']} / {row['segment_id']}** (`{row['split']}`, `{row['attack_type']}`): "
                    f"{row['text']}"
                )
        else:
            lines.append("- None.")
        lines.append("")
    lines.extend(["## Harmless segments wrongly flagged by the judge", ""])
    false_flags = [row for row in rows if row["ground_truth"] == "harmless" and row.get("judge_flag") is True]
    if false_flags:
        for row in false_flags:
            lines.append(
                f"- **{row['doc_id']} / {row['segment_id']}** (`{row['split']}`): "
                f"reason: {row.get('judge_reason') or 'no reason returned'}; text: {row['text']}"
            )
    else:
        lines.append("- None recorded (or the judge has not been run).")
    errors = [row for row in rows if row.get("judge_error")]
    lines.extend(["", "## Judge errors requiring review", ""])
    if errors:
        lines.extend(f"- **{row['doc_id']} / {row['segment_id']}** (`{row['split']}`): combined detector treats this as flagged." for row in errors)
    else:
        lines.append("- None recorded.")
    return "\n".join(lines) + "\n"


def evaluate_legit() -> str:
    if not cfg.LEGIT_JUDGED_OUTPUT_PATH.exists():
        return "No content-dependent judge results yet. Run `python experiments/run_judge.py --dataset legit` after setting GEMINI_API_KEY."
    labels = json.loads(cfg.LEGIT_LABELS_PATH.read_text(encoding="utf-8"))
    label_by_doc = {record["doc_id"]: record for record in labels["documents"]}
    results = json.loads(cfg.LEGIT_JUDGED_OUTPUT_PATH.read_text(encoding="utf-8"))
    legitimate_only: list[dict[str, Any]] = []
    attacks: list[dict[str, Any]] = []
    for row in results:
        label = label_by_doc[row["doc_id"]]
        hit_attack = _overlaps(row["start"], row["end"], label.get("attack_span"))
        hit_legitimate = any(_overlaps(row["start"], row["end"], span) for span in label["legitimate_instruction_spans"])
        if hit_attack:
            attacks.append(row)
        if hit_legitimate and not hit_attack and row.get("judge_ran"):
            legitimate_only.append(row)
    evaluated = len(legitimate_only)
    flagged = sum(row.get("judge_flag") is True for row in legitimate_only)
    attack_evaluated = [row for row in attacks if row.get("judge_ran")]
    attack_flagged = sum(row.get("judge_flag") is True or row.get("judge_error") for row in attack_evaluated)
    if not evaluated:
        return "Legitimate-instruction false-flag rate: not available (no judged legitimate-only segments)."
    return (
        f"Legitimate-instruction false flags: {flagged}/{evaluated} judged legitimate-only segments "
        f"({flagged / evaluated:.3f}). In the injected-attack document, {attack_flagged}/"
        f"{len(attack_evaluated)} judged attack-overlapping segments were flagged or errored."
    )


def choose_consistency_sample(rows: list[dict[str, Any]], sample_size: int = cfg.CONSISTENCY_SAMPLE_SIZE) -> list[dict[str, Any]]:
    eligible = [row for row in rows if row.get("judge_ran")]
    rng = random.Random(cfg.RANDOM_SEED)
    attack_rows = [row for row in eligible if row["ground_truth"] == "attack"]
    harmless_rows = [row for row in eligible if row["ground_truth"] == "harmless"]
    half = sample_size // 2
    attack_sample = rng.sample(attack_rows, min(half, len(attack_rows)))
    harmless_sample = rng.sample(harmless_rows, min(sample_size - len(attack_sample), len(harmless_rows)))
    sample = attack_sample + harmless_sample
    remaining = [row for row in eligible if row not in sample]
    sample.extend(rng.sample(remaining, min(sample_size - len(sample), len(remaining))))
    rng.shuffle(sample)
    return sample


def run_consistency(rows: list[dict[str, Any]], rpm: int) -> str:
    if not os.environ.get(cfg.API_KEY_ENV):
        return f"Not run: {cfg.API_KEY_ENV} is not set; no extra Gemini calls were made."
    sample = choose_consistency_sample(rows)
    if not sample:
        return "Not run: no judged segments are available to sample."
    tasks = load_tasks()
    judge = GeminiJudge(rpm=rpm)
    run_values: dict[str, list[str]] = {}
    calls = total_ms = prompt_tokens = candidate_tokens = 0
    for row in sample:
        task = tasks[row["doc_id"]]
        values: list[str] = []
        for _run in range(cfg.CONSISTENCY_RUNS):
            outcome = judge.judge_segment(task["user_task"], task["context_note"], row["text"])
            calls += int(outcome.get("_api_call_count", 0))
            total_ms += int(outcome.get("judge_latency_ms", 0))
            usage = outcome.get("_token_usage", {})
            prompt_tokens += int(usage.get("prompt_tokens", 0))
            candidate_tokens += int(usage.get("candidate_tokens", 0))
            if outcome.get("judge_error"):
                values.append("ERROR")
            else:
                values.append("true" if outcome.get("judge_flag") else "false")
        run_values[row["segment_id"]] = values
    compared = [values for values in run_values.values() if "ERROR" not in values]
    unanimous = sum(len(set(values)) == 1 for values in compared)
    agreement = unanimous / len(compared) if compared else None
    lines = [
        f"Sample size: {len(sample)} judged segments (seed {cfg.RANDOM_SEED}); {cfg.CONSISTENCY_RUNS} uncached runs per segment.",
        f"Fully agreeing segments: {unanimous}/{len(compared)} ({agreement:.3f}) among segments with three valid outputs." if agreement is not None else "Agreement rate unavailable because all sampled segments had an API error.",
        f"Errors: {sum(values.count('ERROR') for values in run_values.values())}; API calls: {calls}; total request time: {total_ms / 1000:.2f}s; "
        f"prompt/candidate tokens reported: {prompt_tokens}/{candidate_tokens}.",
        "",
        "| Segment ID | Run 1 | Run 2 | Run 3 |",
        "|---|---|---|---|",
    ]
    for segment_id, values in run_values.items():
        if len(set(values)) > 1:
            lines.append(f"| {segment_id} | {values[0]} | {values[1]} | {values[2]} |")
    if all(len(set(values)) == 1 for values in run_values.values()):
        lines.append("| No disagreements | — | — | — |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the Day 3 context-aware judge.")
    parser.add_argument("--rpm", type=int, default=cfg.RPM_LIMIT)
    parser.add_argument("--skip-consistency", action="store_true", help="Write metrics without making the extra 3x consistency calls.")
    args = parser.parse_args(argv)
    if args.rpm < 1:
        parser.error("--rpm must be at least 1")

    rows = load_main_rows()
    tasks = load_tasks()
    cache = JudgeCache(cfg.JUDGE_CACHE_PATH)
    table = _format_metrics(rows, cache, tasks)
    judged_any = any(row.get("judge_ran") for row in rows)
    intro = "" if judged_any else (
        f"Judge metrics are pending: no Gemini judge results are cached. Set {cfg.API_KEY_ENV}, "
        "run the tuning split, then the test split. Unrun segments count as unflagged for the judge-only metric.\n\n"
    )
    report = [
        "# Day 3 detector comparison", "", intro.rstrip(),
        f"PIGuard threshold: {cfg.PIGUARD_THRESHOLD}; judge model: {cfg.MODEL_NAME}; prompt: {cfg.PROMPT_VERSION}.",
        "Judge errors count as flagged by the combined detector and require review.", "", table, "",
        "## Content-dependent tasks (known hard case)", "", evaluate_legit(), "",
    ]
    cfg.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    cfg.EVALUATION_REPORT_PATH.write_text("\n".join(part for part in report if part is not None) + "\n", encoding="utf-8")
    cfg.FLAGGED_SEGMENTS_PATH.write_text(_misses_report(rows), encoding="utf-8")

    if args.skip_consistency:
        consistency_text = "Not run by request (--skip-consistency)."
    else:
        try:
            consistency_text = run_consistency(rows, args.rpm)
        except ModelUnavailableError as exc:
            consistency_text = f"Consistency run stopped: {exc}"
        except RuntimeError as exc:
            consistency_text = f"Consistency run not completed: {exc}"
    cfg.REPEATABILITY_REPORT_PATH.write_text("# Judge repeatability\n\n" + consistency_text + "\n", encoding="utf-8")
    print(f"Wrote {cfg.EVALUATION_REPORT_PATH}, {cfg.FLAGGED_SEGMENTS_PATH}, and {cfg.REPEATABILITY_REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
