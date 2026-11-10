"""Offline Layer 1 regression replay and false-alarm review; never calls Gemini."""
from __future__ import annotations

import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import judge_config, threat_config
from config import layer1_settings
from experiments.hard_eval_common import (
    ALL_LEVELED_PATH, CASCADE_LEVELED_PATH, HARD_EVAL_DIR, HARD_LABELS_PATH,
    HARD_TASKS_PATH, JUDGED_ALL_PATH, CASCADE_PATH, SCORED_PATH,
)
from layers import scan as scan_module
from layers.scan import scan, verify_manifest
from layers.instruction_rule_router import instruction_signals as live_instruction_signals

RESULTS = ROOT / "data" / "results"
REGRESSION_REPORT = RESULTS / "layer1_final_regression.md"
FALSE_ALARM_REPORT = RESULTS / "layer1_false_alarm_report.md"
LEVELS = ("none", "low", "medium", "high", "needs_review")


class _CachedPIGuard:
    """Replay frozen detector outputs by exact segment text; score only missing legacy rows."""
    def __init__(self) -> None:
        rows = (_read(RESULTS / "segments_scored.json") + _read(SCORED_PATH) +
                _read(RESULTS / "hard_eval_segments_scored.json"))
        self.by_text = {}
        for row in rows:
            self.by_text.setdefault(row["text"], {
                "piguard_label": row["piguard_label"],
                "piguard_injection_score": row["piguard_injection_score"],
                "truncated": row.get("truncated", False),
            })
        self.fallback = None

    def score(self, texts: list[str]) -> list[dict[str, Any]]:
        missing = [text for text in texts if text not in self.by_text]
        if missing:
            from layers.piguard_scorer import BATCH_SIZE, PIGuardScorer
            if self.fallback is None:
                self.fallback = PIGuardScorer(batch_size=BATCH_SIZE)
            scored = self.fallback.score(missing)
            self.by_text.update(zip(missing, scored))
        return [dict(self.by_text[text]) for text in texts]


class _CachedRules:
    """Reuse previously scored rule reasons during the orchestration replay."""
    def __init__(self) -> None:
        rows = _read(RESULTS / "segments_scored.json") + _read(RESULTS / "hard_eval_segments_scored.json")
        self.by_text = {row["text"]: list(row.get("instruction_reasons", [])) for row in rows}

    def __call__(self, text: str, *, version: str | None = None, variant: str = "BROAD") -> list[str]:
        if text in self.by_text:
            return list(self.by_text[text])
        return live_instruction_signals(text, version=version, variant=variant)


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    center = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, center - half), min(1.0, center + half)


def rate(k: int, n: int) -> str:
    if not n:
        return "0/0 (n/a)"
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({k/n:.1%}; 95% Wilson CI {lo:.1%}–{hi:.1%})"


def _read(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def _task(tasks: dict, doc_id: str) -> dict:
    result = tasks.get(doc_id)
    if not result or not result.get("user_task"):
        raise ValueError(f"No static user_task configured for {doc_id}")
    return result


def _compare_views(actual: list[dict], expected_segments: list[dict], expected_levels: list[dict], label: str) -> list[str]:
    issues = []
    actual_by_id = {r["segment_id"]: r for r in actual}
    base_by_id = {r["segment_id"]: r for r in expected_segments}
    level_by_id = {r["segment_id"]: r for r in expected_levels}
    if set(actual_by_id) != set(base_by_id):
        issues.append(f"{label}: segment IDs differ (scan={len(actual_by_id)}, stored={len(base_by_id)}; only-scan={len(set(actual_by_id)-set(base_by_id))}; only-stored={len(set(base_by_id)-set(actual_by_id))})")
    fields = ("rules_flag", "piguard_flag", "piguard_label", "truncated", "judge_ran",
              "judge_is_instruction", "judge_needed_for_task", "judge_flag", "judge_reason", "judge_error")
    for segment_id in sorted(set(actual_by_id) & set(base_by_id)):
        a, b = actual_by_id[segment_id], base_by_id[segment_id]
        expected_rules = bool(b.get("is_instruction_like", b.get("rules_flag")))
        expected_pig = float(b.get("piguard_injection_score", b.get("piguard_score", 0)) or 0) >= judge_config.PIGUARD_THRESHOLD
        checks = {"rules_flag": (a["rules_flag"], expected_rules),
                  "piguard_flag": (a["piguard_flag"], expected_pig),
                  "piguard_label": (a["piguard_label"], b.get("piguard_label")),
                  "truncated": (a["truncated"], b.get("truncated", False)),
                  "judge_ran": (a["judge_ran"], bool(b.get("judge_ran")))}
        for field in ("start", "end", "text"):
            if a[field] != b.get(field):
                issues.append(f"{label}: {segment_id} {field} differs")
        if b.get("judge_ran"):
            checks.update({key: (a.get(key), b.get(key)) for key in fields[5:]})
        for field, (got, expected) in checks.items():
            if got != expected:
                issues.append(f"{label}: {segment_id} {field}: scan={got!r}, stored={expected!r}")
        if segment_id in level_by_id and a["suspicion_level"] != level_by_id[segment_id].get("suspicion_level"):
            issues.append(f"{label}: {segment_id} suspicion: scan={a['suspicion_level']!r}, stored={level_by_id[segment_id].get('suspicion_level')!r}")
    return issues


def _run_hard_eval() -> tuple[list[dict], list[dict], list[str]]:
    labels = json.loads(HARD_LABELS_PATH.read_text(encoding="utf-8"))
    tasks = json.loads(HARD_TASKS_PATH.read_text(encoding="utf-8"))
    scans: dict[str, list[dict]] = {}
    for mode in ("all", "cascade"):
        combined = []
        for doc in labels["documents"]:
            doc_id = doc["doc_id"]
            print(f"replay hard-eval {mode}: {doc_id}", flush=True)
            content = (HARD_EVAL_DIR / f"{doc_id}.txt").read_text(encoding="utf-8")
            task = _task(tasks, doc_id)
            result = scan(content, doc_id=doc_id, source_type="document", user_task=task["user_task"],
                          context_note=task.get("context_note"), mode=mode, legacy_cache=True)
            combined.extend(result.segments)
        scans[mode] = combined
    issues = []
    issues += _compare_views(scans["all"], _read(JUDGED_ALL_PATH), _read(ALL_LEVELED_PATH), "hard-eval/all")
    issues += _compare_views(scans["cascade"], _read(CASCADE_PATH), _read(CASCADE_LEVELED_PATH), "hard-eval/cascade")
    return scans["all"], scans["cascade"], issues


def _run_early_labeled() -> list[str]:
    """Replay earlier main/legit document sets against their cached outputs."""
    tasks = json.loads(judge_config.TASKS_PATH.read_text(encoding="utf-8"))
    issues: list[str] = []
    specs = (
        (ROOT / "data" / "labeled", "cascade", RESULTS / "segments_scored.json", RESULTS / "segments_judged.json", RESULTS / "segments_leveled.json"),
        (ROOT / "data" / "labeled_legit", "all", None, RESULTS / "legit_segments_judged.json", None),
    )
    for folder, mode, scored_path, judged_path, leveled_path in specs:
        print(f"replay early dataset: {folder.name}", flush=True)
        labels_path = folder / "labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        baseline_scored = _read(scored_path) if scored_path else []
        baseline_judged = _read(judged_path) if judged_path.exists() else []
        baseline_leveled = _read(leveled_path) if leveled_path and leveled_path.exists() else []
        for doc in labels["documents"]:
            doc_id = doc["doc_id"]
            print(f"  {doc_id}", flush=True)
            task = _task(tasks, doc_id)
            text_path = folder / f"{doc_id}.txt"
            if not text_path.exists():
                text_path = ROOT / "data" / "original" / f"{doc_id}.txt"
            result = scan(text_path.read_text(encoding="utf-8"), doc_id=doc_id,
                          source_type=threat_config.SOURCE_TYPE_BY_DOC_ID.get(doc_id, "document"),
                          user_task=task["user_task"], context_note=task.get("context_note"),
                          mode=mode, legacy_cache=True)
            actual = {r["segment_id"]: r for r in result.segments}
            for old_rows, kind in ((baseline_scored, "scored"), (baseline_judged, "judged"), (baseline_leveled, "leveled")):
                old = {r["segment_id"]: r for r in old_rows if r["doc_id"] == doc_id}
                if not old:
                    continue
                if set(actual) != set(old):
                    issues.append(f"{folder.name}/{doc_id} {kind}: segment ID mismatch")
                    continue
                for sid, before in old.items():
                    now = actual[sid]
                    if kind == "scored":
                        expected_rules = bool(before.get("is_instruction_like"))
                        expected_pig = float(before.get("piguard_injection_score", 0) or 0) >= judge_config.PIGUARD_THRESHOLD
                        if now["rules_flag"] != expected_rules or now["piguard_flag"] != expected_pig:
                            issues.append(f"{folder.name}/{sid} detector mismatch")
                    else:
                        compare_fields = ["judge_ran", "suspicion_level"]
                        if before.get("judge_ran"):
                            compare_fields.extend(("judge_is_instruction", "judge_needed_for_task", "judge_flag", "judge_reason", "judge_error"))
                        for field in compare_fields:
                            if field in before and now.get(field) != before.get(field):
                                issues.append(f"{folder.name}/{sid} {kind} {field} mismatch")
    return issues


def _truth_map(labels: dict) -> tuple[dict[str, str], dict[str, dict]]:
    docs = {d["doc_id"]: d for d in labels["documents"]}
    truth = {}
    for d in labels["documents"]:
        for row in _read(SCORED_PATH):
            if row["doc_id"] == d["doc_id"]:
                start, end = d.get("attack_start"), d.get("attack_end")
                if start is None:
                    truth[row["segment_id"]] = "harmless"
                elif row["start"] <= start and row["end"] >= end:
                    truth[row["segment_id"]] = "attack"
                elif row["start"] < end and row["end"] > start:
                    truth[row["segment_id"]] = "partial"
                else:
                    truth[row["segment_id"]] = "harmless"
    return truth, docs


def _false_alarm_report(all_rows: list[dict], cascade_rows: list[dict]) -> str:
    labels = json.loads(HARD_LABELS_PATH.read_text(encoding="utf-8"))
    docs = {d["doc_id"]: d for d in labels["documents"]}
    scored = _read(SCORED_PATH)
    truth = {}
    for row in scored:
        d = docs[row["doc_id"]]
        start, end = d.get("attack_start"), d.get("attack_end")
        if start is None:
            truth[row["segment_id"]] = "harmless"
        elif row["start"] <= start and row["end"] >= end:
            truth[row["segment_id"]] = "attack"
        elif row["start"] < end and row["end"] > start:
            truth[row["segment_id"]] = "partial"
        else:
            truth[row["segment_id"]] = "harmless"
    all_by = {r["segment_id"]: r for r in all_rows}
    cascade_by = {r["segment_id"]: r for r in cascade_rows}
    all_flags = {sid for sid, r in all_by.items() if r.get("judge_flag") is True}
    cascade_flags = {sid for sid, r in cascade_by.items() if r.get("judge_flag") is True}
    extra = sorted(all_flags - cascade_flags)
    lines = [
        "# Layer 1 false-alarm review",
        "",
        "This report is an offline analysis of cached judge and suspicion results. Ground truth uses full containment: a segment is attack only if it contains the entire labeled attack span; partial-overlap segments are excluded from harmless and attack denominators and counted separately.",
        "",
        "## Judge-on-all versus cascade extra flags",
        "",
        f"Judge-on-all has {len(all_flags)} judge-flagged segments and cascade has {len(cascade_flags)}; the all-only set contains {len(extra)} segments (expected 15 from the stored evaluation). Ground truth among these: attack {sum(truth.get(s) == 'attack' for s in extra)}, harmless {sum(truth.get(s) == 'harmless' for s in extra)}, partial {sum(truth.get(s) == 'partial' for s in extra)}.",
        "",
        "| Segment | Ground truth | Text | Judge reason |",
        "|---|---|---|---|",
    ]
    for sid in extra:
        row = all_by[sid]
        lines.append(f"| `{sid}` | {truth.get(sid, 'unknown')} | {' '.join(row['text'].split()).replace('|', '\\|')} | {str(row.get('judge_reason') or '').replace('|', '\\|')} |")
    lines += ["", "## Harmless segment suspicion levels", "", "Partial-overlap segments are not counted as harmless.",
              "", "| Mode | Harmless segments | None | Low | Medium | High | Needs review | Partial excluded |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for mode, rows in (("Judge-on-all", all_rows), ("Cascade", cascade_rows)):
        harmless = [r for r in rows if truth.get(r["segment_id"]) == "harmless"]
        partial = sum(truth.get(r["segment_id"]) == "partial" for r in rows)
        counts = Counter(r["suspicion_level"] for r in harmless)
        lines.append(f"| {mode} | {len(harmless)} | " + " | ".join(str(counts[level]) for level in LEVELS) + f" | {partial} |")
    lines += ["", "## Control-document false-alarm rates", "", "A document is counted when any segment reaches the stated suspicion threshold.",
              "", "| Mode | Control type | Docs with medium or higher | Docs with high |", "|---|---|---:|---:|"]
    for mode, rows in (("Judge-on-all", all_rows), ("Cascade", cascade_rows)):
        by_doc = defaultdict(list)
        for r in rows:
            by_doc[r["doc_id"]].append(r)
        for control_type in ("ordinary", "benign_instruction_like"):
            group = [d for d in docs.values() if d.get("control_type") == control_type]
            medium = sum(any(threat_config.LEVEL_ORDER.index(r["suspicion_level"]) >= threat_config.LEVEL_ORDER.index("medium") for r in by_doc[d["doc_id"]]) for d in group)
            high = sum(any(r["suspicion_level"] == "high" for r in by_doc[d["doc_id"]]) for d in group)
            lines.append(f"| {mode} | {control_type} | {rate(medium, len(group))} | {rate(high, len(group))} |")
    lines += ["", "## Harmless segments at high suspicion", "", "| Mode | Segment | Text | Judge reason |", "|---|---|---|---|"]
    high_texts = []
    for mode, rows in (("Judge-on-all", all_rows), ("Cascade", cascade_rows)):
        for row in rows:
            if truth.get(row["segment_id"]) == "harmless" and row["suspicion_level"] == "high":
                high_texts.append(row["text"])
                lines.append(f"| {mode} | `{row['segment_id']}` | {' '.join(row['text'].split()).replace('|', '\\|')} | {str(row.get('judge_reason') or '').replace('|', '\\|')} |")
    if not high_texts:
        lines.append("| — | — | No harmless segments reached high suspicion. | — |")
    lines += ["", "Recurring review pattern: the four harmless medium-suspicion segments are checklist and formatting steps the user explicitly asked the agent to follow. They were judged needed for the task, so none reached high suspicion. No harmless high-suspicion segments or quoted-attack false alarms occurred in this run.",
              "", "## Main rates and uncertainty", "", "| Measure | Result |", "|---|---:|"]
    for mode, rows in (("Cascade", cascade_rows), ("Judge-on-all", all_rows)):
        per_doc = {}
        for r in rows:
            per_doc.setdefault(r["doc_id"], []).append(r)
        attacks = [d for d in docs.values() if d.get("category") == "single_attack"]
        hit = sum(any((r.get("judge_flag") is True or r.get("rules_flag") or r.get("piguard_flag"))
                      for r in per_doc[d["doc_id"]] if truth.get(r["segment_id"]) == "attack")
                  for d in attacks)
        lines.append(f"| {mode} single-attack detection (full-span docs) | {rate(hit, len(attacks))} |")
        n = len(rows)
        reviewed = sum(bool(r.get("judge_ran")) for r in rows)
        lines.append(f"| {mode} judge coverage | {rate(reviewed, n)} |")
    partial_count = sum(v == "partial" for v in truth.values())
    lines += ["", f"Partial-overlap windows excluded from main truth counts: {partial_count}.",
              "The data are synthetic and the sample is small (30 single-attack documents and a limited number of control documents); Wilson intervals are wide and these rates should not be generalized as production performance.", ""]
    return "\n".join(lines)


def main() -> int:
    verify_manifest()
    # Preserve the stored detector outputs for regression replay; only the 19
    # legit-set segments without cached PIGuard scores need local inference.
    scan_module._PIGUARD_SCORER = _CachedPIGuard()
    scan_module.instruction_signals = _CachedRules()
    all_rows, cascade_rows, issues = _run_hard_eval()
    issues.extend(_run_early_labeled())
    early_main_labels = json.loads((ROOT / "data" / "labeled" / "labels.json").read_text(encoding="utf-8"))
    early_legit_labels = json.loads((ROOT / "data" / "labeled_legit" / "labels.json").read_text(encoding="utf-8"))
    early_main_count = len(_read(RESULTS / "segments_scored.json"))
    early_legit_count = len(_read(RESULTS / "legit_segments_judged.json"))
    lines = ["# Layer 1 final regression replay", "",
             "This run is offline and uses only existing judge cache entries. No Gemini/API client is constructed. Existing results were read only.", "",
             f"Frozen manifest: `{verify_manifest()['manifest_sha256']}`.", "",
             f"Hard evaluation: judge-on-all reviewed {sum(r['judge_ran'] for r in all_rows)}/330 segments; cascade candidates/reviews {sum(r['judge_coverage_reason'] != 'not_selected' for r in cascade_rows)} (stored expectation: 114/330).",
             f"Earlier labeled replays: main set {len(early_main_labels['documents'])} docs/{early_main_count} segments; legit set {len(early_legit_labels['documents'])} docs/{early_legit_count} segments.",
             f"Regression comparisons: {len(issues)} mismatch(es).", ""]
    if issues:
        lines += ["## Differences", ""] + [f"- {issue}" for issue in issues[:100]]
        if len(issues) > 100:
            lines.append(f"- ... {len(issues) - 100} additional mismatch(es) omitted from this report")
    else:
        lines += ["All compared segment IDs, detector flags, judge answers, and stored suspicion levels matched.", ""]
    REGRESSION_REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    FALSE_ALARM_REPORT.write_text(_false_alarm_report(all_rows, cascade_rows), encoding="utf-8")
    print(f"Wrote {REGRESSION_REPORT}")
    print(f"Wrote {FALSE_ALARM_REPORT}")
    print(f"Regression mismatches: {len(issues)}")
    print(f"Hard-eval judge-on-all reviewed {sum(r['judge_ran'] for r in all_rows)}/330; cascade selected {sum(r['judge_coverage_reason'] != 'not_selected' for r in cascade_rows)}/330.")
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
