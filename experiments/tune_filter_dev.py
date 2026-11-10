"""Tune rule/filter candidates on v1 dev labels and cached judge answers only."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.filter_v2_config import (
    PIGUARD_THRESHOLD_SWEEP, RULES_VERSION, TARGET_FILTER_RECALL,
    TARGET_MAX_JUDGE_FRACTION,
)
from config.judge_config import PIGUARD_THRESHOLD
from experiments.filter_v2_common import V2_RESULTS, load_heldout
from experiments.filter_v2_metrics import evaluate_filter
from layers.instruction_rules import instruction_signals as v1_signals
from layers.instruction_rules_v2 import instruction_signals_v2

DEV_DIR = ROOT / "data" / "hard_eval"
SCORED = V2_RESULTS / "hard_eval_segments_scored.json"
JUDGED = V2_RESULTS / "hard_eval_segments_judged_all.json"
METRICS_PATH = V2_RESULTS / "filter_v2_dev_metrics.json"
CHART = V2_RESULTS / "filter_v2_cost_recall.png"
CHOICE_MD = V2_RESULTS / "filter_v2_choice.md"
CHOICE_JSON = ROOT / "config" / "filter_v2_choice.json"
MANIFEST_V2 = ROOT / "config" / "frozen_manifest_v2.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_dev():
    # Also verify the Phase-0 held-out artifact remains intact.
    load_heldout()
    labels = json.loads((DEV_DIR / "labels.json").read_text(encoding="utf-8"))
    records = json.loads(SCORED.read_text(encoding="utf-8"))
    judged = json.loads(JUDGED.read_text(encoding="utf-8"))
    if len(records) != len(judged) or len({r["segment_id"] for r in records}) != len(records):
        raise RuntimeError("Dev scored/judged segment sets do not match")
    jmap = {r["segment_id"]: r for r in judged}
    for row in records:
        answer = jmap.get(row["segment_id"])
        if answer is None or not answer.get("judge_ran") or answer.get("judge_error"):
            raise RuntimeError(f"Missing or failed cached judge answer for {row['segment_id']}")
    return labels, records, jmap


def _add_rule_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in records:
        text = row["text"]
        out.append({
            **row,
            "_rule_v1": bool(v1_signals(text)),
            "_rule_v2_broad": bool(instruction_signals_v2(text, "BROAD")),
            "_rule_v2_cooccur": bool(instruction_signals_v2(text, "COOCCUR")),
            "_v2_broad_reasons": instruction_signals_v2(text, "BROAD"),
            "_v2_cooccur_reasons": instruction_signals_v2(text, "COOCCUR"),
        })
    return out


def _candidates(records: list[dict[str, Any]], judge: dict[str, Any]):
    cfgs: dict[str, dict[str, Any]] = {}

    def add(name: str, rule_field: str, threshold: float) -> None:
        rule = lambda r, field=rule_field: bool(r[field])
        pig = lambda r, t=threshold: float(r.get("piguard_injection_score", 0.0)) >= t
        choose = lambda r, rf=rule, pf=pig: rf(r) or pf(r)
        metrics = evaluate_filter(records, labels, choose, judge_by_id=judge,
                                  rule_hit=rule, piguard_hit=pig)
        cfgs[name] = {
            "rule_field": rule_field,
            "piguard_threshold": threshold,
            "semantic": False,
            "selection": choose,
            "metrics": metrics,
        }

    add("baseline_v1_piguard_0.50", "_rule_v1", PIGUARD_THRESHOLD)
    add("v2_broad_piguard_0.50", "_rule_v2_broad", PIGUARD_THRESHOLD)
    add("v2_cooccur_piguard_0.50", "_rule_v2_cooccur", PIGUARD_THRESHOLD)
    for threshold in PIGUARD_THRESHOLD_SWEEP:
        if threshold >= PIGUARD_THRESHOLD:
            continue
        add(f"v1_piguard_{threshold:.2f}", "_rule_v1", threshold)
    return cfgs


def _render_choice(chosen_name: str, cfgs: dict[str, Any], met: dict[str, Any], target_met: bool, semantic_note: str) -> str:
    m = met["metrics"]
    target_line = "Met both pre-registered targets." if target_met else "No dev configuration met both pre-registered targets; this is the best-recall option within the 50% judge-volume budget." 
    category_lines = [
        f"| {cat} | {v['filter']['k']}/{v['filter']['n']} ({v['filter']['rate']:.3f}) | {v['final']['k']}/{v['final']['n']} ({v['final']['rate']:.3f}) |"
        for cat, v in sorted(m["per_category"].items())
    ]
    return "\n".join([
        "# Rules v2 configuration choice (DEV only)", "",
        f"Chosen configuration: `{chosen_name}`.", "", target_line, "",
        f"- Pre-registered filter-recall target: {TARGET_FILTER_RECALL:.0%} per attack.",
        f"- Pre-registered maximum judge fraction: {TARGET_MAX_JUDGE_FRACTION:.0%} of segments.",
        f"- Filter recall: {m['filter_attack_recall']['k']}/{m['filter_attack_recall']['n']} ({m['filter_attack_recall']['rate']:.3f}), Wilson 95% CI [{m['filter_attack_recall']['wilson95'][0]:.3f}, {m['filter_attack_recall']['wilson95'][1]:.3f}].",
        f"- Cached end-to-end recall: {m['final_attack_recall']['k']}/{m['final_attack_recall']['n']} ({m['final_attack_recall']['rate']:.3f}), Wilson 95% CI [{m['final_attack_recall']['wilson95'][0]:.3f}, {m['final_attack_recall']['wilson95'][1]:.3f}].",
        f"- Selected for judge: {m['selected_segments']}/{m['segments_total']} ({m['selected_fraction']:.3f}).",
        f"- Final false-flag rate on harmless segments: {m['final_false_flags_harmless']}/{m['harmless_segments']} ({m['final_false_flag_rate_harmless']:.3f}).",
        "", "## Per-category dev results", "",
        "| Category | Filter recall | Cached end-to-end recall |", "|---|---:|---:|",
        *category_lines, "", f"Semantic filter: {semantic_note}", "",
        "Only v1 dev labels and cached judge-on-all answers were used for this choice. The held-out v2 set was not read for tuning. No API calls were made.",
        "After this configuration is frozen, do not change rules v2 or its thresholds.", "",
    ])


def main() -> int:
    global labels
    labels, records, judge = _read_dev()
    records = _add_rule_rows(records)
    cfgs = _candidates(records, judge)
    candidates = []
    for name, item in cfgs.items():
        m = item["metrics"]
        candidates.append({
            "name": name,
            "rule_field": item["rule_field"],
            "piguard_threshold": item["piguard_threshold"],
            "semantic": False,
            "metrics": m,
        })
    eligible = [c for c in candidates
                if c["metrics"]["filter_attack_recall"]["rate"] >= TARGET_FILTER_RECALL
                and c["metrics"]["selected_fraction"] <= TARGET_MAX_JUDGE_FRACTION]
    if eligible:
        chosen = min(eligible, key=lambda c: (c["metrics"]["selected_fraction"],
                                              -c["metrics"]["final_attack_recall"]["rate"], c["name"]))
        target_met = True
        choice_method = "cheapest candidate meeting both pre-registered targets"
    else:
        budgeted = [c for c in candidates if c["metrics"]["selected_fraction"] <= TARGET_MAX_JUDGE_FRACTION]
        pool = budgeted or candidates
        chosen = min(pool, key=lambda c: (-c["metrics"]["filter_attack_recall"]["rate"],
                                          c["metrics"]["selected_fraction"],
                                          -c["metrics"]["final_attack_recall"]["rate"], c["name"]))
        target_met = False
        choice_method = "best filter recall within judge-volume budget; none met both targets"

    sem_installed = importlib.util.find_spec("sentence_transformers") is not None
    semantic_note = "skipped: sentence-transformers is not installed and no local sentence-transformers model was found; no network install was attempted."
    summary = {
        "evaluated_on": "dev, tuned on this set",
        "cached_judge_answers_only": True,
        "network_calls": 0,
        "rules_version_default": RULES_VERSION,
        "semantic_filter": {"used": False, "sentence_transformers_installed": sem_installed,
                            "note": semantic_note},
        "targets": {"filter_recall": TARGET_FILTER_RECALL, "max_judge_fraction": TARGET_MAX_JUDGE_FRACTION},
        "choice": {"name": chosen["name"], "rule_field": chosen["rule_field"],
                   "piguard_threshold": chosen["piguard_threshold"], "semantic": False,
                   "target_met": target_met, "method": choice_method},
        "candidates": candidates,
        "judge_on_all_reference": {
            "fraction_selected": 1.0,
            "judge_only_recall": evaluate_filter(records, labels, lambda r: True,
                                                   judge_by_id=judge,
                                                   rule_hit=lambda r: False,
                                                   piguard_hit=lambda r: False)["final_attack_recall"],
        },
    }
    V2_RESULTS.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    CHOICE_MD.write_text(_render_choice(chosen["name"], cfgs, chosen, target_met, semantic_note), encoding="utf-8")
    choice_payload = {
        "name": chosen["name"],
        "rule_field": chosen["rule_field"],
        "rule_variant": "BROAD" if chosen["rule_field"] == "_rule_v2_broad" else (
            "COOCCUR" if chosen["rule_field"] == "_rule_v2_cooccur" else "v1"
        ),
        "piguard_threshold": chosen["piguard_threshold"],
        "semantic": False,
        "target_met": target_met,
        "method": choice_method,
    }
    CHOICE_JSON.write_text(json.dumps(choice_payload, indent=2) + "\n", encoding="utf-8")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(10, 6))
    for c in candidates:
        m = c["metrics"]
        x = m["selected_fraction"]
        y = m["final_attack_recall"]["rate"]
        label = c["name"]
        ax.scatter([x], [y], s=58, label=label)
        ax.annotate(label, (x, y), xytext=(4, 4), textcoords="offset points", fontsize=7)
    jref = summary["judge_on_all_reference"]["judge_only_recall"]["rate"]
    ax.scatter([1.0], [jref], marker="*", s=180, color="black", label="judge-on-all (judge only)")
    ax.annotate("judge-on-all (judge only)", (1.0, jref), xytext=(-150, 8), textcoords="offset points", fontsize=8)
    ax.set(xlabel="Fraction of segments selected for the judge", ylabel="Per-attack final recall",
           title="Rules v2 dev cost-recall (cached judge answers)", xlim=(-0.03, 1.05), ylim=(-0.03, 1.05))
    ax.grid(True, alpha=0.25)
    fig.tight_layout()
    fig.savefig(CHART, dpi=160)
    plt.close(fig)

    # Freeze rule and selection artifacts after the dev-only choice.
    components = {
        "instruction_rules_v2_sha256": _sha(ROOT / "layers" / "instruction_rules_v2.py"),
        "filter_v2_config_sha256": _sha(ROOT / "config" / "filter_v2_config.py"),
        "rules_router_sha256": _sha(ROOT / "layers" / "instruction_rule_router.py"),
        "choice_config_sha256": _sha(CHOICE_JSON),
        "semantic_filter": {"used": False, "code_sha256": None, "prototypes_sha256": None},
        "choice": choice_payload,
    }
    digest = hashlib.sha256(json.dumps(components, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    MANIFEST_V2.write_text(json.dumps({
        "format_version": 1,
        "created_for": "rules v2 dev-tuned filter",
        "created_at": __import__("datetime").datetime.now().astimezone().isoformat(),
        "components": components,
        "manifest_sha256": digest,
        "do_not_change_filter_after_freeze": True,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Chosen {chosen['name']}; filter recall {chosen['metrics']['filter_attack_recall']['k']}/30; selected {chosen['metrics']['selected_segments']}/{chosen['metrics']['segments_total']}.")
    print(f"Wrote {METRICS_PATH}, {CHOICE_MD}, {CHART}, and {MANIFEST_V2}; no API calls made.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
