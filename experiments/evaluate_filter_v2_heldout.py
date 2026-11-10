"""One-time filter-only evaluation on held-out-v2; absolutely no judge calls."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.filter_v2_config import PIGUARD_THRESHOLD_SWEEP
from config.judge_config import PIGUARD_THRESHOLD
from experiments.filter_v2_common import V2_RESULTS, get_segments, load_heldout, segment_truth, wilson
from experiments.filter_v2_metrics import evaluate_filter
from layers.instruction_rules import instruction_signals as v1_signals
from layers.instruction_rules_v2 import instruction_signals_v2

HASH_MANIFEST = ROOT / "config" / "heldout_v2_hashes.json"
V2_MANIFEST = ROOT / "config" / "frozen_manifest_v2.json"
CHOICE = ROOT / "config" / "filter_v2_choice.json"
SCORED_HELDOUT = V2_RESULTS / "filter_v2_heldout_scored.json"
DEV_METRICS = V2_RESULTS / "filter_v2_dev_metrics.json"
OUT_JSON = V2_RESULTS / "filter_v2_heldout_metrics.json"
REPORT = V2_RESULTS / "filter_v2_report.md"
MISSES = V2_RESULTS / "filter_v2_misses.md"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_v2_manifest() -> dict[str, Any]:
    manifest = json.loads(V2_MANIFEST.read_text(encoding="utf-8"))
    comp = manifest["components"]
    checks = {
        "instruction_rules_v2_sha256": _sha(ROOT / "layers" / "instruction_rules_v2.py"),
        "filter_v2_config_sha256": _sha(ROOT / "config" / "filter_v2_config.py"),
        "rules_router_sha256": _sha(ROOT / "layers" / "instruction_rule_router.py"),
        "choice_config_sha256": _sha(CHOICE),
    }
    changed = [k for k, v in checks.items() if comp.get(k) != v]
    digest = hashlib.sha256(json.dumps(comp, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    if changed or digest != manifest.get("manifest_sha256"):
        raise RuntimeError("RULES V2 MANIFEST MISMATCH: " + ", ".join(changed or ["manifest digest"]))
    return manifest


def _attach_rules(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in records:
        out.append({
            **row,
            "_rule_v1": bool(v1_signals(row["text"])),
            "_rule_v2_broad": bool(instruction_signals_v2(row["text"], "BROAD")),
            "_rule_v2_cooccur": bool(instruction_signals_v2(row["text"], "COOCCUR")),
        })
    return out


def _config_specs(choice: dict[str, Any]) -> list[dict[str, Any]]:
    specs = [
        {"name": "baseline_v1_piguard_0.50", "rule_field": "_rule_v1", "threshold": PIGUARD_THRESHOLD, "selected": False},
        {"name": choice["name"], "rule_field": "_rule_v2_broad" if choice["rule_variant"] == "BROAD" else "_rule_v2_cooccur" if choice["rule_variant"] == "COOCCUR" else "_rule_v1", "threshold": choice["piguard_threshold"], "selected": True},
        {"name": "v2_cooccur_piguard_0.50", "rule_field": "_rule_v2_cooccur", "threshold": PIGUARD_THRESHOLD, "selected": False},
    ]
    for t in PIGUARD_THRESHOLD_SWEEP:
        if t < PIGUARD_THRESHOLD:
            specs.append({"name": f"v1_piguard_{t:.2f}", "rule_field": "_rule_v1", "threshold": t, "selected": False})
    unique = {}
    for spec in specs:
        unique[spec["name"]] = spec
    return list(unique.values())


def _selection_rates_by_control(records, labels, chosen):
    docs = {d["doc_id"]: d for d in labels["documents"]}
    by_doc = defaultdict(list)
    for r in records:
        by_doc[r["doc_id"]].append(r)
    output = {}
    for ctype in ("ordinary", "benign_instruction_like", "benign_approval_like"):
        group = [d for d in labels["documents"] if d.get("control_type") == ctype]
        segs = [r for d in group for r in by_doc[d["doc_id"]]]
        selected = [r for r in segs if chosen(r)]
        docs_selected = [d for d in group if any(chosen(r) for r in by_doc[d["doc_id"]])]
        output[ctype] = {
            "documents": len(group),
            "selected_documents": len(docs_selected),
            "document_selection_rate": len(docs_selected) / len(group) if group else 0.0,
            "segments": len(segs),
            "selected_segments": len(selected),
            "segment_selection_rate": len(selected) / len(segs) if segs else 0.0,
        }
    return output


def _split_results(records, labels, select):
    docs = {d["doc_id"]: d for d in labels["documents"]}
    splits = [d for d in labels["documents"] if d.get("category") == "split_attack"]
    details = []
    for d in splits:
        containing = [r for r in records if r["doc_id"] == d["doc_id"]
                      and r["start"] <= d["attack_start"] and r["end"] >= d["attack_end"]]
        details.append({
            "doc_id": d["doc_id"], "category": "split_attack", "attack_text": d["attack_text"],
            "fully_contained_segments": [r["segment_id"] for r in containing],
            "selected": any(select(r) for r in containing),
        })
    return {"k": sum(x["selected"] for x in details), "n": len(details), "details": details}


def _legacy_stats():
    """FILTER ONLY: no cached judge output is used on legacy sets."""
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("network forbidden"))
    socket.socket.connect = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("network forbidden"))

    result = {}
    labels_path = ROOT / "data" / "labeled" / "labels.json"
    scored_path = ROOT / "data" / "results" / "segments_scored.json"
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    docs = {d["doc_id"]: d for d in labels["documents"]}
    records = json.loads(scored_path.read_text(encoding="utf-8"))
    rows = _attach_rules(records)
    for name, rf, threshold in (
        ("baseline_v1", "_rule_v1", PIGUARD_THRESHOLD),
        ("chosen_v2", "_rule_v2_broad", PIGUARD_THRESHOLD),
    ):
        select = lambda r, rf=rf, t=threshold: bool(r[rf]) or float(r.get("piguard_injection_score", 0.0)) >= t
        selected_ids = {r["segment_id"] for r in rows if select(r)}
        attack_docs = [d for d in labels["documents"] if d.get("attack_text")]
        detected = []
        for d in attack_docs:
            detected.append(any(r["segment_id"] in selected_ids and r["start"] <= d["attack_start"] and r["end"] >= d["attack_end"]
                                for r in rows if r["doc_id"] == d["doc_id"]))
        harmless = [r for r in rows if not any(r["start"] < d.get("attack_end", -1) and r["end"] > d.get("attack_start", -1)
                                               for d in [docs[r["doc_id"]]] if d.get("attack_start") is not None)]
        result[f"data/labeled/{name}"] = {
            "segments": len(rows), "selected_segments": len(selected_ids),
            "selected_fraction": len(selected_ids) / len(rows) if rows else 0.0,
            "fully_contained_attack_cases_selected": sum(detected), "attack_cases": len(attack_docs),
            "selected_harmless_segments": sum(r["segment_id"] in selected_ids for r in harmless),
            "harmless_segments": len(harmless),
            "end_to_end_recall_measured": False,
        }

    legit_labels = json.loads((ROOT / "data" / "labeled_legit" / "labels.json").read_text(encoding="utf-8"))
    from layers.segmenter import make_segments
    legit = []
    for d in legit_labels["documents"]:
        text = (ROOT / "data" / "labeled_legit" / f"{d['doc_id']}.txt").read_text(encoding="utf-8")
        legit.extend(make_segments(d["doc_id"], text, window=3, stride=1))
    from layers.piguard_scorer import PIGuardScorer
    piguard = PIGuardScorer().score([r["text"] for r in legit])
    legit_rows = []
    legit_docmap = {d["doc_id"]: d for d in legit_labels["documents"]}
    for r, p in zip(legit, piguard):
        legit_rows.append({**r, "_rule_v1": bool(v1_signals(r["text"])),
                           "_rule_v2_broad": bool(instruction_signals_v2(r["text"], "BROAD")), **p})
    for name, rf in (("baseline_v1", "_rule_v1"), ("chosen_v2", "_rule_v2_broad")):
        selected = [r for r in legit_rows if r[rf] or r["piguard_injection_score"] >= PIGUARD_THRESHOLD]
        selected_ids = {r["segment_id"] for r in selected}
        attack_docs = [d for d in legit_labels["documents"] if d.get("attack_span")]
        attack_cases_selected = 0
        for d in attack_docs:
            span = d["attack_span"]
            attack_cases_selected += int(any(
                r["segment_id"] in selected_ids and r["start"] <= span["start"] and r["end"] >= span["end"]
                for r in legit_rows if r["doc_id"] == d["doc_id"]
            ))
        harmless_rows = []
        partial_rows = []
        for r in legit_rows:
            d = legit_docmap[r["doc_id"]]
            span = d.get("attack_span")
            if not span:
                harmless_rows.append(r)
            elif r["start"] <= span["start"] and r["end"] >= span["end"]:
                continue
            elif r["start"] < span["end"] and r["end"] > span["start"]:
                partial_rows.append(r)
            else:
                harmless_rows.append(r)
        # These are all filter-level counts. Never infer judge performance.
        result[f"data/labeled_legit/{name}"] = {
            "segments": len(legit_rows), "selected_segments": len(selected),
            "selected_fraction": len(selected) / len(legit_rows) if legit_rows else 0.0,
            "fully_contained_attack_cases_selected": attack_cases_selected,
            "attack_cases": len(attack_docs),
            "selected_harmless_segments": sum(r["segment_id"] in selected_ids for r in harmless_rows),
            "harmless_segments": len(harmless_rows),
            "partial_segments_excluded": len(partial_rows),
            "end_to_end_recall_measured": False,
        }
    return result


def main() -> int:
    verify_v2_manifest()
    labels, _ = load_heldout()
    records = json.loads(SCORED_HELDOUT.read_text(encoding="utf-8"))
    dev = json.loads(DEV_METRICS.read_text(encoding="utf-8"))
    choice = json.loads(CHOICE.read_text(encoding="utf-8"))
    if len(records) != 366:
        raise RuntimeError(f"Expected 366 held-out segments; got {len(records)}")
    records = _attach_rules(records)
    specs = _config_specs(choice)
    outputs = {}
    for spec in specs:
        rf, threshold = spec["rule_field"], spec["threshold"]
        rule = lambda r, rf=rf: bool(r.get(rf))
        pig = lambda r, t=threshold: float(r.get("piguard_injection_score", 0.0)) >= t
        select = lambda r, rr=rule, pp=pig: rr(r) or pp(r)
        metrics = evaluate_filter(records, labels, select, rule_hit=rule, piguard_hit=pig)
        metrics["selected_controls"] = _selection_rates_by_control(records, labels, select)
        metrics["split_attack_filter_recall"] = _split_results(records, labels, select)
        outputs[spec["name"]] = {"selected": spec["selected"], **metrics}

    chosen_name = choice["name"]
    chosen = outputs[chosen_name]
    baseline = outputs["baseline_v1_piguard_0.50"]
    legacy = _legacy_stats()
    payload = {
        "heldout_hashes_verified": True,
        "v2_manifest_sha256": json.loads(V2_MANIFEST.read_text(encoding="utf-8"))["manifest_sha256"],
        "network_calls": 0,
        "heldout_end_to_end_recall_measured": False,
        "chosen_configuration": chosen_name,
        "configs": outputs,
        "dev_vs_heldout_chosen": {
            "dev_filter_recall": dev["candidates"][[c["name"] for c in dev["candidates"]].index(chosen_name)]["metrics"]["filter_attack_recall"],
            "dev_cached_end_to_end_recall": dev["candidates"][[c["name"] for c in dev["candidates"]].index(chosen_name)]["metrics"]["final_attack_recall"],
            "dev_selected_fraction": dev["candidates"][[c["name"] for c in dev["candidates"]].index(chosen_name)]["metrics"]["selected_fraction"],
            "heldout_filter_recall": chosen["filter_attack_recall"],
            "heldout_selected_fraction": chosen["selected_fraction"],
        },
        "legacy_filter_only": legacy,
    }
    OUT_JSON.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_reports(payload, labels, records, specs)
    print(f"Evaluated {len(specs)} filter configurations on 366 held-out segments; no judge/API calls.")
    print(f"Baseline v1 filter recall {baseline['filter_attack_recall']['k']}/{baseline['filter_attack_recall']['n']}; chosen {chosen_name} {chosen['filter_attack_recall']['k']}/{chosen['filter_attack_recall']['n']}; selected {chosen['selected_segments']}/{chosen['segments_total']}.")
    print(f"Wrote {REPORT}, {MISSES}, {OUT_JSON}.")
    return 0


def _write_reports(payload, labels, records, specs):
    configs = payload["configs"]
    base_name = "baseline_v1_piguard_0.50"
    chosen_name = payload["chosen_configuration"]
    base, chosen = configs[base_name], configs[chosen_name]
    cats = sorted(chosen["per_category"])
    b_hci = wilson(base["selected_harmless_segments"], base["harmless_segments"])
    c_hci = wilson(chosen["selected_harmless_segments"], chosen["harmless_segments"])
    report = [
        "# Rules v2 held-out filter evaluation (no judge calls)", "",
        "## Side-by-side: baseline v1 filter vs chosen rules v2 filter", "",
        "| Measure | Baseline filter v1 | Chosen filter v2 |", "|---|---:|---:|",
        f"| Configuration | `{base_name}` | `{chosen_name}` |",
        f"| Single-attack filter recall | {base['filter_attack_recall']['k']}/{base['filter_attack_recall']['n']} ({base['filter_attack_recall']['rate']:.3f}); Wilson 95% CI [{base['filter_attack_recall']['wilson95'][0]:.3f}, {base['filter_attack_recall']['wilson95'][1]:.3f}] | {chosen['filter_attack_recall']['k']}/{chosen['filter_attack_recall']['n']} ({chosen['filter_attack_recall']['rate']:.3f}); Wilson 95% CI [{chosen['filter_attack_recall']['wilson95'][0]:.3f}, {chosen['filter_attack_recall']['wilson95'][1]:.3f}] |",
        f"| Segments selected for judge | {base['selected_segments']}/{base['segments_total']} ({base['selected_fraction']:.3f}) | {chosen['selected_segments']}/{chosen['segments_total']} ({chosen['selected_fraction']:.3f}) |",
        f"| Harmless segment selection (Wilson 95% CI) | {base['selected_harmless_segments']}/{base['harmless_segments']} ({base['harmless_selection_rate']:.3f}); [{b_hci[0]:.3f}, {b_hci[1]:.3f}] | {chosen['selected_harmless_segments']}/{chosen['harmless_segments']} ({chosen['harmless_selection_rate']:.3f}); [{c_hci[0]:.3f}, {c_hci[1]:.3f}] |",
        f"| Any fully-contained split attack selected | {base['split_attack_filter_recall']['k']}/{base['split_attack_filter_recall']['n']} | {chosen['split_attack_filter_recall']['k']}/{chosen['split_attack_filter_recall']['n']} |",
        "", "### Single-attack recall by category", "",
        "| Category | Baseline v1 | Chosen v2 |", "|---|---:|---:|",
    ]
    for cat in cats:
        b, c = base["per_category"][cat]["filter"], chosen["per_category"][cat]["filter"]
        report.append(f"| {cat} | {b['k']}/{b['n']} ({b['rate']:.3f}); [{b['wilson95'][0]:.3f}, {b['wilson95'][1]:.3f}] | {c['k']}/{c['n']} ({c['rate']:.3f}); [{c['wilson95'][0]:.3f}, {c['wilson95'][1]:.3f}] |")
    report += ["", "### Control selection by type (Wilson 95% intervals)", "", "| Control type | v1 segment selection | v1 docs with any selected | v2 segment selection | v2 docs with any selected |", "|---|---:|---:|---:|---:|"]
    for ctype in ("ordinary", "benign_instruction_like", "benign_approval_like"):
        b, c = base["selected_controls"][ctype], chosen["selected_controls"][ctype]
        bsc, csc = wilson(b["selected_segments"], b["segments"]), wilson(c["selected_segments"], c["segments"])
        bdc, cdc = wilson(b["selected_documents"], b["documents"]), wilson(c["selected_documents"], c["documents"])
        report.append(f"| {ctype} | {b['selected_segments']}/{b['segments']} ({b['segment_selection_rate']:.3f}); [{bsc[0]:.3f}, {bsc[1]:.3f}] | {b['selected_documents']}/{b['documents']} ({b['document_selection_rate']:.3f}); [{bdc[0]:.3f}, {bdc[1]:.3f}] | {c['selected_segments']}/{c['segments']} ({c['segment_selection_rate']:.3f}); [{csc[0]:.3f}, {csc[1]:.3f}] | {c['selected_documents']}/{c['documents']} ({c['document_selection_rate']:.3f}); [{cdc[0]:.3f}, {cdc[1]:.3f}] |")
    dev_vs = payload["dev_vs_heldout_chosen"]
    report += ["", "## Dev vs held-out for chosen configuration", "",
               f"On dev (tuned on this set), filter recall was {dev_vs['dev_filter_recall']['k']}/{dev_vs['dev_filter_recall']['n']} ({dev_vs['dev_filter_recall']['rate']:.3f}), cached end-to-end recall was {dev_vs['dev_cached_end_to_end_recall']['k']}/{dev_vs['dev_cached_end_to_end_recall']['n']} ({dev_vs['dev_cached_end_to_end_recall']['rate']:.3f}), and selected fraction was {dev_vs['dev_selected_fraction']:.3f}.",
               f"On held-out v2, filter recall was {dev_vs['heldout_filter_recall']['k']}/{dev_vs['heldout_filter_recall']['n']} ({dev_vs['heldout_filter_recall']['rate']:.3f}; Wilson 95% CI [{dev_vs['heldout_filter_recall']['wilson95'][0]:.3f}, {dev_vs['heldout_filter_recall']['wilson95'][1]:.3f}]) and selected fraction was {dev_vs['heldout_selected_fraction']:.3f}.",
               "Held-out end-to-end recall was **not measured** because no judge calls were made.",
               "", "## Other dev-tuned configurations (filter-only; not selected)", "",
               "| Configuration | Filter recall | Selected fraction | Harmless segment selection |", "|---|---:|---:|---:|"]
    for spec in specs:
        if spec["name"] in {base_name, chosen_name}:
            continue
        m = configs[spec["name"]]
        r = m["filter_attack_recall"]
        report.append(f"| {spec['name']} | {r['k']}/{r['n']} ({r['rate']:.3f}) | {m['selected_fraction']:.3f} | {m['selected_harmless_segments']}/{m['harmless_segments']} ({m['harmless_selection_rate']:.3f}) |")
    report += ["", "## Split attacks (separate; excluded from single-attack recall)", "",
               "| Configuration | Split attacks with any full window selected |", "|---|---:|"]
    for spec in specs:
        m = configs[spec["name"]]
        report.append(f"| {spec['name']} | {m['split_attack_filter_recall']['k']}/{m['split_attack_filter_recall']['n']} |")
    report += ["", "Phase 1 v1 dev diagnostic: each of the five dev split-attack spans fits completely inside one 3-sentence window; cached judge-on-all marked all five as non-instructions. The reasons are in `filter_v2_dev_analysis.md`.",
               "", "## Vocabulary leakage", "",
               "The hashed `data/hard_eval_v2/vocab_check.md` uses smoothed log-odds. Attack-associated terms include `private`, `recovery`, `phrase`, and `string`; the harmless side is led by `group`, `questions`, and `chart`. Terms such as `sample`, `placeholder`, `illustrative`, and `public` occur across both labels. This is a synthetic dataset and the vocabulary analysis is descriptive; residual lexical leakage remains possible.",
               "", "## Older labeled sets: filter-level only", "",
               "No cached judge answers were inferred for newly selected segments. These are filter selection counts only, not end-to-end recall.",
               "", "| Dataset/config | Segments selected | Fully-contained attack cases selected | Selected harmless segments |", "|---|---:|---:|---:|"]
    for key, m in payload["legacy_filter_only"].items():
        attack = f"{m['fully_contained_attack_cases_selected']}/{m['attack_cases']}" if "attack_cases" in m else "n/a"
        harmless = f"{m['selected_harmless_segments']}/{m['harmless_segments']}" if "harmless_segments" in m else "n/a"
        report.append(f"| {key} | {m['selected_segments']}/{m['segments']} ({m['selected_fraction']:.3f}) | {attack} | {harmless} |")
    report += ["", "## Limits", "",
               "The 30 single attacks (five per category) and controls are synthetic. The v2 set was written by the same agent with prior conversational knowledge of v1 misses; despite the initial pre-filter freeze, one control sentence was corrected after dev inspection when the frozen segmenter merged `Corp.`. Attack texts/labels did not change, but control-set blinding is weaker. Confidence intervals are wide. No held-out judge calls were made, so these results measure filter recall/selection only. The optional semantic filter was skipped because sentence-transformers and a local sentence model were unavailable offline.", ""]
    REPORT.write_text("\n".join(report), encoding="utf-8")

    miss = ["# Held-out v2 attacks not selected by each filter (filter-only)", ""]
    docmap = {d["doc_id"]: d for d in labels["documents"]}
    by_doc = defaultdict(list)
    for r in records:
        by_doc[r["doc_id"]].append(r)
    for spec in specs:
        cfg = configs[spec["name"]]
        rf, threshold = spec["rule_field"], spec["threshold"]
        def selected(row):
            return bool(row.get(rf)) or float(row.get("piguard_injection_score", 0.0)) >= threshold
        missed = []
        for d in labels["documents"]:
            if d.get("category") != "single_attack":
                continue
            containing = [r for r in by_doc[d["doc_id"]] if r["start"] <= d["attack_start"] and r["end"] >= d["attack_end"]]
            if not any(selected(r) for r in containing):
                missed.append(d)
        miss += [f"## {spec['name']} ({'chosen' if spec['selected'] else 'not selected'})", ""]
        if not missed:
            miss += ["No single-attack cases missed.", ""]
        else:
            for d in missed:
                miss.append(f"- **{d['doc_id']}** ({d.get('attack_category')}): {d['attack_text']}")
            miss.append("")
        split = cfg["split_attack_filter_recall"]
        miss.append(f"Split attacks selected: {split['k']}/{split['n']}.")
        for d in split["details"]:
            if not d["selected"]:
                miss.append(f"- **{d['doc_id']}** (split_attack): {d['attack_text']}")
        miss.append("")
    MISSES.write_text("\n".join(miss), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
