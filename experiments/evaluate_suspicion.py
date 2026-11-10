"""Re-label attack windows, assign suspicion, build SQLite store, and report."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import judge_config, threat_config
from layers.labeling import label_records, per_attack_flags
from layers.suspicion import apply_suspicion
from layers.threat_store import enrich_segments, rebuild_threat_store_from_json


DETECTORS: dict[str, Callable[[dict[str, Any]], bool]] = {}


def detector_flags(record: dict[str, Any]) -> dict[str, bool]:
    rules = bool(record.get("is_instruction_like"))
    piguard = float(record.get("piguard_injection_score") or 0.0) >= judge_config.PIGUARD_THRESHOLD
    judge = bool(record.get("judge_ran")) and record.get("judge_flag") is True
    judge_review = bool(record.get("judge_error"))
    return {
        "rules": rules,
        "piguard": piguard,
        "judge": judge,
        "day2_any": rules or piguard,
        "day3_any": rules or piguard or judge or judge_review,
    }


def confusion(rows: list[dict[str, Any]], flagged: list[bool]) -> dict[str, int]:
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for row, flag in zip(rows, flagged):
        if row["label_full"] == "attack" and flag:
            counts["TP"] += 1
        elif row["label_full"] == "attack":
            counts["FN"] += 1
        elif row["label_full"] == "harmless" and flag:
            counts["FP"] += 1
        elif row["label_full"] == "harmless":
            counts["TN"] += 1
    return counts


def _attack_metrics(rows: list[dict[str, Any]], labels: dict[str, Any], detector: str) -> tuple[int, int]:
    flags = per_attack_flags(rows, labels, lambda row: detector_flags(row)[detector])
    relevant = [row for row in flags if row["split"] == (rows[0]["split"] if rows else "")]
    return sum(row["flagged"] for row in relevant), len(relevant)


def _metrics(rows: list[dict[str, Any]], labels: dict[str, Any], detector: str) -> dict[str, Any]:
    eligible = [row for row in rows if row["label_full"] in {"attack", "harmless"}]
    flags = [detector_flags(row)[detector] for row in eligible]
    counts = confusion(eligible, flags)
    attacks = sum(row["label_full"] == "attack" for row in eligible)
    harmless = sum(row["label_full"] == "harmless" for row in eligible)
    per_attack, attack_count = _attack_metrics(rows, labels, detector)
    return {
        "counts": counts,
        "attack_segments": attacks,
        "harmless_segments": harmless,
        "partial_segments": sum(row["label_full"] == "partial" for row in rows),
        "recall": counts["TP"] / attacks if attacks else None,
        "false_flag_rate": counts["FP"] / harmless if harmless else None,
        "per_attack_flagged": per_attack,
        "per_attack_total": attack_count,
    }


def _old_overlap_labels(records: list[dict[str, Any]], labels: dict[str, Any]) -> list[dict[str, Any]]:
    docs = {item["doc_id"]: item for item in labels["documents"]}
    output = []
    for row in records:
        doc = docs[row["doc_id"]]
        start, end = doc.get("attack_start"), doc.get("attack_end")
        overlaps = start is not None and row["start"] < end and row["end"] > start
        output.append({**row, "label_full": "attack" if overlaps else "harmless", "split": doc["split"]})
    return output


def _fmt_rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _label_fix_report(records: list[dict[str, Any]], labels: dict[str, Any]) -> str:
    old_rows = _old_overlap_labels(records, labels)
    new_rows = label_records(records, labels)
    lines = [
        "# Ground-truth label correction: old vs full containment", "",
        "Old labels counted any overlap with an inserted span as attack. New labels count a segment as attack only when it fully contains the inserted span; partial overlaps are excluded from recall/FPR denominators. Per-attack recall counts each inserted attack once if any fully containing segment is flagged.",
        "",
        "| Split | Labeling | Detector | Attack segments | Harmless segments | Partial segments | Segment recall | False-flag rate | Per-attack flagged | TP / FP / TN / FN |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for split in ("tuning", "test"):
        for label_name, rows in (("old overlap", old_rows), ("new full", new_rows)):
            subset = [row for row in rows if row["split"] == split]
            for detector in ("rules", "piguard", "judge", "day2_any", "day3_any"):
                metric = _metrics(subset, labels, detector)
                c = metric["counts"]
                lines.append(
                    f"| {split} | {label_name} | {detector} | {metric['attack_segments']} | "
                    f"{metric['harmless_segments']} | {metric['partial_segments']} | "
                    f"{_fmt_rate(metric['recall'])} | {_fmt_rate(metric['false_flag_rate'])} | "
                    f"{metric['per_attack_flagged']}/{metric['per_attack_total']} | "
                    f"{c['TP']} / {c['FP']} / {c['TN']} / {c['FN']} |"
                )
    lines += ["", "## Partial segments excluded by the new labels", ""]
    for split in ("tuning", "test"):
        partial = [row for row in new_rows if row["split"] == split and row["label_full"] == "partial"]
        details = ", ".join(f"{row['segment_id']} ({row['doc_id']})" for row in partial) or "none"
        lines.append(f"- **{split}:** {len(partial)} partial segment(s): {details}.")
    lines += [
        "",
        "Attack-level scores count each inserted attack once. Segment-level denominators differ because sentence windows overlap. The corpus is small; counts are shown with every rate.",
    ]
    return "\n".join(lines) + "\n"


def _suspicion_rows(
    labeled_rows: list[dict[str, Any]], table_name: str,
) -> list[dict[str, Any]]:
    return [apply_suspicion(row, table_name=table_name) for row in labeled_rows]


def _per_attack_suspicion(
    rows: list[dict[str, Any]], labels: dict[str, Any], split: str, table_name: str,
) -> tuple[list[dict[str, Any]], int, int]:
    level_rank = {level: index for index, level in enumerate(threat_config.LEVEL_ORDER)}
    docs = {item["doc_id"]: item for item in labels["documents"]}
    result = []
    for doc in labels["documents"]:
        if doc["split"] != split or doc.get("attack_start") is None:
            continue
        full = [
            row for row in rows if row["doc_id"] == doc["doc_id"]
            and row["start"] <= doc["attack_start"] and row["end"] >= doc["attack_end"]
        ]
        highest = max((row["suspicion_level"] for row in full), key=level_rank.get, default="none")
        result.append({
            "doc_id": doc["doc_id"],
            "attack_text": doc["attack_text"],
            "highest": highest,
            "segments": full,
            "no_full_segment": not full,
        })
    low_or_none = sum(row["highest"] in {"none", "low"} for row in result)
    return result, low_or_none, len(result)


def _table_report(rows: list[dict[str, Any]], labels: dict[str, Any], table_name: str) -> list[str]:
    rows = _suspicion_rows(rows, table_name)
    lines = [f"## Suspicion table: {table_name}", ""]
    for split in ("tuning", "test"):
        subset = [row for row in rows if row["split"] == split]
        full = [row for row in subset if row["label_full"] in {"attack", "harmless"}]
        partial = [row for row in subset if row["label_full"] == "partial"]
        lines += [
            f"### {split.title()} confusion: suspicion level by full-containment ground truth", "",
            "| Suspicion level | Attack | Harmless | Total | Harmless level rate (k/n) |",
            "|---|---:|---:|---:|---:|",
        ]
        harmless_total = sum(row["label_full"] == "harmless" for row in full)
        for level in threat_config.LEVEL_ORDER:
            attack_count = sum(row["label_full"] == "attack" and row["suspicion_level"] == level for row in full)
            harmless_count = sum(row["label_full"] == "harmless" and row["suspicion_level"] == level for row in full)
            rate = f"{harmless_count}/{harmless_total} ({harmless_count / harmless_total:.3f})" if harmless_total else "0/0 (n/a)"
            lines.append(f"| {level} | {attack_count} | {harmless_count} | {attack_count + harmless_count} | {rate} |")
        lines += ["", f"Partial segments excluded from the table: {len(partial)}."]
        if partial:
            lines.extend(f"- `{row['segment_id']}` ({row['doc_id']}): {row['suspicion_level']} — {row['text'][:180]!r}" for row in partial)

        # Harmless documents are controls with no inserted attack span.
        docs_by_id = {item["doc_id"]: item for item in labels["documents"]}
        harmless_docs = [
            doc_id for doc_id, doc in docs_by_id.items()
            if doc["split"] == split and doc.get("attack_start") is None
        ]
        by_doc: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            if row["split"] == split:
                by_doc[row["doc_id"]].append(row)
        medium_up = sum(
            any(threat_config.LEVEL_ORDER.index(row["suspicion_level"]) >= threat_config.LEVEL_ORDER.index("medium") for row in by_doc[doc_id])
            for doc_id in harmless_docs
        )
        high_exact = sum(any(row["suspicion_level"] == "high" for row in by_doc[doc_id]) for doc_id in harmless_docs)
        review_exact = sum(any(row["suspicion_level"] == "needs_review" for row in by_doc[doc_id]) for doc_id in harmless_docs)
        lines += [
            "",
            f"Harmless documents (no inserted attack; controls included): **{medium_up}/{len(harmless_docs)}** with any segment at medium or above; **{high_exact}/{len(harmless_docs)}** with any segment exactly high; **{review_exact}/{len(harmless_docs)}** with any segment at needs_review.",
            "",
            "| Inserted attack | Highest level across fully containing segments | Fully containing segments | Attack text |",
            "|---|---|---:|---|",
        ]
        attack_views, low_or_none, attack_count = _per_attack_suspicion(rows, labels, split, table_name)
        for attack in attack_views:
            lines.append(
                f"| {attack['doc_id']} | {attack['highest']} | {len(attack['segments'])} | {attack['attack_text']} |"
            )
        lines += ["", f"Attacks ending at none or low: **{low_or_none}/{attack_count}**."]
        weak = [attack for attack in attack_views if attack["highest"] in {"none", "low"}]
        if weak:
            lines += [""]
            lines.extend(f"- **{attack['doc_id']}** (highest `{attack['highest']}`; full segments: {', '.join(r['segment_id'] for r in attack['segments']) or 'none'}): {attack['attack_text']}" for attack in weak)
        lines.append("")
    return lines


def _old_any_comparison(rows: list[dict[str, Any]], labels: dict[str, Any]) -> list[str]:
    old_rows = _old_overlap_labels(rows, labels)
    new_rows = label_records(rows, labels)
    lines = [
        "## Old any-flag comparison using old and corrected labels", "",
        "The Day 2 any-flag column is rules OR PIGuard; Day 3 any-flag adds the judge and treats judge errors as review flags.",
        "",
        "| Split | Labels | Detector | Recall (k/n) | False-flag rate (k/n) | Per-attack flagged (k/n) |",
        "|---|---|---|---:|---:|---:|",
    ]
    for split in ("tuning", "test"):
        for label_name, all_rows in (("old overlap", old_rows), ("full / partial excluded", new_rows)):
            subset = [row for row in all_rows if row["split"] == split]
            for detector in ("day2_any", "day3_any"):
                metric = _metrics(subset, labels, detector)
                c = metric["counts"]
                attack_den = metric["attack_segments"]
                harmless_den = metric["harmless_segments"]
                lines.append(
                    f"| {split} | {label_name} | {detector} | {c['TP']}/{attack_den} ({_fmt_rate(metric['recall'])}) | "
                    f"{c['FP']}/{harmless_den} ({_fmt_rate(metric['false_flag_rate'])}) | "
                    f"{metric['per_attack_flagged']}/{metric['per_attack_total']} |"
                )
    return lines


def build_reports(records: list[dict[str, Any]], labels: dict[str, Any]) -> tuple[str, str, list[dict[str, Any]]]:
    leveled = enrich_segments(records, labels)
    label_fix = _label_fix_report(records, labels)
    report = [
        "# Layer 1 suspicion and threat-store evaluation", "",
        f"Active output table: `{threat_config.ACTIVE_LEVEL_TABLE}`. All three tables are shown for comparison; table selection must be based on tuning results, not test results. Trust is independently set to `untrusted` for all external document/email/web sources.",
        "",
        "Assumption for an unspecified input combination: when rules and PIGuard both flag but the judge did not run, the default table assigns `medium` (two signals agree). Judge errors always take precedence and become `needs_review`.",
        "",
        "## Suspicion tables on tuning and test", "",
    ]
    for name in threat_config.LEVEL_TABLES:
        report.extend(_table_report(leveled, labels, name))
    report.extend(_old_any_comparison(records, labels))
    report.extend([
        "",
        "## Interpretation and limits", "",
        "Partial segments are excluded from segment confusion and false-flag denominators. Per-attack scores count each injected attack once, using fully containing segments. Harmless document rates use only documents with no injected attack; controls are included. The split contains very few harmless documents, so document-level fractions are coarse.",
        "Source matching in the threat store is best-effort exact/fuzzy text matching. It cannot restore provenance after a value has been paraphrased or transformed.",
        "Counts are small, and overlapping segments are correlated; these values are descriptive rather than general performance claims.",
        "",
    ])
    return label_fix, "\n".join(report), leveled


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate corrected labels, suspicion levels, and the threat store.")
    parser.add_argument("--table", choices=tuple(threat_config.LEVEL_TABLES), default=threat_config.ACTIVE_LEVEL_TABLE,
                        help="Table used in segments_leveled.json and the SQLite store; reports compare all tables.")
    args = parser.parse_args(argv)
    records = json.loads(threat_config.JUDGED_SEGMENTS_PATH.read_text(encoding="utf-8"))
    labels = json.loads(threat_config.LABELS_PATH.read_text(encoding="utf-8"))
    label_fix, report, _ = build_reports(records, labels)
    # Persist leveled records under selected table; reports compare all tables independently.
    leveled = enrich_segments(records, labels, table_name=args.table)
    threat_config.LEVELED_SEGMENTS_PATH.write_text(json.dumps(leveled, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    threat_config.LABELING_REPORT_PATH.write_text(label_fix, encoding="utf-8")
    threat_config.SUSPICION_REPORT_PATH.write_text(report, encoding="utf-8")
    with rebuild_threat_store_from_json(table_name=args.table) as store:
        stored_count = len(store.segments_by_level("none"))
    print(f"Leveled {len(leveled)} segment(s); rebuilt threat store with {stored_count} segment(s).")
    print(f"Wrote {threat_config.LEVELED_SEGMENTS_PATH}, {threat_config.LABELING_REPORT_PATH}, and {threat_config.SUSPICION_REPORT_PATH}")
    print(f"SQLite store: {threat_config.THREAT_STORE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
