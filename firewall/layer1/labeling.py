"""Ground-truth labeling helpers for inserted attack spans."""
from __future__ import annotations

from collections import defaultdict
from typing import Any


def label_segment(start: int, end: int, attack_start: int | None, attack_end: int | None) -> str:
    """Label full containment as attack, partial overlap as partial, else harmless."""
    if attack_start is None or attack_end is None:
        return "harmless"
    if start <= attack_start and end >= attack_end:
        return "attack"
    if start < attack_end and end > attack_start:
        return "partial"
    return "harmless"


def label_records(
    records: list[dict[str, Any]], labels: dict[str, Any],
) -> list[dict[str, Any]]:
    """Copy records and add full-containment label plus document split."""
    by_doc = {item["doc_id"]: item for item in labels["documents"]}
    output = []
    for record in records:
        doc = by_doc[record["doc_id"]]
        output.append({
            **record,
            "label_full": label_segment(
                int(record["start"]), int(record["end"]), doc.get("attack_start"), doc.get("attack_end")
            ),
            "split": doc["split"],
        })
    return output


def per_attack_flags(
    records: list[dict[str, Any]], labels: dict[str, Any], flag_fn,
) -> list[dict[str, Any]]:
    """Summarize one metric row per inserted attack, not per overlapping segment."""
    by_doc: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_doc[record["doc_id"]].append(record)
    results = []
    for doc in labels["documents"]:
        if doc.get("attack_start") is None:
            continue
        containing = [
            row for row in by_doc[doc["doc_id"]]
            if row["start"] <= doc["attack_start"] and row["end"] >= doc["attack_end"]
        ]
        results.append({
            "doc_id": doc["doc_id"],
            "split": doc["split"],
            "attack_type": doc.get("attack_type", doc.get("attack_category")),
            "attack_category": doc.get("attack_category", doc.get("attack_type")),
            "attack_text": doc["attack_text"],
            "has_full_segment": bool(containing),
            "flagged": any(flag_fn(row) for row in containing),
            "segment_ids": [row["segment_id"] for row in containing],
        })
    return results
