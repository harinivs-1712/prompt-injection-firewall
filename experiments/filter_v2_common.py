"""Offline utilities for the held-out rules-v2 experiment."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HELDOUT_DIR = ROOT / "data" / "hard_eval_v2"
HELDOUT_HASHES = ROOT / "config" / "heldout_v2_hashes.json"
V2_RESULTS = ROOT / "data" / "results"
V1_THRESHOLD = 0.5


def verify_heldout() -> dict[str, Any]:
    """Abort if the held-out set differs from the Phase 0 freeze."""
    frozen = json.loads(HELDOUT_HASHES.read_text(encoding="utf-8"))
    expected = frozen["file_hashes"]
    actual = {}
    for path in sorted(HELDOUT_DIR.rglob("*")):
        if path.is_file():
            actual[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    changed = sorted(
        name for name in set(expected) | set(actual)
        if expected.get(name) != actual.get(name)
    )
    if changed:
        raise RuntimeError("HELD-OUT V2 HASH MISMATCH: " + ", ".join(changed))
    return {"created_at": frozen["created_at"], "file_count": len(expected), "changed": []}


def load_heldout() -> tuple[dict[str, Any], dict[str, Any]]:
    verify_heldout()
    labels = json.loads((HELDOUT_DIR / "labels.json").read_text(encoding="utf-8"))
    tasks = json.loads((ROOT / "config" / "tasks.json").read_text(encoding="utf-8"))
    return labels, tasks


def get_segments(labels: dict[str, Any]) -> list[dict[str, Any]]:
    from layers.segmenter import make_segments

    segments = []
    for document in labels["documents"]:
        text = (HELDOUT_DIR / f"{document['doc_id']}.txt").read_text(encoding="utf-8")
        segments.extend(make_segments(document["doc_id"], text, window=3, stride=1))
    return segments


def segment_truth(segment: dict[str, Any], document: dict[str, Any]) -> str:
    """Full containment is attack; boundary-only overlap is reported separately."""
    start, end = document.get("attack_start"), document.get("attack_end")
    if start is None:
        return "harmless"
    if segment["start"] <= start and segment["end"] >= end:
        return "attack"
    if segment["start"] < end and segment["end"] > start:
        return "partial"
    return "harmless"


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return max(0.0, center - half), min(1.0, center + half)
