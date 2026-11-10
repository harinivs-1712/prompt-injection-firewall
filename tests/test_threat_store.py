"""Offline tests for full-span labels, suspicion levels, and threat provenance."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import threat_config
from experiments.evaluate_suspicion import build_reports, detector_flags
from layers.labeling import label_records, label_segment, per_attack_flags
from layers.suspicion import assess_suspicion
from layers.threat_store import ThreatStore, enrich_segments, rebuild_threat_store_from_json


@pytest.mark.parametrize("rules_flag", [False, True])
@pytest.mark.parametrize("piguard_flag", [False, True])
@pytest.mark.parametrize("judge_state", ["not_run", "ran_clear", "ran_flagged", "error"])
@pytest.mark.parametrize("table_name", ["default", "stricter", "lenient"])
def test_all_valid_suspicion_combinations(rules_flag, piguard_flag, judge_state, table_name):
    judge_ran = judge_state != "not_run"
    judge_error = judge_state == "error"
    judge_flag = {"not_run": None, "ran_clear": False, "ran_flagged": True, "error": None}[judge_state]
    expected_default = {
        "error": "needs_review",
        "ran_flagged": "high",
    }.get(judge_state)
    if expected_default is None:
        if rules_flag and piguard_flag:
            expected_default = "medium"
        elif rules_flag or piguard_flag:
            expected_default = "low"
        else:
            expected_default = "none"
    expected = expected_default
    if table_name == "stricter" and expected == "low":
        expected = "medium"
    if table_name == "lenient" and expected == "medium":
        expected = "low"
    outcome = assess_suspicion(
        rules_flag=rules_flag,
        piguard_flag=piguard_flag,
        judge_ran=judge_ran,
        judge_flag=judge_flag,
        judge_error=judge_error,
        table_name=table_name,
    )
    assert outcome["suspicion_level"] == expected
    assert isinstance(outcome["level_reasons"], list) and outcome["level_reasons"]


@pytest.mark.parametrize("table_name", ["default", "stricter", "lenient"])
def test_judge_error_always_requires_review(table_name):
    for rules_flag in (False, True):
        for piguard_flag in (False, True):
            result = assess_suspicion(
                rules_flag=rules_flag,
                piguard_flag=piguard_flag,
                judge_ran=True,
                judge_flag=None,
                judge_error=True,
                table_name=table_name,
            )
            assert result["suspicion_level"] == "needs_review"


def test_full_containment_and_boundary_overlap_labels():
    assert label_segment(10, 20, 10, 20) == "attack"
    assert label_segment(11, 20, 10, 20) == "partial"
    assert label_segment(10, 21, 10, 20) == "attack"
    assert label_segment(9, 15, 10, 20) == "partial"
    assert label_segment(20, 25, 10, 20) == "harmless"
    assert label_segment(0, 5, None, None) == "harmless"


def test_per_attack_metric_counts_one_attack_once():
    labels = {"documents": [{
        "doc_id": "d1", "split": "tuning", "attack_type": "classic",
        "attack_start": 10, "attack_end": 20, "attack_text": "bad instruction",
    }]}
    rows = [
        {"doc_id": "d1", "segment_id": "d1-a", "start": 0, "end": 25},
        {"doc_id": "d1", "segment_id": "d1-b", "start": 5, "end": 22},
    ]
    per_attack = per_attack_flags(rows, labels, lambda row: row["segment_id"] == "d1-b")
    assert len(per_attack) == 1
    assert per_attack[0]["flagged"] is True
    assert per_attack[0]["segment_ids"] == ["d1-a", "d1-b"]


def _store_record(segment_id="s1", text="Contact alice.smith@example.com about invoice 5000.50."):
    return {
        "segment_id": segment_id,
        "doc_id": "doc_02_email",
        "start": 0,
        "end": len(text),
        "text": text,
        "is_instruction_like": False,
        "piguard_injection_score": 0.1,
        "judge_ran": False,
        "judge_is_instruction": None,
        "judge_needed_for_task": None,
        "judge_reason": None,
        "judge_flag": None,
        "judge_error": False,
        "judge_model": "test",
        "judge_latency_ms": None,
    }


def test_trust_is_untrusted_for_each_external_source_type():
    assert {name: threat_config.trust_for_source(name) for name in ("document", "email", "web")} == {
        "document": "untrusted", "email": "untrusted", "web": "untrusted",
    }
    labels = json.loads(threat_config.LABELS_PATH.read_text(encoding="utf-8"))
    raw = json.loads(threat_config.JUDGED_SEGMENTS_PATH.read_text(encoding="utf-8"))[:12]
    enriched = enrich_segments(raw, labels)
    assert enriched
    assert all(row["trust"] == "untrusted" for row in enriched)


def test_threat_store_roundtrip_queries_and_fuzzy_source_match(tmp_path):
    db = tmp_path / "threat.sqlite"
    record = _store_record()
    with ThreatStore(db) as store:
        store.add_segment(record)
        stored = store.get_segment("s1")
        assert stored["text"] == record["text"]
        assert stored["trust"] == "untrusted"
        assert stored["source_type"] == "email"
        assert store.segments_for_doc("doc_02_email")[0]["segment_id"] == "s1"
        assert [row["segment_id"] for row in store.segments_overlapping("doc_02_email", 5, 20)] == ["s1"]
        assert [row["segment_id"] for row in store.find_sources("alice.smith@example.com")] == ["s1"]
        assert [row["segment_id"] for row in store.find_sources("ALICE.SMITH@EXAMPLE.COM")] == ["s1"]
        assert [row["segment_id"] for row in store.find_sources("alise.smith@example.com", min_ratio=0.85)] == ["s1"]
        assert store.find_sources("totally-unrelated-token") == []


def test_rebuild_from_json_matches_enriched_records(tmp_path):
    raw = json.loads(threat_config.JUDGED_SEGMENTS_PATH.read_text(encoding="utf-8"))
    labels = json.loads(threat_config.LABELS_PATH.read_text(encoding="utf-8"))
    one = [next(row for row in raw if row["doc_id"] == "doc_01_invoice")]
    source = tmp_path / "segments_judged.json"
    source.write_text(json.dumps(one), encoding="utf-8")
    expected = enrich_segments(one, labels)[0]
    with rebuild_threat_store_from_json(source, tmp_path / "rebuilt.sqlite") as store:
        assert store.get_segment(expected["segment_id"]) == expected


def test_enrichment_preserves_all_existing_judge_and_day2_fields():
    raw = json.loads(threat_config.JUDGED_SEGMENTS_PATH.read_text(encoding="utf-8"))
    labels = json.loads(threat_config.LABELS_PATH.read_text(encoding="utf-8"))
    source = next(row for row in raw if row["doc_id"] == "doc_04_readme")
    enriched = enrich_segments([source], labels)[0]
    assert set(source).issubset(enriched)
    assert {"trust", "suspicion_level", "level_reasons", "label_full", "split"} <= set(enriched)
    assert enriched["trust"] == "untrusted"


def test_original_documents_match_recorded_sha256():
    manifest = json.loads((ROOT / "tests" / "fixtures" / "original_sha256.json").read_text(encoding="utf-8"))
    for filename, expected_hash in manifest.items():
        actual_hash = hashlib.sha256((ROOT / "data" / "original" / filename).read_bytes()).hexdigest()
        assert actual_hash == expected_hash


def test_suspicion_report_builds_all_tables_and_partial_report():
    raw = json.loads(threat_config.JUDGED_SEGMENTS_PATH.read_text(encoding="utf-8"))
    labels = json.loads(threat_config.LABELS_PATH.read_text(encoding="utf-8"))
    label_fix, report, leveled = build_reports(raw, labels)
    assert len(leveled) == len(raw)
    assert "stricter" in report and "lenient" in report and "default" in report
    assert "doc_10_product_catalog-w3-0028" in label_fix
    assert "partial" in label_fix.lower()

