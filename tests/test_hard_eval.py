"""Offline integrity and orchestration tests for the held-out evaluation."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import judge_config
from experiments.hard_eval_common import (
    HARD_EVAL_DIR, HARD_LABELS_PATH, HARD_TASKS_PATH,
    duplicate_overlap_hits, rule_keyword_audit, validate_hard_dataset,
    verify_frozen_manifest, write_frozen_manifest,
)
from experiments.run_hard_eval import CompositeCache, _cascade_view, judge_missing
from experiments.run_judge import JudgeCache
from layers.judge import build_judge_prompt
from layers.labeling import label_segment, per_attack_flags
from layers.segmenter import make_segments


class FakeJudge:
    def __init__(self):
        self.inputs: list[tuple[str, str, str]] = []

    def judge_segment(self, user_task: str, context_note: str, segment_text: str) -> dict[str, Any]:
        self.inputs.append((user_task, context_note, segment_text))
        return {
            "judge_is_instruction": False,
            "judge_needed_for_task": False,
            "judge_reason": "Canned offline response.",
            "judge_flag": False,
            "judge_error": False,
            "judge_latency_ms": 1,
            "_api_call_count": 1,
            "_token_usage": {"prompt_tokens": 4, "candidate_tokens": 3},
            "_attempt_latencies_ms": [1],
            "_error_type": None,
        }


def test_frozen_manifest_passes_and_aborts_on_change(tmp_path, capsys):
    root = tmp_path / "repo"
    for folder in ("layers", "config"):
        (root / folder).mkdir(parents=True)
    (root / "layers" / "instruction_rules.py").write_text("RULES = 1\n", encoding="utf-8")
    (root / "layers" / "piguard_scorer.py").write_text('MODEL_NAME = "test-pi"\n', encoding="utf-8")
    (root / "layers" / "judge.py").write_text('JUDGE_SYSTEM_INSTRUCTION = "static system"\nJUDGE_USER_TEMPLATE = "static user"\n', encoding="utf-8")
    (root / "layers" / "segmenter.py").write_text(
        "def make_segments(doc_id, text, window=3, stride=1):\n    return []\n", encoding="utf-8"
    )
    (root / "config" / "judge_config.py").write_text(
        'MODEL_NAME="test-gemini"\nPROMPT_VERSION="v1"\nPIGUARD_THRESHOLD=0.5\n', encoding="utf-8"
    )
    (root / "config" / "threat_config.json").write_text('{"tables": {}}\n', encoding="utf-8")
    manifest = root / "config" / "frozen_manifest.json"
    write_frozen_manifest(path=manifest, root=root)
    assert verify_frozen_manifest(manifest_path=manifest, root=root)["changed_components"] == []
    (root / "layers" / "instruction_rules.py").write_text("RULES = 2\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="FROZEN LAYER 1 MISMATCH"):
        verify_frozen_manifest(manifest_path=manifest, root=root)
    status = verify_frozen_manifest(manifest_path=manifest, root=root, allow_changed=True)
    assert "instruction_rules" in status["changed_components"]
    assert "WARNING" in capsys.readouterr().out


def test_real_frozen_manifest_is_unchanged():
    status = verify_frozen_manifest()
    assert status["changed_components"] == []


def test_full_containment_and_per_attack_count_with_hard_data():
    labels = json.loads(HARD_LABELS_PATH.read_text(encoding="utf-8"))
    attack = next(row for row in labels["documents"] if row.get("attack_category") == "statement_style")
    text = (HARD_EVAL_DIR / f"{attack['doc_id']}.txt").read_text(encoding="utf-8")
    segments = make_segments(attack["doc_id"], text, window=3, stride=1)
    full = [row for row in segments if row["start"] <= attack["attack_start"] and row["end"] >= attack["attack_end"]]
    assert full
    assert label_segment(full[0]["start"], full[0]["end"], attack["attack_start"], attack["attack_end"]) == "attack"
    assert label_segment(attack["attack_start"] + 1, attack["attack_end"], attack["attack_start"], attack["attack_end"]) == "partial"
    duplicate_records = [
        {**full[0], "doc_id": attack["doc_id"], "flagged": False},
        {**full[0], "segment_id": full[0]["segment_id"] + "-dup", "doc_id": attack["doc_id"], "flagged": True},
    ]
    summary = per_attack_flags(duplicate_records, labels, lambda row: row["flagged"])
    selected = [item for item in summary if item["doc_id"] == attack["doc_id"]]
    assert len(selected) == 1 and selected[0]["flagged"] is True


def test_composition_offsets_tasks_placeholders_and_blind_overlap_audit():
    labels = json.loads(HARD_LABELS_PATH.read_text(encoding="utf-8"))
    tasks = json.loads(HARD_TASKS_PATH.read_text(encoding="utf-8"))
    assert validate_hard_dataset(labels, tasks) == []
    assert len(labels["documents"]) == 55
    assert sum(row["category"] == "single_attack" for row in labels["documents"]) == 30
    assert sum(row["category"] == "split_attack" for row in labels["documents"]) == 5
    assert sum(row.get("control_type") == "ordinary" for row in labels["documents"]) == 12
    assert sum(row.get("control_type") == "benign_instruction_like" for row in labels["documents"]) == 8
    per_category = {category: sum(row.get("attack_category") == category for row in labels["documents"])
                    for category in ("statement_style", "disguised_note", "authority_claim", "concealment", "unusual_verbs", "judge_targeted")}
    assert set(per_category.values()) == {5}
    assert duplicate_overlap_hits(labels, threshold=0.90) == []
    audit = rule_keyword_audit(labels)
    assert audit["total"] == 35


def test_cascade_selection_all_judge_coverage_input_is_single_segment_and_cache_reuses(tmp_path, monkeypatch, capsys):
    rows = [
        {"segment_id": "hard-a", "doc_id": "a", "start": 0, "end": 5, "text": "UNIQUE_ALPHA", "is_instruction_like": True, "piguard_injection_score": 0.0},
        {"segment_id": "hard-b", "doc_id": "b", "start": 0, "end": 5, "text": "UNIQUE_BETA", "is_instruction_like": False, "piguard_injection_score": judge_config.PIGUARD_THRESHOLD},
        {"segment_id": "hard-c", "doc_id": "c", "start": 0, "end": 5, "text": "UNIQUE_GAMMA", "is_instruction_like": False, "piguard_injection_score": 0.0},
    ]
    tasks = {key: {"user_task": f"task-{key}", "context_note": f"context-{key}"} for key in ("a", "b", "c")}
    cache = CompositeCache(tmp_path / "hard.jsonl", tmp_path / "existing.jsonl")
    judge = FakeJudge()
    judged, logical, api_calls, _ = judge_missing(rows, tasks, cache, judge)
    assert (logical, api_calls) == (3, 3)
    assert len({segment for _, _, segment in judge.inputs}) == 3
    assert len(judge.inputs) == len(rows)
    for row, (task, context, segment) in zip(rows, judge.inputs):
        system, message = build_judge_prompt(task, context, segment)
        assert task in message and context in message
        assert message.count("<<<SEGMENT") == 1 and message.count("SEGMENT>>>") == 1
        assert segment in message
        assert all(other["text"] not in message for other in rows if other["segment_id"] != row["segment_id"])
    cascade = _cascade_view(judged)
    assert [row["judge_ran"] for row in cascade] == [True, True, False]
    assert [row["segment_id"] for row in rows if row["is_instruction_like"] or row["piguard_injection_score"] >= judge_config.PIGUARD_THRESHOLD] == ["hard-a", "hard-b"]
    judged_again, logical_again, api_again, _ = judge_missing(rows, tasks, cache, judge)
    assert logical_again == api_again == 0
    assert len(judge.inputs) == 3
    assert all(row["judge_ran"] for row in judged_again)
    assert capsys.readouterr().out.count("judged:") == 3


def test_dummy_api_key_never_appears_in_hard_cache_or_outputs(tmp_path, monkeypatch):
    secret = "DUMMY_HARD_EVAL_KEY_DO_NOT_LEAK"
    monkeypatch.setenv("GEMINI_API_KEY", secret)
    row = {"segment_id": "hard-a", "doc_id": "a", "start": 0, "end": 5, "text": "UNIQUE_ALPHA", "is_instruction_like": True, "piguard_injection_score": 0.0}
    cache_path = tmp_path / "hard.jsonl"
    cache = CompositeCache(cache_path, tmp_path / "existing.jsonl")
    judge_missing([row], {"a": {"user_task": "task", "context_note": "context"}}, cache, FakeJudge())
    assert secret not in cache_path.read_text(encoding="utf-8")

