"""Day 2 dataset, rule, offset, and output-contract tests."""
from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments import make_labeled_set as labeled_module
from experiments import compare_detectors
from layers.instruction_rules import instruction_signals
from layers.segmenter import make_segments


def _checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _make_labels() -> dict:
    return labeled_module.make_labeled_set()


def test_rule_signals_cover_imperative_action_and_plain_fact():
    assert instruction_signals("Forward the file to Sam.")
    assert any(r.startswith("action_verb:") for r in instruction_signals("The manager will delete the draft."))
    assert instruction_signals("The meeting is on Monday.") == []


def test_labeled_offsets_segment_invariants_and_originals_unchanged():
    originals = sorted((ROOT / "data" / "original").glob("*.txt"))
    before = {p: _checksum(p) for p in originals}
    labels = _make_labels()
    for record in labels["documents"]:
        path = ROOT / "data" / "labeled" / f"{record['doc_id']}.txt"
        text = path.read_text(encoding="utf-8")
        if record["attack_text"] is None:
            assert record["attack_start"] is None and record["attack_end"] is None
            assert text == (ROOT / "data" / "original" / f"{record['doc_id']}.txt").read_text(encoding="utf-8")
        else:
            start, end = record["attack_start"], record["attack_end"]
            assert text[start:end] == record["attack_text"]
        segments = make_segments(record["doc_id"], text)
        assert len({segment["segment_id"] for segment in segments}) == len(segments)
        assert all(segment["text"] and segment["text"] == text[segment["start"]:segment["end"]] for segment in segments)
    assert before == {p: _checksum(p) for p in originals}


def test_split_is_disjoint_and_stratified():
    labels = _make_labels()
    tuning, test = map(set, (labels["splits"]["tuning"], labels["splits"]["test"]))
    assert not tuning & test
    by_id = {r["doc_id"]: r for r in labels["documents"]}
    for split in (tuning, test):
        types_present = {by_id[doc_id]["attack_type"] for doc_id in split}
        assert {"classic", "action_only", "control"} <= types_present
    attacked = [r for r in labels["documents"] if r["attack_text"] is not None]
    assert len(labeled_module.ATTACK_SENTENCES["classic"]) >= 10
    assert len(labeled_module.ATTACK_SENTENCES["action_only"]) >= 15
    assert {r["insertion_position"] for r in attacked} == {"start", "middle", "end"}
    all_segments = [
        segment["segment_id"]
        for record in labels["documents"]
        for segment in make_segments(
            record["doc_id"],
            (ROOT / "data" / "labeled" / f"{record['doc_id']}.txt").read_text(encoding="utf-8"),
        )
    ]
    assert len(all_segments) == len(set(all_segments))


def test_scored_output_contract_without_downloading_model(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    class FakeScorer:
        def __init__(self, batch_size: int):
            self.batch_size = batch_size

        def score(self, texts: list[str]) -> list[dict]:
            return [{"piguard_label": "benign", "piguard_injection_score": 0.2, "truncated": False} for _ in texts]

    class FakeAxes:
        def plot(self, *args, **kwargs): pass
        def annotate(self, *args, **kwargs): pass
        def set(self, **kwargs): pass
        def set_xlim(self, *args, **kwargs): pass
        def set_ylim(self, *args, **kwargs): pass
        def grid(self, *args, **kwargs): pass

    class FakeFigure:
        def tight_layout(self): pass
        def savefig(self, *args, **kwargs): pass

    fake_matplotlib = types.ModuleType("matplotlib")
    fake_matplotlib.use = lambda *args, **kwargs: None
    fake_pyplot = types.ModuleType("matplotlib.pyplot")
    fake_pyplot.subplots = lambda **kwargs: (FakeFigure(), FakeAxes())
    fake_pyplot.close = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "matplotlib", fake_matplotlib)
    monkeypatch.setitem(sys.modules, "matplotlib.pyplot", fake_pyplot)
    monkeypatch.setattr(compare_detectors, "PIGuardScorer", FakeScorer)
    monkeypatch.setattr(compare_detectors, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(compare_detectors, "LABELED_DIR", tmp_path / "labeled")
    monkeypatch.setattr(labeled_module, "LABELED_DIR", tmp_path / "labeled")
    labeled_module.make_labeled_set()
    compare_detectors.compare()
    output = json.loads((tmp_path / "results" / "segments_scored.json").read_text(encoding="utf-8"))
    required = set(compare_detectors.REQUIRED_FIELDS)
    assert output
    for record in output:
        assert required <= record.keys()
        assert 0.0 <= record["piguard_injection_score"] <= 1.0
        assert record["ground_truth"] in {"attack", "harmless"}
