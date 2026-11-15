from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import types
from pathlib import Path

import pytest

from firewall import Firewall, OutputResult, PolicyError, ScanOutcome, SegmentRecord, load_policy
from firewall.adapters.layer1 import Layer1Scanner, ScannerUnavailable
from firewall.policy import policy_from_mapping
from harness.scanners import FailingScanner, ScriptedScanner
from harness.runner import load_traces, run_trace
from firewall.protocols import InMemoryAuditSink

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network is blocked in Day 7 tests")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def policy(*, actions=None, oversize="truncate", chunk=20000, total=200000, depth=10, strings=500,
           budget=None, disabled=False):
    return {
        "policy_version": "1", "agent_name": "output_test",
        "tools": {"inspect": {"description": "Trusted placeholder tool description.", "risk": "low",
                                "side_effects": False, "scan_output": not disabled, "args": {}}},
        "task_categories": {"inspect": {"allowed_tools": ["inspect"], "keywords": ["inspect"]}},
        "output_inspection": {"oversize_action": oversize, "max_chars_per_chunk": chunk,
                              "max_total_chars": total, "json_max_depth": depth,
                              "json_max_strings": strings, "session_judge_budget": budget,
                              "actions": actions or {}},
    }


def call(text, *, policy_obj=None, scanner=None, task="inspect resource", **kwargs):
    fw = Firewall(policy_obj or policy(), scanner=scanner or ScriptedScanner(), **kwargs)
    session = fw.start_session(task)
    return fw, session, fw.inspect_tool_output(session, "inspect", text)


def test_import_hygiene_for_core_adapter_and_factory():
    code = ("import sys, firewall, firewall.adapters, firewall.factory; "
            "bad=[m for m in sys.modules if m=='layers' or m.startswith('layers.') or "
            "m=='torch' or m.startswith('torch.') or m=='transformers' or m.startswith('transformers.') or "
            "m=='google' or m.startswith('google.')]; assert not bad, bad")
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_layer1_adapter_maps_real_signature_lazily(monkeypatch):
    package = types.ModuleType("layers")
    package.__path__ = []
    fake = types.ModuleType("layers.scan")
    seen = {}
    def scan(content, **kwargs):
        seen.update(content=content, **kwargs)
        row = {"segment_id": "s1", "doc_id": kwargs["doc_id"], "source_type": kwargs["source_type"],
               "start": 0, "end": len(content), "text": content, "suspicion_level": "medium",
               "judge_ran": True, "judge_coverage_reason": "reviewed", "rules_flag": True, "piguard_flag": False}
        return types.SimpleNamespace(segments=[row], summary={"judge_calls_made": 2, "coverage_fraction": 1.0})
    fake.scan = scan
    monkeypatch.setitem(sys.modules, "layers", package)
    monkeypatch.setitem(sys.modules, "layers.scan", fake)
    adapter = Layer1Scanner(mode="cascade", offline_cache_only=True, legacy_cache=True)
    result = adapter.scan("safe placeholder", doc_id="doc", source_type="tool_output",
                          user_task="trusted task", context_note="trusted note", max_judge_calls=3)
    assert result.segments[0].suspicion_level == "medium"
    assert result.judge_calls_made == 2 and result.coverage_fraction == 1.0
    assert seen["mode"] == "cascade" and seen["legacy_cache"] is True
    assert seen["judge"] is None and seen["max_judge_calls"] == 3
    assert "offline_cache_only" not in seen  # the frozen scan() signature has no such parameter


def test_layer1_adapter_sanitizes_failure_and_requires_explicit_live_key(monkeypatch):
    package = types.ModuleType("layers")
    package.__path__ = []
    fake = types.ModuleType("layers.scan")
    def fail(*args, **kwargs):
        raise RuntimeError("secret output must not leak")
    fake.scan = fail
    monkeypatch.setitem(sys.modules, "layers", package)
    monkeypatch.setitem(sys.modules, "layers.scan", fake)
    adapter = Layer1Scanner()
    with pytest.raises(ScannerUnavailable) as exc:
        adapter.scan("secret output must not leak", doc_id="d", source_type="tool_output", user_task="task")
    assert "secret output" not in str(exc.value)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ScannerUnavailable, match="GEMINI_API_KEY"):
        Layer1Scanner(offline_cache_only=False).scan("x", doc_id="d", source_type="tool_output", user_task="task")


def test_layer1_adapter_live_uses_injected_judge_without_network(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "placeholder-key")
    package = types.ModuleType("layers")
    package.__path__ = []
    fake = types.ModuleType("layers.scan")
    seen = {}
    def scan(content, **kwargs):
        seen.update(kwargs)
        return types.SimpleNamespace(segments=[], summary={"judge_calls_made": 0, "coverage_fraction": 1.0})
    fake.scan = scan
    monkeypatch.setitem(sys.modules, "layers", package)
    monkeypatch.setitem(sys.modules, "layers.scan", fake)
    marker = object()
    Layer1Scanner(offline_cache_only=False, judge=marker).scan("x", doc_id="d", source_type="tool_output", user_task="task")
    assert seen["judge"] is marker


@pytest.mark.parametrize("level", ["none", "low", "medium"])
def test_safe_levels_pass_byte_identically_and_store_taint(level):
    class MarkScanner(ScriptedScanner):
        def scan(self, content, **kwargs):
            result = super().scan(content, **kwargs)
            record = result.segments[0]
            return ScanOutcome((SegmentRecord(record.segment_id, record.doc_id, record.source_type,
                                               record.start, record.end, record.text, level, True, "reviewed"),), 0, 1.0)
    text = "Exact unchanged output."
    fw = Firewall(policy(), scanner=MarkScanner())
    session = fw.start_session("inspect")
    result = fw.inspect_tool_output(session, "inspect", text)
    assert result.action == "PASS" and result.agent_view == text
    assert result.agent_view.encode() == text.encode()
    assert session.level_counts[level] == 1


def test_high_hold_hides_original_and_reviewer_gate():
    secret = "secret-secret-123"
    fw, session, result = call(f"Visible. [[HIGH]]{secret}.")
    assert result.action == "HOLD"
    assert result.agent_view == fw.policy.output_inspection.hold_placeholder
    assert secret not in str(result.agent_view)
    with pytest.raises(PermissionError):
        fw.get_original_output(session, result.output_id)
    assert fw.get_original_output(session, result.output_id, reviewer=True) == f"Visible. [[HIGH]]{secret}."


def test_high_mask_merges_overlaps_and_preserves_unicode_and_original():
    text = "雪 stays. [[HIGH]]hide this. Tail Ω."
    class OverlapScanner:
        def scan(self, content, *, doc_id, source_type, user_task, context_note=None, max_judge_calls=None):
            start = content.index("[[HIGH]]")
            end = content.index(".", start) + 1
            rows = (SegmentRecord("h1", doc_id, source_type, start, end, content[start:end], "high", True),
                    SegmentRecord("h2", doc_id, source_type, start + 2, end, content[start + 2:end], "high", True))
            return ScanOutcome(rows, 0, 1.0)
    fw, session, result = call(text, policy_obj=policy(actions={"high": "mask"}), scanner=OverlapScanner())
    assert result.action == "MASK"
    assert result.agent_view == "雪 stays. [removed: suspicious content] Tail Ω."
    assert fw.get_original_output(session, result.output_id, reviewer=True) == text
    assert session.segments[0]["record"].start == text.index("[[HIGH]]")
    assert session.segments[0]["record"].end == text.index(".", text.index("[[HIGH]]")) + 1


def test_high_covering_whole_output_masks_entire_string():
    _, _, result = call("[[HIGH]]Entire output.", policy_obj=policy(actions={"high": "mask"}))
    assert result.agent_view == "[removed: suspicious content]"


def test_unreviewed_pass_marked_and_configurable_hold():
    _, _, passed = call("[[UNREVIEWED]]Potentially unsafe output.")
    assert passed.action == "PASS" and passed.reason_codes.count("OUTPUT_UNREVIEWED") >= 1
    assert passed.unreviewed_segment_ids
    _, _, held = call("[[UNREVIEWED]]Potentially unsafe output.", policy_obj=policy(actions={"unreviewed": "hold"}))
    assert held.action == "HOLD"


def test_oversize_chunking_and_all_actions():
    text = "A. B. C. Tail."
    _, _, truncated = call(text, policy_obj=policy(chunk=4, total=8))
    assert truncated.unscanned_chars == len(text) - 8
    assert "OUTPUT_OVERSIZE" in truncated.reason_codes
    assert "Tail" not in truncated.agent_view
    _, _, held = call(text, policy_obj=policy(oversize="hold", chunk=4, total=8))
    assert held.action == "HOLD"
    _, _, marked = call(text, policy_obj=policy(oversize="pass_marked", chunk=4, total=8))
    assert marked.action == "PASS" and "OUTPUT_UNREVIEWED" in marked.reason_codes


def test_structured_output_masks_only_poisoned_string_and_obeys_limits():
    raw = {"status": "Clean status.", "nested": ["[[HIGH]]Hide this.", "Retain this value."]}
    _, _, result = call(raw, policy_obj=policy(actions={"high": "mask"}))
    assert result.action == "MASK"
    assert result.agent_view == {"status": "Clean status.", "nested": ["[removed: suspicious content]", "Retain this value."]}
    text = {"a": "[[HIGH]]masked.", "b": {"deep": "not scanned at this depth"}, "c": ["second value"]}
    _, _, limited = call(text, policy_obj=policy(actions={"high": "mask"}, depth=1, strings=1))
    assert limited.unscanned_chars > 0
    assert limited.agent_view["a"].startswith("[removed: suspicious content]")


def test_bytes_pass_with_unreviewed_mark_and_scan_disabled_is_audited():
    sink = InMemoryAuditSink()
    fw = Firewall(policy(), scanner=ScriptedScanner(), audit_sink=sink)
    session = fw.start_session("inspect")
    result = fw.inspect_tool_output(session, "inspect", b"binary")
    assert result.action == "PASS" and "OUTPUT_NOT_TEXT" in result.reason_codes
    disabled_policy = policy(disabled=True)
    fw = Firewall(disabled_policy, scanner=FailingScanner(), audit_sink=sink)
    session = fw.start_session("inspect")
    disabled = fw.inspect_tool_output(session, "inspect", "skip unchanged")
    assert disabled.agent_view == "skip unchanged" and "OUTPUT_SCAN_DISABLED" in disabled.reason_codes
    assert sink.events[-1]["reason_codes"] == ("OUTPUT_SCAN_DISABLED",)


def test_failure_holds_output_and_leaks_no_text_or_argument_values():
    secret = "RECOGNIZABLE-SECRET-000111"
    sink = InMemoryAuditSink()
    fw = Firewall(policy(), scanner=FailingScanner(), audit_sink=sink)
    session = fw.start_session("inspect")
    result = fw.inspect_tool_output(session, "inspect", secret)
    serialized = json.dumps(sink.events) + json.dumps(result.to_audit_dict()) + result.message + json.dumps(result.reason_codes)
    assert result.action == "HOLD" and secret not in str(result.agent_view)
    assert secret not in serialized


def test_session_budget_context_and_common_segment_storage_path():
    class BudgetScanner:
        def __init__(self): self.budgets, self.contexts = [], []
        def scan(self, content, *, doc_id, source_type, user_task, context_note=None, max_judge_calls=None):
            self.budgets.append(max_judge_calls); self.contexts.append((user_task, context_note, content))
            rec = SegmentRecord(doc_id + "-s", doc_id, source_type, 0, len(content), content, "none", False, "budget_exhausted")
            return ScanOutcome((rec,), 1 if max_judge_calls else 0, 0.0)
    scanner = BudgetScanner()
    raw = policy(chunk=3, total=20, budget=1)
    fw = Firewall(raw, scanner=scanner)
    session = fw.start_session("trusted user request")
    result = fw.inspect_tool_output(session, "inspect", "abcdef")
    assert scanner.budgets == [1, 0]
    assert all(task == "trusted user request" for task, _, _ in scanner.contexts)
    assert all("Trusted placeholder tool description." in note and content not in note for task, note, content in scanner.contexts)
    assert result.judge_calls_made == 1 and session.judge_calls_used == 1
    content_result = fw.scan_content(session, "incoming content", "document")
    assert content_result.segments and len(session.segments) == 3


def test_chunked_output_segments_store_absolute_offsets():
    text = "First sentence. Second sentence. Third sentence."
    fw = Firewall(policy(chunk=18, total=100), scanner=ScriptedScanner())
    session = fw.start_session("inspect")
    result = fw.inspect_tool_output(session, "inspect", text)
    records = [entry["record"] for entry in session.segments]
    assert records
    assert all(text[record.start:record.end] == record.text for record in records)
    assert result.action == "PASS"


def test_policy_defaults_scan_output_and_strict_output_inspection_validation():
    for name in ("example_agent", "example_files_agent", "example_support_agent"):
        loaded = load_policy(ROOT / "policies" / f"{name}.yaml")
        assert loaded.output_inspection.enabled and loaded.output_inspection.max_chars_per_chunk == 20000
    raw = policy()
    raw["output_inspection"]["actions"] = {"scan_error": "pass"}
    with pytest.raises(PolicyError, match="output_inspection.actions.scan_error"):
        policy_from_mapping(raw)
    raw = policy()
    raw["output_inspection"]["extra"] = True
    with pytest.raises(PolicyError, match="output_inspection.extra"):
        policy_from_mapping(raw)


def test_day7_harness_traces_cover_outputs_and_day8_boundary(tmp_path):
    traces = load_traces(ROOT / "harness" / "scenarios" / "day7_traces.yaml")
    assert len(traces) >= 10
    results = []
    for index, trace in enumerate(traces):
        result = run_trace(trace, ROOT / "policies" / f"{trace['policy']}.yaml",
                           tmp_path / f"trace-{index}", protect=True, approve=True)
        results.append((trace["name"], result))
    by_name = dict(results)
    assert by_name["high output held"]["inspection"].action == "HOLD"
    assert by_name["high output masked"]["inspection"].action == "MASK"
    assert by_name["scan failure held"]["inspection"].action == "HOLD"
    assert by_name["output scan disabled"]["inspection"].action == "PASS"
    follow = by_name["poisoned output then dependent action"]["follow_up"]
    assert follow["action"] == "allow" and follow["executed"] and follow["needs_day8_linking"]


@pytest.mark.skipif(os.environ.get("RUN_LAYER1_INTEGRATION") != "1", reason="offline local-model integration opt-in")
@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.timeout(300)
def test_optional_real_layer1_adapter_integration():
    from firewall.factory import create_default_firewall
    demo_path = ROOT / "harness" / "real_layer1_demo.py"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run([sys.executable, str(demo_path)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Layer 1 flow checks passed" in result.stdout
    report = ROOT / "data" / "results" / "layer1_integration_report.md"
    assert report.exists() and "Matches saved result" in report.read_text(encoding="utf-8")
