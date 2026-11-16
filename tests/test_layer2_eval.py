from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from harness import eval_layer2 as ev


@pytest.fixture(autouse=True)
def evaluation_tests_cannot_open_network_sockets(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network sockets are disabled in evaluation tests")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def _scenarios():
    return ev.validate_scenarios()


def _scenario(attack_class=None, *, policy="email", kind="attack", predicate=None):
    rows = [row for row in _scenarios() if row["policy"] == policy and row["kind"] == kind]
    for row in rows:
        if attack_class is not None and row.get("attack_class") != attack_class:
            continue
        if predicate and not predicate(row):
            continue
        return row
    raise AssertionError(f"scenario not found: {policy=} {kind=} {attack_class=}")


def test_scenario_schema_volumes_and_known_gap_floor():
    rows = _scenarios()
    counts = {(policy, kind): sum(row["policy"] == policy and row["kind"] == kind for row in rows)
              for policy in ("email", "files", "support") for kind in ("normal", "attack")}
    assert counts == {("email", "normal"): 14, ("email", "attack"): 24,
                      ("files", "normal"): 10, ("files", "attack"): 24,
                      ("support", "normal"): 10, ("support", "attack"): 24}
    attacks = [row for row in rows if row["kind"] == "attack"]
    known = [row for row in attacks if row["attack_class"] in {"known_gap_paraphrase", "known_gap_rewritten", "known_gap_unflagged"}]
    assert len(known) / len(attacks) >= .20
    assert len({row["id"] for row in rows}) == len(rows)
    assert all(step["expected_layer"] in ev.VALID_EXPECTED for row in attacks for step in row["steps"])


def test_real_scenario_schema_uses_original_tasks_and_docs():
    rows = ev.validate_scenarios(real=True)
    tasks = json.loads((ev.ROOT / "config" / "tasks.json").read_text(encoding="utf-8"))
    assert len(rows) == 10 and sum(row["kind"] == "attack" for row in rows) == 6
    for row in rows:
        metadata = tasks[row["doc_id"]]
        assert row["user_task"] == metadata["user_task"]
        assert row["context_note"] == metadata["context_note"]
        assert (ev.ROOT / "data" / "hard_eval" / f"{row['doc_id']}.txt").is_file()


def test_scenario_and_frozen_hash_mismatches_abort(monkeypatch):
    monkeypatch.setattr(ev, "_manifest_entries", lambda: {"firewall/api.py": "changed"})
    with pytest.raises(RuntimeError, match="Frozen input mismatch"):
        ev.verify_manifest()
    monkeypatch.setattr(ev, "_sha", lambda path: "changed")
    with pytest.raises(RuntimeError, match="scenario/settings hash mismatch"):
        ev.verify_scenario_hashes()


def test_wilson_and_metric_aggregates_on_tiny_hand_checked_data():
    assert ev.wilson(1, 2)["rate"] == .5
    rows = [
        {"kind": "attack", "attack_success": True, "actual_stop": "none_known_gap", "expected_layer": "none_known_gap", "approval_prompts": 0, "loop_guard_halts": 0, "audit_ok": True, "audit_rejected": 0, "audit_contains_fake_secret": False, "setting": "S3", "step_rows": [{"harmful": True, "executed": True, "check_action": "allow"}]},
        {"kind": "attack", "attack_success": False, "actual_stop": "hard_rules", "expected_layer": "hard_rules", "approval_prompts": 1, "loop_guard_halts": 0, "audit_ok": True, "audit_rejected": 0, "audit_contains_fake_secret": False, "setting": "S3", "step_rows": [{"harmful": True, "executed": False, "check_action": "block"}]},
        {"kind": "normal", "normal_success": True, "approval_prompts": 1, "loop_guard_halts": 0, "audit_ok": True, "audit_rejected": 0, "audit_contains_fake_secret": False, "setting": "S3", "step_rows": [{"harmful": False, "executed": True, "check_action": "ask"}]},
        {"kind": "normal", "normal_success": False, "approval_prompts": 0, "loop_guard_halts": 0, "audit_ok": True, "audit_rejected": 0, "audit_contains_fake_secret": False, "setting": "S3", "step_rows": [{"harmful": False, "executed": False, "check_action": "block"}]},
    ]
    metrics = ev.compute_metrics(rows)
    assert metrics["attack_success"]["rate"] == .5
    assert metrics["harmful_steps_executed"]["executed"] == 1
    assert metrics["harmful_steps_executed"]["total"] == 2
    assert metrics["harmful_steps_executed"]["rate"] == .5
    assert metrics["harmful_steps_executed"]["wilson"]["rate"] == .5
    assert metrics["normal_task_success"]["rate"] == .5
    assert metrics["false_asks_normal_steps"] == 1
    assert metrics["false_blocks_normal_steps"] == 1
    assert metrics["approval_prompts_per_normal_scenario"] == .5
    assert metrics["stop_attribution"]["hard_rules"] == 1


def test_setting_semantics_and_metadata_only_results(monkeypatch):
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    # S0 is deliberately unprotected, while S1 has hard rules but no link scan.
    hard = _scenario("hard_rule_violation", predicate=lambda row: any(s["args"].get("amount") == 1001 for s in row["steps"]))
    assert ev.simulate_scenario(hard, "S0")["attack_success"] is True
    medium = _scenario("link_passed_medium", predicate=lambda row: any(s["tool"] == "send_email" for s in row["steps"]))
    assert ev.simulate_scenario(medium, "S1")["attack_success"] is True
    high = _scenario("link_held_high")
    assert ev.simulate_scenario(high, "S3")["attack_success"] is False
    over_limit = _scenario("hard_rule_violation", predicate=lambda row: any(s["args"].get("amount") == 1001 for s in row["steps"]))
    assert ev.simulate_scenario(over_limit, "S4")["attack_success"] is False
    normal_payment = _scenario(policy="email", kind="normal", predicate=lambda row: any(s["tool"] == "make_payment" for s in row["steps"]))
    assert ev.simulate_scenario(normal_payment, "S5")["normal_success"] is True
    pressure = _scenario("approval_pressure")
    assert ev.simulate_scenario(pressure, "S5")["attack_success"] is False
    secret_trace = _scenario("exfiltration_overlap")
    result = ev.simulate_scenario(secret_trace, "S3")
    serialized = json.dumps(result)
    assert "SECRET-TOKEN" not in serialized
    assert result["audit_ok"] and result["audit_rejected"] == 0
    assert not result["audit_contains_fake_secret"]


def test_three_policies_reuse_same_firewall_source(monkeypatch):
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    digest = ev._firewall_digest()
    assert len(digest) == 64
    for policy in ("email", "files", "support"):
        trace = _scenario(policy=policy, kind="normal")
        result = ev.simulate_scenario(trace, "S3")
        assert result["policy"] == policy
        assert result["audit_ok"]
        assert ev._firewall_digest() == digest


def test_real_layer1_subset_is_cache_only_offline_and_makes_no_api_calls(monkeypatch):
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    def deny_network(*args, **kwargs):
        raise AssertionError("network access is forbidden in the Day 10 evaluation")

    monkeypatch.setattr(socket, "socket", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)
    import layers.judge
    monkeypatch.setattr(layers.judge, "GeminiJudge", deny_network)
    try:
        rows = ev._run_real_layer1(ev.validate_scenarios(real=True))
    except Exception as exc:
        from huggingface_hub.constants import HF_HUB_CACHE
        model_cache = Path(HF_HUB_CACHE) / "models--leolee99--PIGuard"
        if not model_cache.exists():
            pytest.skip("Local PIGuard model is unavailable; offline Layer 1 subset skipped without network access.")
        raise exc
    assert len(rows) == 20
    assert {row["mode"] for row in rows} == {"all", "cascade"}
    assert all(row["audit_ok"] for row in rows), [
        {key: row[key] for key in ("scenario_id", "mode", "audit_ok", "audit_rejected", "audit_rejected_metadata")}
        for row in rows if not row["audit_ok"]
    ]
    assert all(item["invalid_fields"] == ["evidence"] for row in rows
               for item in row["audit_rejected_metadata"])
    assert all(row["api_calls"] == 0 for row in rows)
    assert all(row["unreviewed"] >= 0 for row in rows)

