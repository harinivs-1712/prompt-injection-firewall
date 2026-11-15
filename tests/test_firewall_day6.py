from __future__ import annotations

import copy
import re
import socket
from pathlib import Path

import pytest

from firewall import Action, Firewall, PolicyError, ReasonCode, load_policy, register_type
from firewall.policy import policy_from_mapping
from harness.fake_tools import make_logging_tool
from harness.runner import load_traces, run_trace

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network access is disabled")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def run(policy, task, tool, args):
    fw = Firewall(ROOT / "policies" / f"{policy}.yaml")
    return fw.check_tool_call(fw.start_session(task), tool, args)


@pytest.mark.parametrize("name", ["example_agent", "example_files_agent", "example_support_agent"])
def test_all_example_policies_use_same_engine(name):
    policy = load_policy(ROOT / "policies" / f"{name}.yaml")
    fw = Firewall(policy)
    assert policy.tools
    assert fw.start_session("read", allowed_tools=list(policy.tools)).allowed_tools == frozenset(policy.tools)


def test_path_policy_and_host_task_override():
    good = run("example_files_agent", "read document", "read_file", {"path": "/workspace/docs/guide.txt"})
    bad = run("example_files_agent", "read document", "read_file", {"path": "/outside/guide.txt"})
    assert good.action is Action.ALLOW
    assert bad.action is Action.BLOCK and ReasonCode.PATH_NOT_ALLOWED in bad.reason_codes
    fw = Firewall(ROOT / "policies" / "example_files_agent.yaml")
    session = fw.start_session("read document", allowed_tools=["write_file"])
    override = fw.check_tool_call(session, "read_file", {"path": "/workspace/docs/guide.txt"})
    assert override.action is Action.ASK and ReasonCode.TOOL_NOT_ALLOWED_FOR_TASK in override.reason_codes


def test_support_policy_constraints_and_always_ask():
    valid = run("example_support_agent", "support refund", "issue_refund", {"order_id": "ORD-123456", "amount": 20})
    assert valid.action is Action.ASK and ReasonCode.ALWAYS_ASK_TOOL in valid.reason_codes
    bad_pattern = run("example_support_agent", "support refund", "issue_refund", {"order_id": "xORD-123456", "amount": 20})
    assert bad_pattern.action is Action.BLOCK and ReasonCode.CONSTRAINT_VIOLATION in bad_pattern.reason_codes
    bad_enum = run("example_support_agent", "support record", "update_record", {"field": "password", "value": "x"})
    assert bad_enum.action is Action.BLOCK and ReasonCode.CONSTRAINT_VIOLATION in bad_enum.reason_codes
    bad_integer = run("example_support_agent", "support ticket", "close_ticket", {"ticket_id": 0})
    assert bad_integer.action is Action.BLOCK and ReasonCode.CONSTRAINT_VIOLATION in bad_integer.reason_codes


def _type_policy(arg_type, constraints=None):
    arg = {"type": arg_type}
    if constraints is not None:
        arg["constraints"] = constraints
    return {"policy_version": "1", "agent_name": "tmp", "tools": {
        "run_anything": {"description": "generic", "risk": "low", "side_effects": False,
                         "args": {"value": arg}}}}


def test_integer_and_number_bounds():
    fw = Firewall(_type_policy("integer", {"min": 2, "max": 5}))
    sess = fw.start_session("do task")
    assert fw.check_tool_call(sess, "run_anything", {"value": 3}).action is Action.ALLOW
    assert ReasonCode.CONSTRAINT_VIOLATION in fw.check_tool_call(sess, "run_anything", {"value": 6}).reason_codes
    fw = Firewall(_type_policy("number", {"min": 0.5, "max": 1.5}))
    assert fw.check_tool_call(fw.start_session("x"), "run_anything", {"value": 0.25}).action is Action.BLOCK


def test_fullmatch_max_length_and_non_string_are_safe():
    fw = Firewall(_type_policy("text_pattern", {"allowed_pattern": "^ORD-[0-9]{6}$", "max_length": 10}))
    session = fw.start_session("x")
    assert fw.check_tool_call(session, "run_anything", {"value": "ORD-123456"}).action is Action.ALLOW
    assert fw.check_tool_call(session, "run_anything", {"value": "xORD-123456"}).action is Action.BLOCK
    too_long = fw.check_tool_call(session, "run_anything", {"value": "x" * 5000})
    assert ReasonCode.CONSTRAINT_VIOLATION in too_long.reason_codes
    non_string = fw.check_tool_call(session, "run_anything", {"value": 123})
    assert ReasonCode.WRONG_ARGUMENT_TYPE in non_string.reason_codes


def test_policy_only_tool_extension_enforces_its_constraints():
    raw = {"policy_version": "1", "agent_name": "new", "tools": {
        "new_tool": {"description": "new tool", "risk": "low", "side_effects": False,
                      "args": {"count": {"type": "integer", "constraints": {"min": 1, "max": 3}}}}}}
    path = ROOT / "tests" / "_temporary_policy_test.yaml"
    try:
        import yaml
        path.write_text(yaml.safe_dump(raw), encoding="utf-8")
        fw = Firewall(path)
        assert fw.check_tool_call(fw.start_session("x"), "new_tool", {"count": 2}).action is Action.ALLOW
        assert fw.check_tool_call(fw.start_session("x"), "new_tool", {"count": 4}).action is Action.BLOCK
    finally:
        path.unlink(missing_ok=True)


def test_custom_type_and_unknown_type_path():
    class Toy:
        constraint_keys = frozenset({"max_length"})
        accepts = staticmethod(lambda v: isinstance(v, str))
        def validate(self, value, spec, limits):
            if not isinstance(value, str):
                return None, "INVALID_ARGUMENT_VALUE"
            if len(value) > spec.constraints.get("max_length", 20):
                return None, "CONSTRAINT_VIOLATION"
            return value.strip(), None
    register_type("toy_token", Toy())
    fw = Firewall(_type_policy("toy_token", {"max_length": 4}))
    assert fw.check_tool_call(fw.start_session("x"), "run_anything", {"value": "abc"}).action is Action.ALLOW
    with pytest.raises(PolicyError) as exc:
        policy_from_mapping(_type_policy("unregistered_custom"))
    assert "tools.run_anything.args.value.type" in str(exc.value)


@pytest.mark.parametrize("raw, expected", [
    (_type_policy("integer", {"minimum": 1}), "constraints.minimum"),
    (_type_policy("free_text", {"min": 1}), "constraints.min"),
    (_type_policy("text_pattern", {"allowed_pattern": "["}), "allowed_pattern"),
])
def test_constraints_are_strictly_validated(raw, expected):
    with pytest.raises(PolicyError, match=re.escape(expected)):
        policy_from_mapping(raw)


def test_argument_values_never_appear_in_decision_or_audit():
    secret = "private-value-abc123"
    fw = Firewall(ROOT / "policies" / "example_files_agent.yaml")
    session = fw.start_session("read document")
    decision = fw.check_tool_call(session, "read_file", {"path": "/outside/" + secret})
    serialized = decision.to_json() + repr(session.events)
    assert secret not in serialized


def test_generic_fake_tool_logs_only_tool_and_argument_names(tmp_path):
    tool = make_logging_tool("placeholder", tmp_path / "calls.log")
    tool(secret="do-not-write", count=3)
    text = (tmp_path / "calls.log").read_text(encoding="utf-8")
    assert "placeholder" in text and "count" in text and "secret" in text
    assert "do-not-write" not in text and "3" not in text


def test_harness_blocks_attacks_and_executes_approved_normal_traces(tmp_path):
    traces = load_traces(ROOT / "harness" / "scenarios" / "day6_traces.yaml")
    for index, trace in enumerate(traces):
        policy = ROOT / "policies" / f"{trace['policy']}.yaml"
        unprotected = run_trace(trace, policy, tmp_path / f"raw-{index}", protect=False)
        assert unprotected["executed"]
        protected = run_trace(trace, policy, tmp_path / f"guarded-{index}", protect=True, approve=False)
        if trace["label"] == "attack":
            assert not protected["executed"], trace["name"]
        else:
            approved = run_trace(trace, policy, tmp_path / f"approved-{index}", protect=True, approve=True)
            assert approved["executed"], trace["name"]


def test_firewall_source_has_no_concrete_tool_or_domain_terms():
    forbidden = re.compile(r"\b(?:send_email|make_payment|email)\b", re.I)
    for path in (ROOT / "firewall").glob("*.py"):
        source = path.read_text(encoding="utf-8")
        # Tokenize to ignore comments and docstrings; inspect executable string literals too.
        import io
        import tokenize
        tokens = [t.string for t in tokenize.generate_tokens(io.StringIO(source).readline)
                  if t.type not in {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER}]
        assert not forbidden.search(" ".join(tokens)), path.name
