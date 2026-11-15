from __future__ import annotations

import copy
import json
import socket
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from firewall import Action, Decision, Firewall, NotConfigured, PolicyError, ReasonCode, Session, load_policy
from firewall.cleaning import (
    domain_of, is_domain_allowed, normalize_account, normalize_amount, normalize_email,
    normalize_path, normalize_text, normalize_url, path_is_under,
)
from firewall.policy import policy_from_mapping
from firewall.protocols import InMemoryAuditSink
from firewall.types import ScanOutcome, SegmentRecord

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_POLICY = ROOT / "policies" / "example_agent.yaml"


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network access is disabled in Day 5 tests")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


def _raw_policy():
    return {
        "policy_version": "1",
        "agent_name": "test_agent",
        "tools": {
            "send_email": {
                "description": "Send a placeholder message.", "risk": "high", "side_effects": True,
                "args": {"to": {"type": "recipient"}, "body": {"type": "free_text"}},
            },
            "read_note": {
                "description": "Read a note.", "risk": "low", "side_effects": False,
                "args": {"note_id": {"type": "identifier"}},
            },
        },
        "limits": {"allowed_recipient_domains": ["example.com"], "max_amount": 1000},
        "task_categories": {"read_only": {"allowed_tools": ["read_note"], "keywords": ["read", "find"]}},
        "verb_to_tool": {"send": ["send_email"]},
    }


def test_example_policy_loads_as_immutable_schema():
    policy = load_policy(EXAMPLE_POLICY)
    assert policy.agent_name == "example_agent"
    assert policy.has_tool("send_email")
    assert policy.get_tool("make_payment").always_ask
    assert policy.arg_types("send_email")["to"] == "recipient"
    with pytest.raises(TypeError):
        policy.tools["other"] = policy.get_tool("read_email")
    with pytest.raises(TypeError):
        policy.get_tool("send_email").args["to"] = None


@pytest.mark.parametrize(
    ("mutate", "path"),
    [
        (lambda p: p.update(extra=True), "policy.extra"),
        (lambda p: p["tools"]["send_email"].update(risk="extreme"), "tools.send_email.risk"),
        (lambda p: p["tools"]["send_email"]["args"]["to"].update(type="recepient"), "tools.send_email.args.to.type"),
        (lambda p: p["limits"].update(max_amount=-1), "limits.max_amount"),
        (lambda p: p["task_categories"]["read_only"].update(allowed_tools=["ghost"]), "task_categories.read_only.allowed_tools"),
        (lambda p: p["verb_to_tool"].update(send=["ghost"]), "verb_to_tool.send"),
        (lambda p: p["tools"]["send_email"]["args"].update(body={"type": "free_text", "surprise": True}), "tools.send_email.args.body.surprise"),
        (lambda p: p["tools"]["send_email"].update(side_effects="yes"), "tools.send_email.side_effects"),
    ],
)
def test_policy_rejects_invalid_schema_with_path(mutate, path):
    raw = copy.deepcopy(_raw_policy())
    mutate(raw)
    with pytest.raises(PolicyError) as exc:
        policy_from_mapping(raw)
    assert path in str(exc.value)


def test_loader_rejects_empty_wrong_yaml_types_and_duplicate_names(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("  \n", encoding="utf-8")
    with pytest.raises(PolicyError, match="empty"):
        load_policy(empty)

    wrong = tmp_path / "wrong.yaml"
    wrong.write_text("policy_version: 1\nagent_name: test\ntools: []\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="policy.policy_version"):
        load_policy(wrong)

    wrong_tools = tmp_path / "wrong-tools.yaml"
    wrong_tools.write_text("policy_version: '1'\nagent_name: test\ntools: []\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="policy.tools"):
        load_policy(wrong_tools)

    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("policy_version: '1'\nagent_name: test\ntools:\n  send_email: {}\n  send_email: {}\n", encoding="utf-8")
    with pytest.raises(PolicyError) as exc:
        load_policy(duplicate)
    assert "policy.tools.send_email" in str(exc.value)


def test_firewall_construction_rejects_invalid_policy():
    raw = _raw_policy()
    raw["tools"]["send_email"]["risk"] = "extreme"
    with pytest.raises(PolicyError, match="tools.send_email.risk"):
        Firewall(raw)


def test_text_email_and_domain_normalization():
    assert normalize_text("  ＨＥＬＬＯ\u200b\t World  ") == "hello world"
    assert normalize_email(" Ａlice＠ＥＸＡＭＰＬＥ．ＣＯＭ. ") == "alice@example.com"
    assert normalize_email("Alice\u200b@Example.COM.") == "alice@example.com"
    for invalid in (None, b"a@example.com", "no-at", "a@@example.com", "a @example.com", "@example.com", "a@"):
        assert normalize_email(invalid) is None
    assert domain_of("https://example.com@evil.example.net/x?q=1#fragment") == "evil.example.net"
    assert domain_of("ALICE@EXAMPLE.COM.") == "example.com"
    assert domain_of("https://EXAMPLE.COM.:443/a?x=1#frag") == "example.com"
    assert is_domain_allowed("EXAMPLE.COM.", ["example.com"])
    assert is_domain_allowed("mail.example.com", ["example.com"], allow_subdomains=True)
    assert not is_domain_allowed("mail.example.com", ["example.com"])
    assert not is_domain_allowed("evil-example.com", ["example.com"], allow_subdomains=True)
    assert not is_domain_allowed("example.com.evil.net", ["example.com"], allow_subdomains=True)


def test_amount_account_path_and_url_cleaning():
    assert normalize_amount("5,000.00") == Decimal("5000.00")
    assert normalize_amount("5,00,000") == Decimal("500000")
    assert normalize_amount("$5,000") == Decimal("5000")
    assert normalize_amount("Rs. 5000") == Decimal("5000")
    assert normalize_amount("5000 rupees") == Decimal("5000")
    for invalid in ("-5", "NaN", "Infinity", "1e999", "abc", "", "5,00.00", None, True, b"10"):
        assert normalize_amount(invalid) is None
    assert normalize_account("ab-00 11") == "AB0011"
    assert normalize_account("---") is None
    assert normalize_path("a//b") == "a/b"
    assert normalize_path(r"a\b") == "a/b"
    assert normalize_path("a/./b/../c") == "a/c"
    assert normalize_path("../x") is None
    assert normalize_path("/../../x") is None
    assert path_is_under("/data/email/a.txt", ["/data/email"])
    assert not path_is_under("/data/emailsX/a.txt", ["/data/email"])
    assert normalize_path("/Data/Notes", case_insensitive=True) == "/data/notes"
    assert normalize_url("HTTPS://EXAMPLE.COM:443/a?Q=AbC#section") == "https://example.com/a?Q=AbC"
    assert normalize_url("http://example.com:80/a") == "http://example.com/a"
    assert normalize_url("javascript:alert(1)") is None
    assert normalize_url("https://user:pass@example.com/x") is None


def test_cleaners_handle_odd_values_and_long_strings_without_crashing():
    for value in (None, b"bytes", 17, object(), "x" * 10_000):
        normalize_text(value)
        normalize_email(value)
        domain_of(value)
        normalize_account(value)
        normalize_amount(value)
        normalize_path(value)
        normalize_url(value)
        path_is_under(value, ["/data"])
    assert normalize_text(b"bytes") is None


def _firewall(*, policy=None, sink=None, **kwargs):
    return Firewall(policy or _raw_policy(), audit_sink=sink, **kwargs)


def test_tool_call_safe_defaults_and_unknown_tool_policy():
    sink = InMemoryAuditSink()
    fw = _firewall(sink=sink)
    session = fw.start_session("Send the placeholder reply.")
    unknown = fw.check_tool_call(session, "unknown", {"x": "000-111"})
    assert unknown.action is Action.ASK
    assert unknown.reason_codes == (ReasonCode.UNKNOWN_TOOL,)

    raw = _raw_policy()
    raw["defaults"] = {"unknown_tool_action": "block"}
    blocked_unknown = _firewall(policy=raw).check_tool_call(Session(user_task="x"), "unknown", {})
    assert blocked_unknown.action is Action.BLOCK

    missing = fw.check_tool_call(session, "send_email", {"to": "user@example.com"})
    assert missing.action is Action.BLOCK and ReasonCode.MISSING_ARGUMENT in missing.reason_codes
    unexpected = fw.check_tool_call(session, "read_note", {"note_id": "000-111", "extra": "x"})
    assert unexpected.action is Action.BLOCK and ReasonCode.UNEXPECTED_ARGUMENT in unexpected.reason_codes
    wrong = fw.check_tool_call(session, "send_email", {"to": ["user@example.com", 7], "body": "hi"})
    assert wrong.action is Action.BLOCK and ReasonCode.WRONG_ARGUMENT_TYPE in wrong.reason_codes
    valid = fw.check_tool_call(fw.start_session("Send the placeholder reply.", allowed_tools=["send_email"]), "send_email", {"to": "user@example.com", "body": "hello"})
    assert valid.action is Action.ALLOW and ReasonCode.ALL_RULES_PASSED in valid.reason_codes
    assert session.blocked_attempts["send_email"] == 2
    assert session.blocked_attempts["read_note"] == 1


def test_strict_args_false_and_internal_error_are_still_fail_closed():
    raw = _raw_policy()
    raw["defaults"] = {"strict_args": False}
    fw = _firewall(policy=raw)
    session = fw.start_session("reply")
    result = fw.check_tool_call(session, "read_note", {"note_id": "N-000", "extra": "x"})
    assert result.action is Action.ALLOW and ReasonCode.ALL_RULES_PASSED in result.reason_codes

    secret = "SECRET_SHOULD_NOT_LEAK_000-111"
    class ExplodingArgs(dict):
        def __getitem__(self, key):
            raise RuntimeError(secret)
    error = _firewall().check_tool_call(Session(user_task="read"), "read_note", ExplodingArgs(note_id=secret))
    assert error.action is Action.ASK and error.reason_codes == (ReasonCode.INTERNAL_ERROR,)
    assert secret not in error.to_json() and secret not in error.message


def test_decisions_audit_and_sessions_never_record_argument_values():
    secret = "PRIVATE_PLACEHOLDER_000-111"
    sink = InMemoryAuditSink()
    fw = _firewall(sink=sink)
    session = fw.start_session("Summarize the note.")
    decision = fw.check_tool_call(session, "send_email", {"to": "user@example.com", "body": secret})
    combined = decision.to_json() + json.dumps(sink.events) + json.dumps(session.events)
    assert secret not in combined
    assert sink.events[0]["tool_name"] == "send_email"
    assert sink.events[0]["argument_names"] == ("body", "to")
    assert decision.details["argument_names"] == ("body", "to")
    assert Decision.allow().action is Action.ALLOW


def test_scan_content_requires_injected_scanner_and_stores_segments():
    session = Session(user_task="Summarize the message.")
    fw = _firewall()
    with pytest.raises(NotConfigured, match="scanner was injected"):
        fw.scan_content(session, "external content", "email")

    class MockScanner:
        def __init__(self):
            self.calls = []
        def scan(self, content, **kwargs):
            self.calls.append((content, kwargs))
            return ScanOutcome((SegmentRecord("s-000", kwargs["doc_id"], kwargs["source_type"], 0,
                                              len(content), content, "none", True, "reviewed"),), 0, 1.0)

    scanner = MockScanner()
    result = _firewall(scanner=scanner).scan_content(session, "external paragraph", "tool_output", doc_id="tool-000")
    assert result.segments[0].text == session.segments[0]["record"].text
    assert scanner.calls[0][0] == "external paragraph"
    assert scanner.calls[0][1]["user_task"] == "Summarize the message."
    assert "Summarize the message." not in scanner.calls[0][0]


def test_firewall_import_has_no_heavy_or_layer1_imports():
    code = (
        "import sys, firewall; "
        "bad = [m for m in sys.modules if m == 'layers' or m.startswith('layers.') "
        "or m == 'torch' or m.startswith('torch.') or m == 'transformers' "
        "or m.startswith('transformers.') or m == 'google' or m.startswith('google.')]; "
        "assert not bad, bad"
    )
    completed = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=15)
    assert completed.returncode == 0, completed.stderr
