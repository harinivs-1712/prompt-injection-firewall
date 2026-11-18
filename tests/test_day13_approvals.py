"""Comprehensive test suite for Layer 3 Day 13: Approval broker, reviewer endpoints, sanitized view."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import sqlite3
import sys
import tempfile
import threading
import time
from contextlib import closing
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from firewall.api import Firewall
from firewall.approval import ReviewPacket
from firewall.audit import SQLiteAuditStore
from firewall.decision import Action, Decision, ReasonCode
from firewall.policy import load_policy
from firewall.session import Session
from firewall_server.app import create_app
from firewall_server.broker import (
    AlreadyDecidedError,
    ApprovalBroker,
    BrokerFullError,
    HashMismatchError,
    PendingRequest,
    RequestExpiredError,
    RequestNotFoundError,
    compute_request_hash,
    sanitize_values_preview,
)
from firewall_server.broker_client import BrokerApprovalCallback, make_firewall_with_broker
from firewall_server.review_store import ReviewRecorder, ReviewStore
from firewall_server.security import ActionRateLimiter, FailureThrottle
from firewall_server.settings import Settings, from_args
from firewall_server.view import build_masked_pieces, merge_spans, split_text_into_pieces

VIEWER_TOKEN = "test-viewer-token-string-001"
REVIEWER_TOKEN = "test-reviewer-token-string-002"
AGENT_TOKEN = "test-agent-token-string-003"
WEAK_TOKEN = "passwordpasswordpassword"

AUTH_VIEWER = {"Authorization": f"Bearer {VIEWER_TOKEN}"}
AUTH_REVIEWER = {"Authorization": f"Bearer {REVIEWER_TOKEN}"}
AUTH_AGENT = {"Authorization": f"Bearer {AGENT_TOKEN}"}


@pytest.fixture(autouse=True)
def guard_external_sockets(monkeypatch):
    orig_connect = socket.socket.connect

    def guarded_connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        # Windows' Proactor event loop implements its private wake-up pipe with
        # socket.socketpair().  Its address is bytes on some Python builds, so
        # normalize that local-only form before applying the external-network
        # guard used by these tests.
        if isinstance(host, bytes):
            host = host.decode("ascii", errors="ignore")
        if host not in ("127.0.0.1", "localhost", "::1", "testserver"):
            raise AssertionError(f"External network connection to {host} is blocked")
        return orig_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


def _make_dbs(tmp_path: Path, *, store_text: bool = True):
    audit_path = tmp_path / "audit.sqlite"
    review_path = tmp_path / "review.sqlite"

    store = SQLiteAuditStore(audit_path)
    store.record_session("sess-001", "1.0", "demo_agent", "Test user task string")
    store.record({
        "event_type": "tool_check",
        "session_id": "sess-001",
        "tool": "make_payment",
        "action": "allow",
        "reason_codes": ["ALL_RULES_PASSED"],
        "rule_ids": ["R-TASK"],
    })
    store.close()

    review = ReviewStore(review_path, store_text=store_text)
    review.add(
        session_id="sess-001",
        item_type="held_output",
        tool="search_notes",
        output_id="out-001",
        max_level="high",
        reason_codes=["OUTPUT_HELD"],
        segment_ids=["seg-001"],
        level_counts={"high": 1},
        original_text="Hello world secret text",
        spans=[{"start": 12, "end": 18, "level": "high", "segment_id": "seg-001"}],
    )
    return audit_path, review_path


def _make_client(
    tmp_path: Path,
    *,
    enable_broker: bool = True,
    store_text: bool = True,
    throttle: FailureThrottle | None = None,
    rate_limiter: ActionRateLimiter | None = None,
    broker: ApprovalBroker | None = None,
    agent_token: str = AGENT_TOKEN,
) -> TestClient:
    audit_path, review_path = _make_dbs(tmp_path, store_text=store_text)
    settings = Settings(
        audit_db=audit_path,
        review_db=review_path,
        policy=ROOT / "policies" / "example_agent.yaml",
        viewer_token=VIEWER_TOKEN,
        reviewer_token=REVIEWER_TOKEN,
        agent_token=agent_token,
        enable_broker=enable_broker,
        cors_origins=("http://localhost:5173", "http://127.0.0.1:5173"),
        store_text=store_text,
        allowed_hosts=("testserver",),
        broker_max_pending=10,
        broker_max_ttl_seconds=300.0,
    )
    app = create_app(settings, throttle=throttle, rate_limiter=rate_limiter, broker=broker)
    return TestClient(app, base_url="http://localhost")


# ==============================================================================
# 1. Roles, Auth and Endpoint Guards
# ==============================================================================

class TestRolesAndGuards:
    def test_startup_refuses_invalid_agent_token(self, tmp_path, monkeypatch):
        a_db, r_db = _make_dbs(tmp_path)
        monkeypatch.setenv("FIREWALL_VIEWER_TOKEN", VIEWER_TOKEN)
        monkeypatch.setenv("FIREWALL_REVIEWER_TOKEN", REVIEWER_TOKEN)
        monkeypatch.setenv("FIREWALL_ENABLE_BROKER", "1")

        # Missing agent token
        monkeypatch.delenv("FIREWALL_AGENT_TOKEN", raising=False)
        with pytest.raises(ValueError, match="FIREWALL_AGENT_TOKEN is required"):
            from_args(["--audit-db", str(a_db), "--review-db", str(r_db), "--policy", "policies/example_agent.yaml", "--enable-broker"])

        # Short agent token
        monkeypatch.setenv("FIREWALL_AGENT_TOKEN", "short")
        with pytest.raises(ValueError, match="agent token must be at least 24 characters"):
            from_args(["--audit-db", str(a_db), "--review-db", str(r_db), "--policy", "policies/example_agent.yaml", "--enable-broker"])

        # Agent token same as viewer
        monkeypatch.setenv("FIREWALL_AGENT_TOKEN", VIEWER_TOKEN)
        with pytest.raises(ValueError, match="agent and viewer tokens must differ"):
            from_args(["--audit-db", str(a_db), "--review-db", str(r_db), "--policy", "policies/example_agent.yaml", "--enable-broker"])

        # Agent token same as reviewer
        monkeypatch.setenv("FIREWALL_AGENT_TOKEN", REVIEWER_TOKEN)
        with pytest.raises(ValueError, match="agent and reviewer tokens must differ"):
            from_args(["--audit-db", str(a_db), "--review-db", str(r_db), "--policy", "policies/example_agent.yaml", "--enable-broker"])

    def test_broker_disabled_returns_404(self, tmp_path):
        client = _make_client(tmp_path, enable_broker=False)
        res = client.get("/api/v1/approvals", headers=AUTH_REVIEWER)
        assert res.status_code == 404

        res2 = client.post("/api/v1/broker/requests", headers=AUTH_AGENT, json={"session_id": "s", "tool": "t"})
        assert res2.status_code == 404

    def test_role_separation(self, tmp_path):
        client = _make_client(tmp_path, enable_broker=True)

        payload = {
            "session_id": "s1",
            "tool": "make_payment",
            "reason_codes": ["ASK"],
            "values_preview": {"amt": "10"},
        }
        # Viewer cannot create request
        res_v = client.post("/api/v1/broker/requests", headers=AUTH_VIEWER, json=payload)
        assert res_v.status_code == 403

        # Reviewer cannot create request
        res_r = client.post("/api/v1/broker/requests", headers=AUTH_REVIEWER, json=payload)
        assert res_r.status_code == 403

        # Agent can create request
        res_a = client.post("/api/v1/broker/requests", headers=AUTH_AGENT, json=payload)
        assert res_a.status_code == 200
        req_id = res_a.json()["request_id"]

        # Agent cannot list approvals or access audit summary
        assert client.get("/api/v1/approvals", headers=AUTH_AGENT).status_code == 403
        assert client.get("/api/v1/summary", headers=AUTH_AGENT).status_code == 403
        assert client.get(f"/api/v1/approvals/{req_id}", headers=AUTH_AGENT).status_code == 403

        # Viewer cannot access reviewer approvals list
        assert client.get("/api/v1/approvals", headers=AUTH_VIEWER).status_code == 403

        # Reviewer can list approvals
        assert client.get("/api/v1/approvals", headers=AUTH_REVIEWER).status_code == 200

    def test_agent_endpoint_rejects_origin_header(self, tmp_path):
        client = _make_client(tmp_path, enable_broker=True)
        headers = {**AUTH_AGENT, "Origin": "http://evil.com"}
        res = client.post("/api/v1/broker/requests", headers=headers, json={"session_id": "s", "tool": "t"})
        assert res.status_code == 403
        assert "access-control-allow-origin" not in res.headers

    def test_post_content_type_and_extra_fields_enforcement(self, tmp_path):
        client = _make_client(tmp_path, enable_broker=True)

        # Content-type not application/json -> 415
        res_ct = client.post(
            "/api/v1/broker/requests",
            headers={"Authorization": f"Bearer {AGENT_TOKEN}", "Content-Type": "text/plain"},
            content=b"hello",
        )
        assert res_ct.status_code == 415

        # Unknown field -> 422
        bad_payload = {"session_id": "s", "tool": "t", "forbidden_field": 123}
        res_extra = client.post("/api/v1/broker/requests", headers=AUTH_AGENT, json=bad_payload)
        assert res_extra.status_code == 422

    def test_post_body_size_limit(self, tmp_path):
        client = _make_client(tmp_path, enable_broker=True)
        huge_explanation = "x" * 70000
        payload = {"session_id": "s", "tool": "t", "explanation": huge_explanation}
        res = client.post("/api/v1/broker/requests", headers=AUTH_AGENT, json=payload)
        assert res.status_code == 413


# ==============================================================================
# 2. Broker State Machine and Concurrency
# ==============================================================================

class TestBrokerStateMachine:
    def test_hash_calculation(self):
        h1 = compute_request_hash("req-1", "sess-1", "tool_a", ["R1", "R2"], {"k": "v"})
        h2 = compute_request_hash("req-1", "sess-1", "tool_a", ["R2", "R1"], {"k": "v"})
        assert h1 == h2
        h3 = compute_request_hash("req-1", "sess-1", "tool_a", ["R1", "R2"], {"k": "v2"})
        assert h1 != h3

    def test_values_sanitization(self):
        dirty = {"arg\x001": "clean\n\ttext\x01\x1fend", "arg2": "a" * 10000}
        cleaned = sanitize_values_preview(dirty)
        assert "\x00" not in cleaned["arg1"]
        assert "\x01" not in cleaned["arg1"]
        assert len(cleaned["arg2"]) <= 4096

    def test_background_sweeper_expires_and_wipes_values(self):
        """Expiry is automatic; it must not wait for a later API request."""
        fake_time = [1000.0]
        broker = ApprovalBroker(max_pending=5, max_ttl_seconds=30.0, clock=lambda: fake_time[0])
        request_id, _ = broker.create_request(
            session_id="s",
            tool="t",
            reason_codes=["ASK"],
            explanation="Review this action",
            evidence_summary=[],
            sensitivity_flags=[],
            values_preview={"secret": "SECRET-TOKEN-0000"},
            ttl_seconds=1.0,
        )
        broker.start_sweeper(interval_seconds=0.01)
        try:
            fake_time[0] += 2.0
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline:
                if broker.get_request_detail(request_id)["status"] == "expired":
                    break
                time.sleep(0.01)
            detail = broker.get_request_detail(request_id)
            assert detail["status"] == "expired"
            assert "values_preview" not in detail
            assert "explanation" not in detail
        finally:
            broker.stop_sweeper()

    def test_state_flow_approve_and_confirm(self, tmp_path):
        client = _make_client(tmp_path, enable_broker=True)
        create_res = client.post(
            "/api/v1/broker/requests",
            headers=AUTH_AGENT,
            json={"session_id": "s1", "tool": "t1", "values_preview": {"secret": "val"}},
        )
        assert create_res.status_code == 200
        req_id = create_res.json()["request_id"]

        detail_res = client.get(f"/api/v1/approvals/{req_id}", headers=AUTH_REVIEWER)
        req_hash = detail_res.json()["request_hash"]
        assert detail_res.json()["values_preview"]["secret"] == "val"

        # Approve without confirm=true fails with 422
        bad_dec = client.post(
            f"/api/v1/approvals/{req_id}/decision",
            headers=AUTH_REVIEWER,
            json={"decision": "approve", "request_hash": req_hash, "confirm": False},
        )
        assert bad_dec.status_code == 422

        # Approve with wrong hash fails with 409 and remains pending
        bad_hash_dec = client.post(
            f"/api/v1/approvals/{req_id}/decision",
            headers=AUTH_REVIEWER,
            json={"decision": "approve", "request_hash": "wronghash", "confirm": True},
        )
        assert bad_hash_dec.status_code == 409
        assert bad_hash_dec.json()["code"] == "HASH_MISMATCH"

        # Approve with valid hash and confirm=true
        ok_dec = client.post(
            f"/api/v1/approvals/{req_id}/decision",
            headers=AUTH_REVIEWER,
            json={"decision": "approve", "request_hash": req_hash, "confirm": True},
        )
        assert ok_dec.status_code == 200
        assert ok_dec.json()["status"] == "approved"

        # Second decision fails with 409 ALREADY_DECIDED
        second_dec = client.post(
            f"/api/v1/approvals/{req_id}/decision",
            headers=AUTH_REVIEWER,
            json={"decision": "deny", "request_hash": req_hash, "confirm": False},
        )
        assert second_dec.status_code == 409
        assert second_dec.json()["code"] == "ALREADY_DECIDED"

        # After decision, values_preview is None in detail
        after_detail = client.get(f"/api/v1/approvals/{req_id}", headers=AUTH_REVIEWER).json()
        assert after_detail["values_preview"] is None
        assert after_detail["request_hash"] is None
        assert after_detail["status"] == "approved"
        assert after_detail["explanation"] is None
        assert after_detail["evidence_summary"] is None
        assert after_detail["sensitivity_flags"] is None

    def test_state_flow_deny_and_cancel(self, tmp_path):
        client = _make_client(tmp_path, enable_broker=True)
        # Test Deny
        r1 = client.post("/api/v1/broker/requests", headers=AUTH_AGENT, json={"session_id": "s", "tool": "t"}).json()["request_id"]
        h1 = client.get(f"/api/v1/approvals/{r1}", headers=AUTH_REVIEWER).json()["request_hash"]
        dec_deny = client.post(f"/api/v1/approvals/{r1}/decision", headers=AUTH_REVIEWER, json={"decision": "deny", "request_hash": h1})
        assert dec_deny.status_code == 200
        assert dec_deny.json()["status"] == "denied"

        # Test Cancel by agent
        r2 = client.post("/api/v1/broker/requests", headers=AUTH_AGENT, json={"session_id": "s", "tool": "t"}).json()["request_id"]
        res_cancel = client.post(f"/api/v1/broker/requests/{r2}/cancel", headers={**AUTH_AGENT, "Content-Type": "application/json"})
        assert res_cancel.status_code == 200
        assert res_cancel.json()["status"] == "cancelled"

    def test_concurrent_decisions_race(self, tmp_path):
        fake_time = [1000.0]
        clock = lambda: fake_time[0]
        broker = ApprovalBroker(max_pending=5, max_ttl_seconds=300.0, clock=clock)
        client = _make_client(tmp_path, enable_broker=True, broker=broker)

        create_res = client.post("/api/v1/broker/requests", headers=AUTH_AGENT, json={"session_id": "s", "tool": "t"})
        req_id = create_res.json()["request_id"]
        req_hash = client.get(f"/api/v1/approvals/{req_id}", headers=AUTH_REVIEWER).json()["request_hash"]

        results = []

        def worker(decision):
            r = client.post(
                f"/api/v1/approvals/{req_id}/decision",
                headers=AUTH_REVIEWER,
                json={"decision": decision, "request_hash": req_hash, "confirm": True},
            )
            results.append(r.status_code)

        t1 = threading.Thread(target=worker, args=("approve",))
        t2 = threading.Thread(target=worker, args=("deny",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert 200 in results
        assert 409 in results

    def test_queue_full_503(self, tmp_path):
        client = _make_client(tmp_path, enable_broker=True)
        # Max pending is configured to 10
        for i in range(10):
            res = client.post("/api/v1/broker/requests", headers=AUTH_AGENT, json={"session_id": f"s{i}", "tool": "t"})
            assert res.status_code == 200

        res_full = client.post("/api/v1/broker/requests", headers=AUTH_AGENT, json={"session_id": "s_overflow", "tool": "t"})
        assert res_full.status_code == 503
        assert res_full.json()["code"] == "BROKER_FULL"

    def test_expiry_and_decision_after_expiry(self, tmp_path):
        fake_time = [1000.0]
        broker = ApprovalBroker(max_pending=10, max_ttl_seconds=300.0, clock=lambda: fake_time[0])
        client = _make_client(tmp_path, enable_broker=True, broker=broker)

        create_res = client.post("/api/v1/broker/requests", headers=AUTH_AGENT, json={"session_id": "s", "tool": "t", "ttl_seconds": 10.0})
        req_id = create_res.json()["request_id"]
        req_hash = client.get(f"/api/v1/approvals/{req_id}", headers=AUTH_REVIEWER).json()["request_hash"]

        # Advance fake time past expiry
        fake_time[0] += 15.0

        res_dec = client.post(
            f"/api/v1/approvals/{req_id}/decision",
            headers=AUTH_REVIEWER,
            json={"decision": "approve", "request_hash": req_hash, "confirm": True},
        )
        assert res_dec.status_code == 409
        assert res_dec.json()["code"] == "EXPIRED"


# ==============================================================================
# 3. Memory Privacy and Secret Redaction
# ==============================================================================

class TestMemoryPrivacy:
    def test_secrets_never_persisted_to_disk(self, tmp_path):
        fake_secret = "SECRET-TOKEN-0000-SUPER-CONFIDENTIAL"
        audit_path, review_path = _make_dbs(tmp_path, store_text=True)
        settings = Settings(
            audit_db=audit_path,
            review_db=review_path,
            policy=ROOT / "policies" / "example_agent.yaml",
            viewer_token=VIEWER_TOKEN,
            reviewer_token=REVIEWER_TOKEN,
            agent_token=AGENT_TOKEN,
            enable_broker=True,
            cors_origins=("http://localhost:5173",),
            store_text=True,
            allowed_hosts=("testserver",),
        )
        app = create_app(settings)
        client = TestClient(app, base_url="http://localhost")

        create_res = client.post(
            "/api/v1/broker/requests",
            headers=AUTH_AGENT,
            json={
                "session_id": "sess-priv",
                "tool": "make_payment",
                "values_preview": {"password": fake_secret},
            },
        )
        req_id = create_res.json()["request_id"]
        req_hash = client.get(f"/api/v1/approvals/{req_id}", headers=AUTH_REVIEWER).json()["request_hash"]

        # Decide
        client.post(
            f"/api/v1/approvals/{req_id}/decision",
            headers=AUTH_REVIEWER,
            json={"decision": "approve", "request_hash": req_hash, "confirm": True},
        )

        # Inspect sqlite bytes
        audit_bytes = audit_path.read_bytes()
        review_bytes = review_path.read_bytes()
        secret_bytes = fake_secret.encode("utf-8")

        assert secret_bytes not in audit_bytes
        assert secret_bytes not in review_bytes


# ==============================================================================
# 4. Sanitized View (Original vs Masked Pieces)
# ==============================================================================

class TestSanitizedView:
    def test_merge_spans_logic(self):
        # Overlapping and adjacent spans
        spans = [
            {"start": 5, "end": 10, "level": "medium"},
            {"start": 10, "end": 15, "level": "high"},   # adjacent to first
            {"start": 20, "end": 25, "level": "medium"},
            {"start": 22, "end": 28, "level": "medium"},  # overlapping with third
            {"start": 100, "end": 120, "level": "high"},  # outside text of length 50
        ]
        merged = merge_spans(spans, text_len=50)
        assert len(merged) == 2
        assert merged[0] == {"start": 5, "end": 15, "level": "high"}
        assert merged[1] == {"start": 20, "end": 28, "level": "medium"}

    def test_pieces_splitting_with_astral_emoji(self):
        text = "Hello 😊 world, beware of 😈 attack!"
        # Python character offsets:
        # "Hello " (0-6)
        # "😊" (6-7)
        # " world, beware of " (7-25)
        # "😈" (25-26)
        # " attack!" (26-34)
        spans = [
            {"start": 6, "end": 7, "level": "medium"},
            {"start": 25, "end": 26, "level": "high"},
        ]
        merged = merge_spans(spans, len(text))
        pieces = split_text_into_pieces(text, merged)
        assert "".join(p["text"] for p in pieces) == text
        assert pieces[1] == {"text": "😊", "level": "medium"}
        assert pieces[3] == {"text": "😈", "level": "high"}

    def test_view_endpoint_behavior(self, tmp_path):
        client = _make_client(tmp_path, store_text=True)
        # Get review item from fixture
        items = client.get("/api/v1/review/items", headers=AUTH_VIEWER).json()["items"]
        item_id = items[0]["id"]

        res = client.get(f"/api/v1/review/items/{item_id}/view", headers=AUTH_VIEWER)
        assert res.status_code == 200
        data = res.json()
        assert data["has_text"] is True
        assert data["spans_available"] is True
        assert data["untrusted_content"] is True
        assert data["render"] == "plain_text_only"
        assert len(data["original_pieces"]) > 0
        joined = "".join(p["text"] for p in data["original_pieces"])
        assert joined == "Hello world secret text"


# ==============================================================================
# 5. Review Store Additive Migration
# ==============================================================================

class TestReviewStoreMigration:
    def test_additive_migration_on_day12_db(self, tmp_path):
        db_path = tmp_path / "legacy_day12.db"
        with closing(sqlite3.connect(db_path)) as conn:
            conn.execute("""CREATE TABLE review_items(
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, session_id TEXT NOT NULL,
                item_type TEXT NOT NULL, tool TEXT, output_id TEXT, status TEXT NOT NULL, max_level TEXT,
                reason_codes TEXT NOT NULL, segment_ids TEXT NOT NULL, level_counts TEXT NOT NULL,
                text_sha256 TEXT, original_text TEXT, masked_text TEXT, text_truncated INTEGER NOT NULL DEFAULT 0
            )""")
            conn.execute("INSERT INTO review_items VALUES ('i1', '2026-01-01', '2035-01-01', 's1', 'held_output', 't1', 'o1', 'pending', 'high', '[]', '[]', '{}', 'hash', 'orig', 'masked', 0)")
            conn.commit()

        # Open with Day 13 ReviewStore
        store = ReviewStore(db_path, store_text=True)
        item = store.get("i1")
        assert item is not None
        assert item["id"] == "i1"
        assert item["spans"] == []

        # Running migration again is harmless
        store._migrate(store._connect())


# ==============================================================================
# 6. BrokerApprovalCallback Client and End-to-End Execution
# ==============================================================================

class TestBrokerApprovalCallback:
    def test_callback_refuses_non_loopback(self):
        with pytest.raises(ValueError, match="Refusing non-loopback"):
            BrokerApprovalCallback("http://external-site.com:8000", AGENT_TOKEN, allow_remote=False)

    def test_callback_repr_hides_token(self):
        cb = BrokerApprovalCallback("http://127.0.0.1:8000", AGENT_TOKEN)
        assert AGENT_TOKEN not in repr(cb)
        assert "<redacted>" in repr(cb)

    def test_callback_fails_closed_on_errors(self):
        cb = BrokerApprovalCallback("http://127.0.0.1:54321", AGENT_TOKEN, request_timeout=0.2)
        packet = ReviewPacket("r1", "s1", "t1", ("ASK",), "expl", (), (), {})
        # Server not running -> fails closed (returns False)
        assert cb(packet, 0.5) is False


class TestEndToEndApprovalWithRealFirewall:
    def test_end_to_end_flow(self, tmp_path):
        import uvicorn

        def get_free_port():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]

        port = get_free_port()
        audit_path, review_path = _make_dbs(tmp_path)
        settings = Settings(
            audit_db=audit_path,
            review_db=review_path,
            policy=ROOT / "policies" / "example_agent.yaml",
            viewer_token=VIEWER_TOKEN,
            reviewer_token=REVIEWER_TOKEN,
            agent_token=AGENT_TOKEN,
            enable_broker=True,
            host="127.0.0.1",
            port=port,
            cors_origins=("http://localhost:5173",),
            store_text=True,
        )

        app = create_app(settings)
        server_config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(server_config)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()

        # Wait for server ready
        with httpx.Client(timeout=2.0) as client:
            for _ in range(50):
                try:
                    if client.get(f"http://127.0.0.1:{port}/health").status_code == 200:
                        break
                except Exception:
                    time.sleep(0.05)

        callback = BrokerApprovalCallback(
            base_url=f"http://127.0.0.1:{port}",
            agent_token=AGENT_TOKEN,
            poll_wait=0.2,
            request_timeout=2.0,
        )

        audit_store = SQLiteAuditStore(audit_path)
        firewall = Firewall(
            policy=ROOT / "policies" / "example_agent.yaml",
            approval_callback=callback,
            audit_sink=audit_store,
        )

        session = Session(session_id="sess-e2e", user_task="Testing approval flow")
        audit_store.record_session(session.session_id, "1.0", "example_agent", session.user_task)

        # Background reviewer thread
        def reviewer_action(action_to_take):
            with httpx.Client(timeout=5.0) as client:
                for _ in range(40):
                    r = client.get(f"http://127.0.0.1:{port}/api/v1/approvals?status=pending", headers=AUTH_REVIEWER)
                    if r.status_code == 200 and r.json().get("items"):
                        req_id = r.json()["items"][0]["id"]
                        detail = client.get(f"http://127.0.0.1:{port}/api/v1/approvals/{req_id}", headers=AUTH_REVIEWER).json()
                        req_hash = detail.get("request_hash")
                        if req_hash:
                            confirm = True if action_to_take == "approve" else False
                            client.post(
                                f"http://127.0.0.1:{port}/api/v1/approvals/{req_id}/decision",
                                headers={**AUTH_REVIEWER, "Content-Type": "application/json"},
                                json={"decision": action_to_take, "request_hash": req_hash, "confirm": confirm},
                            )
                            break
                    time.sleep(0.1)

        # 1. Test Approved call
        t_rev = threading.Thread(target=reviewer_action, args=("approve",))
        t_rev.start()
        dec1 = firewall.authorize_tool_call(session, "make_payment", {"account": "ACCT-0001", "amount": "50.00"})
        t_rev.join()
        assert dec1.action == "ALLOW"

        # 2. Test Denied call
        t_rev2 = threading.Thread(target=reviewer_action, args=("deny",))
        t_rev2.start()
        dec2 = firewall.authorize_tool_call(session, "make_payment", {"account": "ACCT-0002", "amount": "50.00"})
        t_rev2.join()
        assert dec2.action == "DENIED"

        server.should_exit = True
        audit_store.close()

        # Audit hash chain verification
        ok, bad_id = SQLiteAuditStore(audit_path).verify_chain()
        assert ok is True


# ==============================================================================
# 7. Rate Limiting and Failure Throttling
# ==============================================================================

class TestRateLimitingAndThrottle:
    def test_action_rate_limiter_with_fake_clock(self):
        fake_time = [100.0]
        limiter = ActionRateLimiter(clock=lambda: fake_time[0], limit=3, window=10.0)

        assert limiter.is_allowed("user1") is True
        assert limiter.is_allowed("user1") is True
        assert limiter.is_allowed("user1") is True
        assert limiter.is_allowed("user1") is False

        # Advance fake time past window
        fake_time[0] += 11.0
        assert limiter.is_allowed("user1") is True

    def test_failed_auth_throttle_on_new_routes(self, tmp_path):
        current_time = 100.0
        throttle = FailureThrottle(clock=lambda: current_time, limit=5, window=60.0, cooldown=60.0)
        client = _make_client(tmp_path, enable_broker=True, throttle=throttle)

        # 6 failures (more than limit of 5)
        for _ in range(6):
            r = client.get("/api/v1/approvals", headers={"Authorization": "Bearer wrong-token-1234567890123456"})
            assert r.status_code == 401

        # 7th attempt triggers 429
        r_throttled = client.get("/api/v1/approvals", headers={"Authorization": "Bearer wrong-token-1234567890123456"})
        assert r_throttled.status_code == 429
        assert r_throttled.json()["code"] == "AUTH_THROTTLED"


# ==============================================================================
# 8. Import Hygiene
# ==============================================================================

class TestImportHygiene:
    def test_firewall_server_imports_no_heavy_libraries(self):
        import sys

        heavy = ["torch", "transformers", "google"]
        for mod in heavy:
            assert not any(loaded.startswith(mod) for loaded in sys.modules)

    def test_firewall_core_loads_no_fastapi(self):
        # Subprocess to check clean import of firewall
        import subprocess

        cmd = [sys.executable, "-c", "import sys, firewall; assert 'fastapi' not in sys.modules; assert 'firewall_server' not in sys.modules"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0
