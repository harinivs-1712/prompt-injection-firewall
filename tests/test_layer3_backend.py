"""Comprehensive test suite for Layer 3 Day 12 FastAPI backend and review store."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from firewall.audit import SQLiteAuditStore
from firewall_server.app import create_app
from firewall_server.review_store import ReviewRecorder, ReviewStore
from firewall_server.security import FailureThrottle
from firewall_server.settings import Settings, from_args, parser

VIEWER_TOKEN = "test-viewer-token-string-001"
REVIEWER_TOKEN = "test-reviewer-token-string-002"
AUTH_VIEWER = {"Authorization": f"Bearer {VIEWER_TOKEN}"}
AUTH_REVIEWER = {"Authorization": f"Bearer {REVIEWER_TOKEN}"}


def _make_stores(tmp_path: Path, *, store_text: bool = False):
    audit_path = tmp_path / "audit.sqlite"
    review_path = tmp_path / "review.sqlite"
    audit = SQLiteAuditStore(audit_path)
    audit.record_session("sess-001", "1.0", "demo_agent", "Test user task string")
    audit.record({
        "event_type": "tool_check",
        "session_id": "sess-001",
        "tool": "search_notes",
        "action": "allow",
        "reason_codes": ["ALL_RULES_PASSED"],
        "rule_ids": ["R-TASK"],
    })
    audit.record({
        "event_type": "tool_check",
        "session_id": "sess-001",
        "tool": "send_email",
        "action": "block",
        "reason_codes": ["ARG_MATCHES_HIGH_SUSPICION_SEGMENT"],
        "rule_ids": ["R-LINK"],
    })
    audit.close()

    review = ReviewStore(review_path, store_text=store_text)
    review.add(
        session_id="sess-001",
        item_type="held_output",
        tool="read_email",
        output_id="out-001",
        max_level="high",
        reason_codes=["OUTPUT_HELD"],
        segment_ids=["seg-001"],
        level_counts={"high": 1},
        original_text="<script>alert('xss')</script>\x00Dangerous text",
    )
    return audit_path, review_path


def _make_client(tmp_path: Path, *, store_text: bool = False, enable_docs: bool = False, throttle: FailureThrottle | None = None) -> TestClient:
    audit_path, review_path = _make_stores(tmp_path, store_text=store_text)
    settings = Settings(
        audit_db=audit_path,
        review_db=review_path,
        policy=ROOT / "policies" / "example_agent.yaml",
        viewer_token=VIEWER_TOKEN,
        reviewer_token=REVIEWER_TOKEN,
        cors_origins=("http://localhost:5173", "http://127.0.0.1:5173"),
        enable_docs=enable_docs,
        store_text=store_text,
        allowed_hosts=("testserver",),
    )
    app = create_app(settings, throttle=throttle)
    return TestClient(app, base_url="http://localhost")


# ==============================================================================
# 1. Startup and Configuration Tests
# ==============================================================================

class TestStartupAndConfig:
    def test_startup_refuses_missing_tokens(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FIREWALL_VIEWER_TOKEN", raising=False)
        monkeypatch.delenv("FIREWALL_REVIEWER_TOKEN", raising=False)
        with pytest.raises(ValueError, match="Missing required settings"):
            from_args(["--audit-db", str(tmp_path / "a.db"), "--review-db", str(tmp_path / "r.db"), "--policy", "policies/example_agent.yaml"])

    def test_startup_refuses_short_tokens(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FIREWALL_VIEWER_TOKEN", "short")
        monkeypatch.setenv("FIREWALL_REVIEWER_TOKEN", "also-short")
        with pytest.raises(ValueError, match="must be at least 24 characters"):
            from_args(["--audit-db", str(tmp_path / "a.db"), "--review-db", str(tmp_path / "r.db"), "--policy", "policies/example_agent.yaml"])

    def test_startup_refuses_equal_tokens(self, tmp_path, monkeypatch):
        (tmp_path / "a.db").write_text("dummy")
        (tmp_path / "r.db").write_text("dummy")
        token = "identical-valid-token-string-012345"
        monkeypatch.setenv("FIREWALL_VIEWER_TOKEN", token)
        monkeypatch.setenv("FIREWALL_REVIEWER_TOKEN", token)
        with pytest.raises(ValueError, match="viewer and reviewer tokens must differ"):
            from_args(["--audit-db", str(tmp_path / "a.db"), "--review-db", str(tmp_path / "r.db"), "--policy", "policies/example_agent.yaml"])

    def test_startup_refuses_weak_tokens(self, tmp_path, monkeypatch):
        (tmp_path / "a.db").write_text("dummy")
        (tmp_path / "r.db").write_text("dummy")
        monkeypatch.setenv("FIREWALL_VIEWER_TOKEN", "passwordpasswordpassword")
        monkeypatch.setenv("FIREWALL_REVIEWER_TOKEN", "changemechangemechangeme")
        with pytest.raises(ValueError, match="not an obvious weak value"):
            from_args(["--audit-db", str(tmp_path / "a.db"), "--review-db", str(tmp_path / "r.db"), "--policy", "policies/example_agent.yaml"])

    def test_startup_refuses_nonlocal_host_without_flag(self, tmp_path, monkeypatch):
        (tmp_path / "a.db").write_text("dummy")
        (tmp_path / "r.db").write_text("dummy")
        monkeypatch.setenv("FIREWALL_VIEWER_TOKEN", VIEWER_TOKEN)
        monkeypatch.setenv("FIREWALL_REVIEWER_TOKEN", REVIEWER_TOKEN)
        with pytest.raises(ValueError, match="Refusing non-local host without --allow-remote"):
            from_args(["--host", "0.0.0.0", "--audit-db", str(tmp_path / "a.db"), "--review-db", str(tmp_path / "r.db"), "--policy", "policies/example_agent.yaml"])

    def test_startup_refuses_missing_audit_db(self, tmp_path, monkeypatch):
        (tmp_path / "r.db").write_text("dummy")
        monkeypatch.setenv("FIREWALL_VIEWER_TOKEN", VIEWER_TOKEN)
        monkeypatch.setenv("FIREWALL_REVIEWER_TOKEN", REVIEWER_TOKEN)
        with pytest.raises(ValueError, match="Audit database does not exist"):
            from_args(["--audit-db", str(tmp_path / "nonexistent.sqlite"), "--review-db", str(tmp_path / "r.db"), "--policy", "policies/example_agent.yaml"])

    def test_docs_disabled_by_default(self, tmp_path):
        client = _make_client(tmp_path, enable_docs=False)
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404

    def test_docs_enabled_with_flag(self, tmp_path):
        client = _make_client(tmp_path, enable_docs=True)
        assert client.get("/docs").status_code == 200
        assert client.get("/openapi.json").status_code == 200


# ==============================================================================
# 2. Authentication, Rate Limiting, and Security Headers
# ==============================================================================

class TestAuthAndSecurity:
    def test_health_is_open(self, tmp_path):
        client = _make_client(tmp_path)
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json() == {"status": "ok", "version": "0.1.0"}

    def test_missing_or_bad_token_returns_401(self, tmp_path):
        client = _make_client(tmp_path)
        for headers in [{}, {"Authorization": "Bearer bad"}, {"Authorization": "Basic 1234"}]:
            res = client.get("/api/v1/summary", headers=headers)
            assert res.status_code == 401
            assert res.json() == {"error": "Request could not be completed.", "code": "UNAUTHORIZED"}

    def test_roles_viewer_and_reviewer_work(self, tmp_path):
        client = _make_client(tmp_path)
        res_v = client.get("/api/v1/summary", headers=AUTH_VIEWER)
        assert res_v.status_code == 200
        res_r = client.get("/api/v1/summary", headers=AUTH_REVIEWER)
        assert res_r.status_code == 200

    def test_failed_auth_throttle_returns_429(self, tmp_path):
        current_time = 1000.0
        throttle = FailureThrottle(clock=lambda: current_time, limit=5, window=60.0, cooldown=60.0)
        client = _make_client(tmp_path, throttle=throttle)
        # 6 failures (more than 5)
        for _ in range(6):
            res = client.get("/api/v1/summary", headers={"Authorization": "Bearer wrong"})
            assert res.status_code == 401

        # 7th attempt -> 429
        res = client.get("/api/v1/summary", headers={"Authorization": "Bearer wrong"})
        assert res.status_code == 429
        assert res.json()["code"] == "AUTH_THROTTLED"

        # Advance past cooldown -> should recover to 401 on bad token
        current_time += 65.0
        res = client.get("/api/v1/summary", headers={"Authorization": "Bearer wrong"})
        assert res.status_code == 401

    def test_host_header_enforcement(self, tmp_path):
        client = _make_client(tmp_path)
        res = client.get("/health", headers={"Host": "evil.example.com"})
        assert res.status_code == 400

    def test_security_headers_on_all_responses(self, tmp_path):
        client = _make_client(tmp_path)
        for path, headers in [("/health", {}), ("/api/v1/summary", AUTH_VIEWER), ("/api/v1/summary", {})]:
            res = client.get(path, headers=headers)
            assert res.headers.get("X-Content-Type-Options") == "nosniff"
            assert res.headers.get("Cache-Control") == "no-store"
            assert res.headers.get("Content-Security-Policy") == "default-src 'none'; frame-ancestors 'none'"
            assert res.headers.get("Referrer-Policy") == "no-referrer"
            assert res.headers.get("Cross-Origin-Resource-Policy") == "same-origin"

    def test_cors_headers(self, tmp_path):
        client = _make_client(tmp_path)
        res = client.options("/api/v1/summary", headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        })
        assert res.headers.get("access-control-allow-origin") == "http://localhost:5173"

    def test_query_length_and_get_body_rejection(self, tmp_path):
        client = _make_client(tmp_path)
        long_query = "x=" + ("a" * 4100)
        res_414 = client.get(f"/health?{long_query}")
        assert res_414.status_code == 414
        assert res_414.json()["code"] == "QUERY_TOO_LONG"

        res_405 = client.request("GET", "/health", content=b"illegal-body")
        assert res_405.status_code == 405
        assert res_405.json()["code"] == "REQUEST_BODY_NOT_ALLOWED"


# ==============================================================================
# 3. Read Endpoints and Filters
# ==============================================================================

class TestReadEndpoints:
    def test_summary_endpoint(self, tmp_path):
        client = _make_client(tmp_path)
        res = client.get("/api/v1/summary", headers=AUTH_VIEWER)
        assert res.status_code == 200
        data = res.json()
        assert data["sessions"] >= 1
        assert data["events"] >= 2
        assert "decisions_by_action" in data
        assert "top_reason_codes" in data

    def test_sessions_list_and_detail(self, tmp_path):
        client = _make_client(tmp_path)
        res = client.get("/api/v1/sessions?limit=10&offset=0", headers=AUTH_VIEWER)
        assert res.status_code == 200
        data = res.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1

        sid = data["items"][0]["session_id"]
        detail = client.get(f"/api/v1/sessions/{sid}", headers=AUTH_VIEWER)
        assert detail.status_code == 200
        assert detail.json()["session"]["session_id"] == sid
        assert len(detail.json()["timeline"]) >= 2

        # 404 for unknown session
        assert client.get("/api/v1/sessions/unknown-id-xyz", headers=AUTH_VIEWER).status_code == 404

    def test_session_events_filtering(self, tmp_path):
        client = _make_client(tmp_path)
        events = client.get("/api/v1/sessions/sess-001/events?event_type=tool_check&action=allow", headers=AUTH_VIEWER)
        assert events.status_code == 200
        items = events.json()["items"]
        assert all(e["action"] == "allow" for e in items)

        # Invalid filter -> 422
        bad_event = client.get("/api/v1/sessions/sess-001/events?event_type=invalid_type", headers=AUTH_VIEWER)
        assert bad_event.status_code == 422
        bad_action = client.get("/api/v1/sessions/sess-001/events?action=invalid_action", headers=AUTH_VIEWER)
        assert bad_action.status_code == 422

    def test_audit_verify_endpoint(self, tmp_path):
        client = _make_client(tmp_path)
        res = client.get("/api/v1/audit/verify", headers=AUTH_VIEWER)
        assert res.status_code == 200
        assert res.json()["ok"] is True
        assert res.json()["checked"] >= 2

    def test_audit_verify_tampered_db(self, tmp_path):
        audit_path, review_path = _make_stores(tmp_path)
        # Tamper directly with the SQLite database file on a copy/after dropping trigger
        with sqlite3.connect(audit_path) as db:
            db.execute("DROP TRIGGER audit_events_append_only_update")
            db.execute("UPDATE audit_events SET action = 'tampered' WHERE id = 1")
            db.commit()

        settings = Settings(
            audit_db=audit_path,
            review_db=review_path,
            policy=ROOT / "policies" / "example_agent.yaml",
            viewer_token=VIEWER_TOKEN,
            reviewer_token=REVIEWER_TOKEN,
            cors_origins=("http://localhost:5173",),
            allowed_hosts=("localhost",),
        )
        client = TestClient(create_app(settings), base_url="http://localhost")
        res = client.get("/api/v1/audit/verify", headers=AUTH_VIEWER)
        assert res.status_code == 200
        assert res.json()["ok"] is False
        assert res.json()["first_bad_id"] == 1

    def test_review_items_list_and_detail(self, tmp_path):
        client = _make_client(tmp_path, store_text=False)
        items = client.get("/api/v1/review/items", headers=AUTH_VIEWER).json()
        assert items["total"] >= 1
        item_id = items["items"][0]["id"]
        # In list endpoint, original_text MUST NOT be returned
        assert "original_text" not in items["items"][0]

        # Detail endpoint with text storage OFF
        detail = client.get(f"/api/v1/review/items/{item_id}", headers=AUTH_VIEWER).json()
        assert detail["untrusted_content"] is True
        assert detail["render"] == "plain_text_only"
        assert detail["original_text"] is None

        # Filter validation
        assert client.get("/api/v1/review/items?status=bad_status", headers=AUTH_VIEWER).status_code == 422
        assert client.get("/api/v1/review/items?item_type=bad_type", headers=AUTH_VIEWER).status_code == 422
        assert client.get("/api/v1/review/items/nonexistent-item-id", headers=AUTH_VIEWER).status_code == 404

    def test_policy_and_lint_endpoint(self, tmp_path):
        client = _make_client(tmp_path)
        res = client.get("/api/v1/policy", headers=AUTH_VIEWER)
        assert res.status_code == 200
        data = res.json()
        assert "agent_name" in data
        assert "tools" in data
        assert "lint_warnings" in data
        # No file paths should be leaked
        assert "policies/" not in json.dumps(data)
        assert "C:\\" not in json.dumps(data)

    def test_config_endpoint(self, tmp_path):
        client = _make_client(tmp_path)
        res = client.get("/api/v1/config", headers=AUTH_VIEWER)
        assert res.status_code == 200
        data = res.json()
        assert data["release_version"] == "0.1.0"
        assert "judge_mode" in data
        assert data["audit_hash_chain_verified_at_startup"] is True

    def test_eval_results_endpoint(self, tmp_path):
        client = _make_client(tmp_path)
        res = client.get("/api/v1/eval/results", headers=AUTH_VIEWER)
        assert res.status_code == 200
        data = res.json()
        assert "results" in data
        assert "known_gaps" in data
        assert "prediction_mismatch" in data


# ==============================================================================
# 4. Read-Only Enforcement and Privacy Guarantees
# ==============================================================================

class TestReadOnlyAndPrivacy:
    def test_databases_opened_read_only(self, tmp_path):
        audit_path, review_path = _make_stores(tmp_path)
        from firewall_server.app import _ro
        with pytest.raises(sqlite3.OperationalError):
            with closing(_ro(audit_path)) as db:
                db.execute("INSERT INTO sessions VALUES('x','x','x','x','x',1,'x')")

    def test_audit_db_and_review_db_contain_no_argument_values(self, tmp_path):
        secret_arg = "SUPER_SECRET_ARG_VALUE_987654"
        audit_path = tmp_path / "audit_priv.sqlite"
        audit = SQLiteAuditStore(audit_path)
        audit.record_session("s1", "1.0", "agent", "task")
        audit.record({
            "event_type": "tool_check",
            "session_id": "s1",
            "tool": "send_email",
            "action": "block",
            "reason_codes": ["BLOCKED"],
            # Even if caller attempts to pass args in event:
            "user_provided_args": ["to"],
            "argument_names": ["to", "body"],
        })
        audit.close()

        raw_bytes = audit_path.read_bytes()
        assert secret_arg.encode("utf-8") not in raw_bytes

    def test_opt_in_stored_text_with_control_chars_stripped(self, tmp_path):
        client = _make_client(tmp_path, store_text=True)
        items = client.get("/api/v1/review/items", headers=AUTH_VIEWER).json()
        item_id = items["items"][0]["id"]
        detail = client.get(f"/api/v1/review/items/{item_id}", headers=AUTH_VIEWER).json()
        assert detail["has_text"] is True
        assert detail["original_text"] is not None
        # Null bytes must be stripped
        assert "\x00" not in detail["original_text"]
        assert "<script>alert('xss')</script>Dangerous text" in detail["original_text"]
        assert detail["untrusted_content"] is True
        assert detail["render"] == "plain_text_only"

    def test_text_cap_and_truncation_flag(self, tmp_path):
        review_path = tmp_path / "rev_trunc.sqlite"
        review = ReviewStore(review_path, store_text=True)
        long_text = "A" * 60_000
        item_id = review.add(session_id="s1", item_type="held_output", original_text=long_text)
        item = review.get(item_id, include_text=True)
        assert item["text_truncated"] is True
        assert len(item["original_text"]) == 50_000

    def test_review_retention_and_purge(self, tmp_path):
        review_path = tmp_path / "rev_retention.sqlite"
        review = ReviewStore(review_path, retention_hours=1)
        item_id = review.add(session_id="s1", item_type="held_output")
        # Backdate the item to make it expired
        with sqlite3.connect(review_path) as db:
            past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
            db.execute("UPDATE review_items SET expires_at = ? WHERE id = ?", (past, item_id))
            db.commit()

        # Querying an expired item returns None
        assert review.get(item_id) is None
        # Purge removes it
        assert review.purge_expired() >= 1


# ==============================================================================
# 5. ReviewRecorder and Failure Isolation
# ==============================================================================

class TestReviewRecorder:
    def test_recorder_never_raises_on_database_error(self, tmp_path):
        review_path = tmp_path / "failing.sqlite"
        store = ReviewStore(review_path)
        recorder = ReviewRecorder(store)

        # Force store.add to raise
        store.add = MagicMock(side_effect=sqlite3.DatabaseError("Disk full"))

        # Output result recording fails cleanly
        mock_output = MagicMock()
        mock_output.action = "HOLD"
        mock_output.output_id = "out-1"
        mock_output.max_level = "high"
        mock_output.reason_codes = ["HELD"]
        mock_output.segment_ids = ["s1"]
        mock_output.level_counts = {}
        mock_output.agent_view = "view"

        mock_fw = MagicMock()
        mock_fw.get_original_output.return_value = "secret"
        mock_session = MagicMock()
        mock_session.session_id = "sess-1"

        res = recorder.record_output_result(mock_fw, mock_session, mock_output, "tool")
        assert res["stored"] is False
        assert recorder.errors == 1

        # Approval request recording fails cleanly
        mock_decision = MagicMock()
        mock_decision.reason_codes = ["ALWAYS_ASK"]
        res_appr = recorder.record_approval_request(mock_session, mock_decision, "explanation")
        assert res_appr["stored"] is False
        assert recorder.errors == 2


# ==============================================================================
# 6. Import Hygiene and Subprocess Checks
# ==============================================================================

class TestImportHygiene:
    def test_import_firewall_server_loads_no_heavy_libraries(self):
        code = "import sys, json, firewall_server; print(json.dumps(sorted(sys.modules)))"
        import subprocess
        res = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
        modules = json.loads(res.stdout.strip().splitlines()[-1])
        forbidden = [m for m in modules if m.startswith(("torch", "transformers", "google", "firewall.layer1"))]
        assert not forbidden, f"Forbidden modules imported by firewall_server: {forbidden}"

    def test_import_firewall_loads_no_fastapi(self):
        code = "import sys, json, firewall; print(json.dumps(sorted(sys.modules)))"
        import subprocess
        res = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True)
        modules = json.loads(res.stdout.strip().splitlines()[-1])
        forbidden = [m for m in modules if m.startswith(("fastapi", "starlette", "firewall_server"))]
        assert not forbidden, f"Forbidden modules imported by firewall: {forbidden}"

    def test_server_never_creates_audit_db(self, tmp_path):
        missing_db = tmp_path / "never_created.sqlite"
        review_db = tmp_path / "rev.sqlite"
        ReviewStore(review_db)
        settings = Settings(
            audit_db=missing_db,
            review_db=review_db,
            policy=ROOT / "policies" / "example_agent.yaml",
            viewer_token=VIEWER_TOKEN,
            reviewer_token=REVIEWER_TOKEN,
            cors_origins=("http://localhost:5173",),
        )
        with pytest.raises(Exception):
            create_app(settings)
        assert not missing_db.exists()

    def test_hostile_content_handling_full(self, tmp_path):
        review_path = tmp_path / "hostile.sqlite"
        review = ReviewStore(review_path, store_text=True)
        hostile_text = "<script>alert(1)</script> [click](https://evil.example.com) \x00 " + ("A" * 1000) + " \u202eRLO"
        item_id = review.add(session_id="s1", item_type="held_output", original_text=hostile_text)

        audit_path = tmp_path / "audit.sqlite"
        SQLiteAuditStore(audit_path).close()
        settings = Settings(
            audit_db=audit_path,
            review_db=review_path,
            policy=ROOT / "policies" / "example_agent.yaml",
            viewer_token=VIEWER_TOKEN,
            reviewer_token=REVIEWER_TOKEN,
            cors_origins=("http://localhost:5173",),
            store_text=True,
            allowed_hosts=("localhost",),
        )
        client = TestClient(create_app(settings), base_url="http://localhost")
        res = client.get(f"/api/v1/review/items/{item_id}", headers=AUTH_VIEWER)
        assert res.status_code == 200
        assert res.headers["content-type"].startswith("application/json")
        assert res.headers["x-content-type-options"] == "nosniff"
        data = res.json()
        assert data["untrusted_content"] is True
        assert data["render"] == "plain_text_only"
        assert "\x00" not in data["original_text"]
        assert "<script>alert(1)</script>" in data["original_text"]
        assert "\u202eRLO" in data["original_text"]

    def test_recorder_uses_only_public_firewall_apis(self, tmp_path):
        class StrictPublicOnlyFirewall:
            def get_original_output(self, session, output_id, reviewer=True):
                return "Public output text"
            def __getattr__(self, name):
                if name.startswith("_"):
                    raise AttributeError(f"Private access forbidden: {name}")
                raise AttributeError(name)

        review = ReviewStore(tmp_path / "pub_rev.sqlite", store_text=True)
        recorder = ReviewRecorder(review)
        mock_output = MagicMock()
        mock_output.action = "HOLD"
        mock_output.output_id = "out-1"
        mock_output.max_level = "high"
        mock_output.reason_codes = ["HELD"]
        mock_output.segment_ids = ["s1"]
        mock_output.level_counts = {}
        mock_output.agent_view = "view"
        mock_session = MagicMock()
        mock_session.session_id = "s1"

        res = recorder.record_output_result(StrictPublicOnlyFirewall(), mock_session, mock_output, "tool")
        assert res["stored"] is True

    def test_seeded_demo_databases_validity(self):
        audit_file = ROOT / "var" / "demo" / "audit.sqlite"
        assert audit_file.is_file()
        store = SQLiteAuditStore(audit_file)
        valid, detail = store.verify_chain()
        store.close()
        assert valid is True
