"""FastAPI application factory for the localhost-only firewall review and approval API."""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from collections import Counter
from contextlib import closing
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from firewall.__version__ import __version__
from firewall.lint import lint_policy
from firewall.policy import load_policy
from firewall_server.broker import (
    AlreadyDecidedError,
    ApprovalBroker,
    BrokerFullError,
    HashMismatchError,
    RequestExpiredError,
    RequestNotFoundError,
)
from firewall_server.review_store import ReviewStore
from firewall_server.security import (
    ActionRateLimiter,
    FailureThrottle,
    TokenRedactionFilter,
    auth_guard,
    bearer,
    request_id,
    role_dependency,
)
from firewall_server.settings import Settings
from firewall_server.view import build_masked_pieces, merge_spans, split_text_into_pieces

ROOT = Path(__file__).resolve().parents[1]
SAFE_EVENT_TYPES = {
    "session_started", "tool_check", "tool_authorized", "approval_requested",
    "approval_outcome", "output_inspected", "tool_output_inspection",
    "loop_guard_triggered", "session_halted", "session_resumed", "audit_event_rejected",
}
SAFE_ACTIONS = {
    "allow", "ask", "block", "denied", "pass", "mask", "hold",
    "ALLOW", "BLOCK", "DENIED", "PASS", "MASK", "HOLD",
}


class BrokerRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    tool: str
    reason_codes: list[str] = Field(default_factory=list)
    explanation: str = ""
    evidence_summary: list[dict[str, Any]] = Field(default_factory=list)
    sensitivity_flags: list[str] = Field(default_factory=list)
    values_preview: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: float = 300.0


class BrokerDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "deny"]
    request_hash: str
    confirm: bool = False


class _StrictResponse(BaseModel):
    """Base for broker responses exposed in the generated API schema."""

    model_config = ConfigDict(extra="forbid")


class BrokerCreatedOut(_StrictResponse):
    request_id: str
    expires_at: str


class BrokerStatusOut(_StrictResponse):
    status: Literal["pending", "approved", "denied", "expired", "cancelled"]


class ApprovalListItemOut(_StrictResponse):
    id: str
    session_id: str
    tool: str
    reason_codes: list[str]
    created_at: str
    expires_at: str
    seconds_remaining: int
    status: Literal["pending", "approved", "denied", "expired", "cancelled"]


class ApprovalListOut(_StrictResponse):
    items: list[ApprovalListItemOut]
    total: int
    limit: int
    offset: int


class ApprovalDetailOut(ApprovalListItemOut):
    # Present only while pending. Terminal responses retain metadata only.
    explanation: str | None = None
    evidence_summary: list[dict[str, Any]] | None = None
    sensitivity_flags: list[str] | None = None
    values_preview: dict[str, str] | None = None
    request_hash: str | None = None
    decided_at: str | None = None
    decided_by_role: str | None = None
    time_to_decision_ms: int | None = None


class ApprovalDecisionOut(_StrictResponse):
    status: Literal["approved", "denied"]
    request_id: str


class ApprovalStatsOut(_StrictResponse):
    counts_by_outcome: dict[str, int]
    median_time_to_decision_ms: int | None
    expired_count: int
    total_requests: int


def _ro(path: Path):
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    db.execute("PRAGMA query_only=ON")
    return db


def _rows(path: Path, sql: str, values=()):
    with closing(_ro(path)) as db:
        db.row_factory = sqlite3.Row
        return [dict(item) for item in db.execute(sql, values)]


def _count(path: Path, table: str, where="", values=()):
    with closing(_ro(path)) as db:
        return int(db.execute(f"SELECT count(*) FROM {table}" + where, values).fetchone()[0])


def _page(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=1_000_000)):
    return limit, offset


def _clean_event(row):
    for key in ("reason_codes", "rule_ids", "evidence", "counts"):
        try:
            row[key] = json.loads(row[key])
        except Exception:
            row[key] = [] if key != "counts" else {}
    return row


def _verify(path: Path, cap: int):
    import hashlib
    from firewall.audit import _canonical

    with closing(_ro(path)) as db:
        db.row_factory = sqlite3.Row
        total = int(db.execute("SELECT count(*) FROM audit_events").fetchone()[0])
        if total > cap:
            return {"ok": False, "checked": 0, "first_bad_id": None, "message": "audit table exceeds verification cap"}
        previous, checked = "", 0
        for row in db.execute("SELECT * FROM audit_events ORDER BY id"):
            record = {
                "ts": row["ts"],
                "session_id": row["session_id"],
                "event_type": row["event_type"],
                "tool": row["tool"],
                "action": row["action"],
                "reason_codes": json.loads(row["reason_codes"]),
                "rule_ids": json.loads(row["rule_ids"]),
                "link_level": row["link_level"],
                "evidence": json.loads(row["evidence"]),
                "approval_outcome": row["approval_outcome"],
                "output_id": row["output_id"],
                "max_level": row["max_level"],
                "counts": json.loads(row["counts"]),
            }
            actual = hashlib.sha256((previous + _canonical(record)).encode()).hexdigest()
            checked += 1
            if row["prev_hash"] != previous or row["row_hash"] != actual:
                return {"ok": False, "checked": checked, "first_bad_id": row["id"], "message": "hash-chain mismatch"}
            previous = actual
    return {"ok": True, "checked": checked, "first_bad_id": None, "message": "hash chain verified"}


def create_app(
    settings: Settings,
    throttle: FailureThrottle | None = None,
    rate_limiter: ActionRateLimiter | None = None,
    broker: ApprovalBroker | None = None,
) -> FastAPI:
    docs = "/docs" if settings.enable_docs else None
    app = FastAPI(
        title="Firewall review API",
        docs_url=docs,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    allowed_hosts = ["localhost", "127.0.0.1", "[::1]", "::1", *settings.allowed_hosts]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        allow_credentials=False,
    )

    throttle = throttle or FailureThrottle()
    rate_limiter = rate_limiter or ActionRateLimiter()

    require_viewer = auth_guard(settings, throttle, {"viewer", "reviewer"})
    require_reviewer = auth_guard(settings, throttle, {"reviewer"})
    require_agent = auth_guard(settings, throttle, {"agent"})

    # Review store: writable connection for broker updates, readonly for pure audit
    review = ReviewStore(
        settings.review_db,
        store_text=settings.store_text,
        retention_hours=settings.retention_hours,
        readonly=False if settings.enable_broker else True,
    )

    if settings.enable_broker:
        broker = broker or ApprovalBroker(
            review_store=review,
            max_pending=settings.broker_max_pending,
            max_ttl_seconds=settings.broker_max_ttl_seconds,
        )
    else:
        broker = None

    app.state.settings = settings
    app.state.review = review
    app.state.broker = broker
    app.state.rate_limiter = rate_limiter
    app.state.throttle = throttle
    app.state.audit_verified = _verify(settings.audit_db, settings.audit_verify_cap)["ok"]

    if broker is not None:
        @app.on_event("startup")
        async def start_broker_expiry_sweeper() -> None:
            broker.start_sweeper()

        @app.on_event("shutdown")
        async def stop_broker_expiry_sweeper() -> None:
            broker.stop_sweeper()

    tokens = [settings.viewer_token, settings.reviewer_token]
    if settings.agent_token:
        tokens.append(settings.agent_token)
    logging.getLogger().addFilter(TokenRedactionFilter(tuple(tokens)))

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        return JSONResponse(
            {"error": detail.get("error", "Request could not be completed."), "code": detail.get("code", "REQUEST_ERROR")},
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            {"error": "Validation error.", "code": "VALIDATION_ERROR"},
            status_code=422,
        )

    @app.middleware("http")
    async def headers(request: Request, call_next):
        start, rid = time.monotonic(), request_id()
        request.state.request_id = rid

        if len(request.url.query) > 4096:
            response = JSONResponse({"error": "Request could not be completed.", "code": "QUERY_TOO_LONG"}, status_code=414)
        elif request.method == "GET" and int(request.headers.get("content-length", "0") or 0) > 0:
            response = JSONResponse({"error": "Request could not be completed.", "code": "REQUEST_BODY_NOT_ALLOWED"}, status_code=405)
        elif request.url.path.startswith("/api/v1/broker/") and request.headers.get("origin"):
            response = JSONResponse({"error": "Origin header not allowed on agent endpoints.", "code": "FORBIDDEN"}, status_code=403)
        elif request.method == "POST":
            content_type = request.headers.get("content-type", "").lower()
            if not content_type.startswith("application/json"):
                response = JSONResponse({"error": "Content-Type must be application/json.", "code": "UNSUPPORTED_MEDIA_TYPE"}, status_code=415)
            else:
                body_bytes = await request.body()
                if len(body_bytes) > settings.broker_body_max_bytes:
                    response = JSONResponse({"error": "Request body too large.", "code": "REQUEST_TOO_LARGE"}, status_code=413)
                else:
                    try:
                        response = await call_next(request)
                    except HTTPException as exc:
                        detail = exc.detail if isinstance(exc.detail, dict) else {}
                        response = JSONResponse({"error": detail.get("error", "Request could not be completed."), "code": detail.get("code", "REQUEST_ERROR")}, status_code=exc.status_code)
                    except Exception as exc:
                        logging.getLogger("firewall_server").error("request failed class=%s id=%s", type(exc).__name__, rid)
                        response = JSONResponse({"error": "Request could not be completed.", "code": "INTERNAL_ERROR"}, status_code=500)
        else:
            try:
                response = await call_next(request)
            except HTTPException as exc:
                detail = exc.detail if isinstance(exc.detail, dict) else {}
                response = JSONResponse({"error": detail.get("error", "Request could not be completed."), "code": detail.get("code", "REQUEST_ERROR")}, status_code=exc.status_code)
            except Exception as exc:
                logging.getLogger("firewall_server").error("request failed class=%s id=%s", type(exc).__name__, rid)
                response = JSONResponse({"error": "Request could not be completed.", "code": "INTERNAL_ERROR"}, status_code=500)

        response.headers.update({
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Request-ID": rid,
        })

        # Strip CORS headers from agent endpoints
        if request.url.path.startswith("/api/v1/broker/"):
            for cors_hdr in list(response.headers.keys()):
                if cors_hdr.lower().startswith("access-control-"):
                    del response.headers[cors_hdr]

        route_path = request.scope.get("route").path if request.scope.get("route") else request.url.path
        logging.getLogger("firewall_server.access").info(
            "%s %s %s %.3f %s", request.method, route_path, response.status_code, time.monotonic() - start, rid
        )
        return response

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/summary")
    def summary(_role=Depends(require_viewer)):
        events = _rows(settings.audit_db, "SELECT action,reason_codes,event_type,approval_outcome FROM audit_events")
        actions, reasons, outcomes = Counter(), Counter(), Counter()
        for event in events:
            if event["action"]:
                actions[event["action"]] += 1
            reasons.update(json.loads(event["reason_codes"]))
            if event["approval_outcome"]:
                outcomes[event["approval_outcome"]] += 1
        return {
            "sessions": _count(settings.audit_db, "sessions"),
            "events": len(events),
            "decisions_by_action": dict(actions),
            "top_reason_codes": reasons.most_common(20),
            "approval_outcomes": dict(outcomes),
            "held_outputs": sum(e["event_type"] in {"output_inspected", "tool_output_inspection"} and str(e["action"]).upper() == "HOLD" for e in events),
            "halts": sum(e["event_type"] == "session_halted" for e in events),
            "rejected_audit_events": sum(e["event_type"] == "audit_event_rejected" for e in events),
        }

    @app.get("/api/v1/sessions")
    def sessions(page=Depends(_page), _role=Depends(require_viewer)):
        limit, offset = page
        rows = _rows(settings.audit_db, "SELECT session_id,started_at,agent_name,policy_version,user_task_length FROM sessions ORDER BY started_at DESC LIMIT ? OFFSET ?", (limit, offset))
        return {"items": rows, "limit": limit, "offset": offset, "total": _count(settings.audit_db, "sessions")}

    @app.get("/api/v1/sessions/{session_id}")
    def session(session_id: str, _role=Depends(require_viewer)):
        rows = _rows(settings.audit_db, "SELECT session_id,started_at,agent_name,policy_version,user_task_length FROM sessions WHERE session_id=?", (session_id,))
        if not rows:
            raise HTTPException(404, {"error": "Not found.", "code": "NOT_FOUND"})
        events = _rows(settings.audit_db, "SELECT id,ts,event_type,action,tool,reason_codes FROM audit_events WHERE session_id=? ORDER BY id", (session_id,))
        return {"session": rows[0], "timeline": [_clean_event(event) for event in events], "event_count": len(events)}

    @app.get("/api/v1/sessions/{session_id}/events")
    def session_events(
        session_id: str,
        event_type: str | None = None,
        action: str | None = None,
        tool: str | None = None,
        page=Depends(_page),
        _role=Depends(require_viewer),
    ):
        if event_type is not None and event_type not in SAFE_EVENT_TYPES:
            raise HTTPException(422, {"error": "Invalid filter.", "code": "INVALID_FILTER"})
        if action is not None and action not in SAFE_ACTIONS:
            raise HTTPException(422, {"error": "Invalid filter.", "code": "INVALID_FILTER"})
        limit, offset = page
        clauses, values = ["session_id=?"], [session_id]
        for key, value in (("event_type", event_type), ("action", action), ("tool", tool)):
            if value is not None:
                clauses.append(key + "=?")
                values.append(value)
        where = " WHERE " + " AND ".join(clauses)
        rows = _rows(settings.audit_db, "SELECT * FROM audit_events" + where + " ORDER BY id LIMIT ? OFFSET ?", (*values, limit, offset))
        return {"items": [_clean_event(row) for row in rows], "limit": limit, "offset": offset, "total": _count(settings.audit_db, "audit_events", where, values)}

    @app.get("/api/v1/audit/verify")
    def audit_verify(max_rows: int = Query(100_000, ge=1, le=1_000_000), _role=Depends(require_viewer)):
        return _verify(settings.audit_db, max_rows)

    @app.get("/api/v1/review/items")
    def review_items(
        status: str | None = None,
        session_id: str | None = None,
        item_type: str | None = None,
        page=Depends(_page),
        _role=Depends(require_viewer),
    ):
        if status and status not in {"pending", "viewed", "resolved", "expired", "archived", "approved", "denied", "cancelled"}:
            raise HTTPException(422, {"error": "Invalid filter.", "code": "INVALID_FILTER"})
        if item_type and item_type not in {"held_output", "masked_output", "flagged_content", "approval_request"}:
            raise HTTPException(422, {"error": "Invalid filter.", "code": "INVALID_FILTER"})
        limit, offset = page
        items, total = review.list(status=status, session_id=session_id, item_type=item_type, limit=limit, offset=offset)
        return {"items": items, "limit": limit, "offset": offset, "total": total}

    @app.get("/api/v1/review/items/{identifier}")
    def review_item(identifier: str, _role=Depends(require_viewer)):
        item = review.get(identifier, include_text=True)
        if not item:
            raise HTTPException(404, {"error": "Not found.", "code": "NOT_FOUND"})
        item.update({"render": "plain_text_only", "untrusted_content": True})
        return item

    @app.get("/api/v1/review/items/{identifier}/view")
    def review_item_view(identifier: str, _role=Depends(require_viewer)):
        item = review.get(identifier, include_text=True)
        if not item:
            raise HTTPException(404, {"error": "Not found.", "code": "NOT_FOUND"})

        mode = "held" if item.get("item_type") == "held_output" else "masked"
        has_text = bool(item.get("has_text"))
        orig_text = item.get("original_text")
        masked_text = item.get("masked_text")
        truncated = bool(item.get("text_truncated", False))

        if not has_text or not settings.store_text or (orig_text is None and masked_text is None):
            return {
                "id": item["id"],
                "session_id": item["session_id"],
                "tool": item.get("tool"),
                "has_text": False,
                "spans_available": False,
                "text_truncated": False,
                "untrusted_content": True,
                "render": "plain_text_only",
                "mode": mode,
                "original_pieces": [],
                "masked_pieces": [],
            }

        raw_spans = item.get("spans") or []
        text_len = len(orig_text or "")
        merged = merge_spans(raw_spans, text_len)
        spans_available = bool(raw_spans and len(raw_spans) > 0)

        orig_pieces = split_text_into_pieces(orig_text or "", merged)
        masked_pieces = build_masked_pieces(orig_text, masked_text, merged)

        return {
            "id": item["id"],
            "session_id": item["session_id"],
            "tool": item.get("tool"),
            "has_text": True,
            "spans_available": spans_available,
            "text_truncated": truncated,
            "untrusted_content": True,
            "render": "plain_text_only",
            "mode": mode,
            "original_pieces": orig_pieces,
            "masked_pieces": masked_pieces,
        }

    @app.get("/api/v1/policy")
    def policy(_role=Depends(require_viewer)):
        current = load_policy(settings.policy)
        tools = {
            name: {
                "risk": spec.risk,
                "side_effects": spec.side_effects,
                "always_ask": spec.always_ask,
                "arg_types": {arg: rule.type for arg, rule in spec.args.items()},
                "egress": bool(spec.egress),
                "output_sensitivity": spec.output_sensitivity,
            }
            for name, spec in current.tools.items()
        }
        limits = {key: list(value) if isinstance(value, tuple) else value for key, value in vars(current.limits).items()}
        return {
            "agent_name": current.agent_name,
            "policy_version": current.policy_version,
            "tools": tools,
            "limits": limits,
            "link_policy": {k: dict(v) for k, v in current.link_policy.items()},
            "sensitivity": vars(current.sensitivity),
            "approval": vars(current.approval),
            "loop_guard": vars(current.loop_guard),
            "lint_warnings": [{"code": w.code, "tool": w.tool, "message": w.message} for w in lint_policy(current)],
        }

    @app.get("/api/v1/config")
    def configuration(_role=Depends(require_viewer)):
        source = (ROOT / "config" / "layer1_settings.py").read_text(encoding="utf-8")
        mode = "cascade" if 'JUDGE_MODE = "cascade"' in source else "all" if 'JUDGE_MODE = "all"' in source else "unavailable"
        return {"judge_mode": mode, "release_version": __version__, "audit_hash_chain_verified_at_startup": app.state.audit_verified}

    @app.get("/api/v1/eval/results")
    def evaluation(_role=Depends(require_viewer)):
        result_dir = ROOT / "data" / "results" / "layer2_eval"
        settings_path = ROOT / "data" / "layer2_eval" / "settings.yaml"
        return {
            "results": json.loads((result_dir / "results.json").read_text(encoding="utf-8")),
            "known_gaps": (result_dir / "known_gaps.md").read_text(encoding="utf-8"),
            "prediction_mismatch": (result_dir / "prediction_mismatch.md").read_text(encoding="utf-8"),
            "settings": settings_path.read_text(encoding="utf-8"),
        }

    # Mount Broker & Approval Routes only if broker is enabled
    if settings.enable_broker and broker is not None:

        @app.post("/api/v1/broker/requests", response_model=BrokerCreatedOut)
        async def broker_create_request(request: Request, body: BrokerRequestIn, _role=Depends(require_agent)):
            ip = request.client.host if request.client else "unknown"
            rate_limiter.check(ip, "broker_create")
            try:
                req_id, expires_at = broker.create_request(
                    session_id=body.session_id,
                    tool=body.tool,
                    reason_codes=body.reason_codes,
                    explanation=body.explanation,
                    evidence_summary=body.evidence_summary,
                    sensitivity_flags=body.sensitivity_flags,
                    values_preview=body.values_preview,
                    ttl_seconds=body.ttl_seconds,
                )
                return {"request_id": req_id, "expires_at": expires_at}
            except BrokerFullError:
                raise HTTPException(503, {"error": "Broker queue is full.", "code": "BROKER_FULL"})

        @app.get("/api/v1/broker/requests/{identifier}/decision", response_model=BrokerStatusOut)
        async def broker_get_decision(
            identifier: str,
            wait_seconds: float = Query(0.0, ge=0.0, le=20.0),
            _role=Depends(require_agent),
        ):
            try:
                status = broker.get_decision(identifier, wait_seconds=wait_seconds)
                return {"status": status}
            except RequestNotFoundError:
                raise HTTPException(404, {"error": "Not found.", "code": "NOT_FOUND"})

        @app.post("/api/v1/broker/requests/{identifier}/cancel", response_model=BrokerStatusOut)
        async def broker_cancel_request(identifier: str, _role=Depends(require_agent)):
            try:
                status = broker.cancel_request(identifier)
                return {"status": status}
            except RequestNotFoundError:
                raise HTTPException(404, {"error": "Not found.", "code": "NOT_FOUND"})

        @app.get("/api/v1/approvals", response_model=ApprovalListOut)
        def approvals_list(
            status: str = Query("pending"),
            page=Depends(_page),
            _role=Depends(require_reviewer),
        ):
            if status not in {"pending", "all"}:
                raise HTTPException(422, {"error": "Invalid filter.", "code": "INVALID_FILTER"})
            limit, offset = page
            items, total = broker.list_requests(status=status, limit=limit, offset=offset)
            return {"items": items, "total": total, "limit": limit, "offset": offset}

        @app.get("/api/v1/approvals/stats", response_model=ApprovalStatsOut)
        def approvals_stats(_role=Depends(require_viewer)):
            return review.stats()

        @app.get("/api/v1/approvals/{identifier}", response_model=ApprovalDetailOut)
        def approval_detail(identifier: str, _role=Depends(require_reviewer)):
            try:
                return broker.get_request_detail(identifier)
            except RequestNotFoundError:
                raise HTTPException(404, {"error": "Not found.", "code": "NOT_FOUND"})

        @app.post("/api/v1/approvals/{identifier}/decision", response_model=ApprovalDecisionOut)
        def approval_decision(
            identifier: str,
            body: BrokerDecisionIn,
            request: Request,
            _role=Depends(require_reviewer),
        ):
            ip = request.client.host if request.client else "unknown"
            rate_limiter.check(ip, "reviewer_decide")
            if body.decision == "approve" and not body.confirm:
                raise HTTPException(422, {"error": "Approval requires confirm=true.", "code": "CONFIRM_REQUIRED"})
            try:
                final_status = broker.decide(
                    identifier,
                    decision=body.decision,
                    request_hash=body.request_hash,
                    confirm=body.confirm,
                    decided_by_role="reviewer",
                )
                return {"status": final_status, "request_id": identifier}
            except RequestNotFoundError:
                raise HTTPException(404, {"error": "Not found.", "code": "NOT_FOUND"})
            except RequestExpiredError:
                raise HTTPException(409, {"error": "Approval request has expired.", "code": "EXPIRED"})
            except AlreadyDecidedError:
                raise HTTPException(409, {"error": "Approval request already decided.", "code": "ALREADY_DECIDED"})
            except HashMismatchError:
                raise HTTPException(409, {"error": "Request hash mismatch.", "code": "HASH_MISMATCH"})
            except ValueError as e:
                raise HTTPException(422, {"error": str(e), "code": "INVALID_DECISION"})

    return app
