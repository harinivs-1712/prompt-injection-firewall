"""FastAPI application factory for the localhost-only read-only dashboard API."""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from contextlib import closing
from collections import Counter
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from firewall.__version__ import __version__
from firewall.lint import lint_policy
from firewall.policy import load_policy
from firewall_server.review_store import ReviewStore
from firewall_server.security import FailureThrottle, TokenRedactionFilter, bearer, request_id, role_dependency
from firewall_server.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
SAFE_EVENT_TYPES = {"session_started", "tool_check", "tool_authorized", "approval_requested", "approval_outcome", "output_inspected", "tool_output_inspection", "loop_guard_triggered", "session_halted", "session_resumed", "audit_event_rejected"}
SAFE_ACTIONS = {"allow", "ask", "block", "denied", "pass", "mask", "hold", "ALLOW", "BLOCK", "DENIED", "PASS", "MASK", "HOLD"}


def _ro(path: Path):
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    db.execute("PRAGMA query_only=ON")
    return db


def _rows(path: Path, sql: str, values=()):
    with closing(_ro(path)) as db:
        db.row_factory = sqlite3.Row
        return [dict(item) for item in db.execute(sql, values)]


def _count(path: Path, table: str, where="", values=()):
    with closing(_ro(path)) as db: return int(db.execute(f"SELECT count(*) FROM {table}" + where, values).fetchone()[0])


def _page(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=1_000_000)):
    return limit, offset


def _clean_event(row):
    for key in ("reason_codes", "rule_ids", "evidence", "counts"):
        try: row[key] = json.loads(row[key])
        except Exception: row[key] = [] if key != "counts" else {}
    return row


def _verify(path: Path, cap: int):
    import hashlib
    from firewall.audit import _canonical
    with closing(_ro(path)) as db:
        db.row_factory = sqlite3.Row
        total = int(db.execute("SELECT count(*) FROM audit_events").fetchone()[0])
        if total > cap: return {"ok": False, "checked": 0, "first_bad_id": None, "message": "audit table exceeds verification cap"}
        previous, checked = "", 0
        for row in db.execute("SELECT * FROM audit_events ORDER BY id"):
            record = {"ts":row["ts"],"session_id":row["session_id"],"event_type":row["event_type"],"tool":row["tool"],"action":row["action"],"reason_codes":json.loads(row["reason_codes"]),"rule_ids":json.loads(row["rule_ids"]),"link_level":row["link_level"],"evidence":json.loads(row["evidence"]),"approval_outcome":row["approval_outcome"],"output_id":row["output_id"],"max_level":row["max_level"],"counts":json.loads(row["counts"])}
            actual = hashlib.sha256((previous + _canonical(record)).encode()).hexdigest()
            checked += 1
            if row["prev_hash"] != previous or row["row_hash"] != actual:
                return {"ok": False, "checked": checked, "first_bad_id": row["id"], "message": "hash-chain mismatch"}
            previous = actual
    return {"ok": True, "checked": checked, "first_bad_id": None, "message": "hash chain verified"}


def create_app(settings: Settings, throttle: FailureThrottle | None = None) -> FastAPI:
    docs = "/docs" if settings.enable_docs else None
    app = FastAPI(title="Firewall review API", docs_url=docs, redoc_url=None, openapi_url="/openapi.json" if settings.enable_docs else None)
    allowed_hosts = ["localhost", "127.0.0.1", "[::1]", "::1", *settings.allowed_hosts]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["GET", "OPTIONS"], allow_headers=["Authorization", "Content-Type"], allow_credentials=False)
    throttle = throttle or FailureThrottle()
    require = role_dependency(settings, throttle)
    review = ReviewStore(settings.review_db, store_text=settings.store_text, retention_hours=settings.retention_hours, readonly=True)
    app.state.settings, app.state.review, app.state.audit_verified = settings, review, _verify(settings.audit_db, settings.audit_verify_cap)["ok"]
    logging.getLogger().addFilter(TokenRedactionFilter((settings.viewer_token, settings.reviewer_token)))

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        return JSONResponse(
            {"error": detail.get("error", "Request could not be completed."), "code": detail.get("code", "REQUEST_ERROR")},
            status_code=exc.status_code,
        )

    @app.middleware("http")
    async def headers(request: Request, call_next):
        start, rid = time.monotonic(), request_id(); request.state.request_id = rid
        if len(request.url.query) > 4096:
            response = JSONResponse({"error":"Request could not be completed.","code":"QUERY_TOO_LONG"}, status_code=414)
        elif request.method == "GET" and int(request.headers.get("content-length", "0") or 0) > 0:
            response = JSONResponse({"error":"Request could not be completed.","code":"REQUEST_BODY_NOT_ALLOWED"}, status_code=405)
        else:
            try: response = await call_next(request)
            except HTTPException as exc:
                detail = exc.detail if isinstance(exc.detail, dict) else {}
                response = JSONResponse({"error":"Request could not be completed.","code":detail.get("code","REQUEST_ERROR")}, status_code=exc.status_code)
            except Exception as exc:
                logging.getLogger("firewall_server").error("request failed class=%s id=%s", type(exc).__name__, rid)
                response = JSONResponse({"error":"Request could not be completed.","code":"INTERNAL_ERROR"}, status_code=500)
        response.headers.update({"X-Content-Type-Options":"nosniff", "Cache-Control":"no-store", "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'", "Referrer-Policy":"no-referrer", "Cross-Origin-Resource-Policy":"same-origin", "X-Request-ID":rid})
        logging.getLogger("firewall_server.access").info("%s %s %s %.3f %s", request.method, request.scope.get("route").path if request.scope.get("route") else request.url.path, response.status_code, time.monotonic()-start, rid)
        return response

    async def auth(request: Request, credentials=Depends(bearer)): return await require(request, credentials)

    @app.get("/health")
    def health(): return {"status":"ok", "version":__version__}

    @app.get("/api/v1/summary")
    def summary(_role=Depends(auth)):
        events = _rows(settings.audit_db, "SELECT action,reason_codes,event_type,approval_outcome FROM audit_events")
        actions, reasons, outcomes = Counter(), Counter(), Counter()
        for event in events:
            if event["action"]: actions[event["action"]] += 1
            reasons.update(json.loads(event["reason_codes"]))
            if event["approval_outcome"]: outcomes[event["approval_outcome"]] += 1
        return {"sessions":_count(settings.audit_db,"sessions"), "events":len(events), "decisions_by_action":dict(actions), "top_reason_codes":reasons.most_common(20), "approval_outcomes":dict(outcomes), "held_outputs":sum(e["event_type"] in {"output_inspected","tool_output_inspection"} and str(e["action"]).upper()=="HOLD" for e in events), "halts":sum(e["event_type"]=="session_halted" for e in events), "rejected_audit_events":sum(e["event_type"]=="audit_event_rejected" for e in events)}

    @app.get("/api/v1/sessions")
    def sessions(page=Depends(_page), _role=Depends(auth)):
        limit, offset = page
        rows = _rows(settings.audit_db, "SELECT session_id,started_at,agent_name,policy_version,user_task_length FROM sessions ORDER BY started_at DESC LIMIT ? OFFSET ?", (limit,offset))
        return {"items":rows,"limit":limit,"offset":offset,"total":_count(settings.audit_db,"sessions")}

    @app.get("/api/v1/sessions/{session_id}")
    def session(session_id: str, _role=Depends(auth)):
        rows = _rows(settings.audit_db, "SELECT session_id,started_at,agent_name,policy_version,user_task_length FROM sessions WHERE session_id=?", (session_id,))
        if not rows: raise HTTPException(404, {"error":"Not found.","code":"NOT_FOUND"})
        events = _rows(settings.audit_db, "SELECT id,ts,event_type,action,tool,reason_codes FROM audit_events WHERE session_id=? ORDER BY id", (session_id,))
        return {"session":rows[0], "timeline":[_clean_event(event) for event in events], "event_count":len(events)}

    @app.get("/api/v1/sessions/{session_id}/events")
    def session_events(session_id: str, event_type: str | None=None, action: str | None=None, tool: str | None=None, page=Depends(_page), _role=Depends(auth)):
        if event_type is not None and event_type not in SAFE_EVENT_TYPES: raise HTTPException(422, {"error":"Invalid filter.","code":"INVALID_FILTER"})
        if action is not None and action not in SAFE_ACTIONS: raise HTTPException(422, {"error":"Invalid filter.","code":"INVALID_FILTER"})
        limit, offset = page; clauses, values = ["session_id=?"], [session_id]
        for key, value in (("event_type",event_type),("action",action),("tool",tool)):
            if value is not None: clauses.append(key+"=?"); values.append(value)
        where = " WHERE " + " AND ".join(clauses)
        rows = _rows(settings.audit_db, "SELECT * FROM audit_events"+where+" ORDER BY id LIMIT ? OFFSET ?", (*values,limit,offset))
        return {"items":[_clean_event(row) for row in rows],"limit":limit,"offset":offset,"total":_count(settings.audit_db,"audit_events",where,values)}

    @app.get("/api/v1/audit/verify")
    def audit_verify(max_rows: int = Query(100_000, ge=1, le=1_000_000), _role=Depends(auth)): return _verify(settings.audit_db, max_rows)

    @app.get("/api/v1/review/items")
    def review_items(status: str | None=None, session_id: str | None=None, item_type: str | None=None, page=Depends(_page), _role=Depends(auth)):
        if status and status not in {"pending","viewed","resolved","expired","archived"}: raise HTTPException(422, {"error":"Invalid filter.","code":"INVALID_FILTER"})
        if item_type and item_type not in {"held_output","masked_output","flagged_content","approval_request"}: raise HTTPException(422, {"error":"Invalid filter.","code":"INVALID_FILTER"})
        limit, offset = page; items, total = review.list(status=status, session_id=session_id, item_type=item_type, limit=limit, offset=offset)
        return {"items":items,"limit":limit,"offset":offset,"total":total}

    @app.get("/api/v1/review/items/{identifier}")
    def review_item(identifier: str, _role=Depends(auth)):
        item = review.get(identifier, include_text=True)
        if not item: raise HTTPException(404, {"error":"Not found.","code":"NOT_FOUND"})
        item.update({"render":"plain_text_only", "untrusted_content":True})
        return item

    @app.get("/api/v1/policy")
    def policy(_role=Depends(auth)):
        current = load_policy(settings.policy)
        tools = {name:{"risk":spec.risk,"side_effects":spec.side_effects,"always_ask":spec.always_ask,"arg_types":{arg:rule.type for arg,rule in spec.args.items()},"egress":bool(spec.egress),"output_sensitivity":spec.output_sensitivity} for name,spec in current.tools.items()}
        limits = {key:list(value) if isinstance(value,tuple) else value for key,value in vars(current.limits).items()}
        return {"agent_name":current.agent_name,"policy_version":current.policy_version,"tools":tools,"limits":limits,"link_policy":{k:dict(v) for k,v in current.link_policy.items()},"sensitivity":vars(current.sensitivity),"approval":vars(current.approval),"loop_guard":vars(current.loop_guard),"lint_warnings":[{"code":w.code,"tool":w.tool,"message":w.message} for w in lint_policy(current)]}

    @app.get("/api/v1/config")
    def configuration(_role=Depends(auth)):
        # Read simple settings constants without importing Layer 1 or its optional libraries.
        source = (ROOT/"config"/"layer1_settings.py").read_text(encoding="utf-8")
        mode = "cascade" if 'JUDGE_MODE = "cascade"' in source else "all" if 'JUDGE_MODE = "all"' in source else "unavailable"
        return {"judge_mode":mode,"release_version":__version__,"audit_hash_chain_verified_at_startup":app.state.audit_verified}

    @app.get("/api/v1/eval/results")
    def evaluation(_role=Depends(auth)):
        result_dir = ROOT/"data"/"results"/"layer2_eval"; settings_path = ROOT/"data"/"layer2_eval"/"settings.yaml"
        return {"results":json.loads((result_dir/"results.json").read_text(encoding="utf-8")), "known_gaps":(result_dir/"known_gaps.md").read_text(encoding="utf-8"), "prediction_mismatch":(result_dir/"prediction_mismatch.md").read_text(encoding="utf-8"), "settings":settings_path.read_text(encoding="utf-8")}
    return app
