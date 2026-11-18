"""In-memory approval broker for real-time human decision flows."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from firewall_server.review_store import ReviewStore

logger = logging.getLogger("firewall_server.broker")

MAX_VALUE_BYTES = 4096
MAX_TOTAL_VALUES_BYTES = 20480


def _clean_str(val: str, max_len: int = MAX_VALUE_BYTES) -> str:
    cleaned = "".join(ch for ch in str(val) if ch in "\n\t" or ord(ch) >= 32)
    return cleaned[:max_len]


def sanitize_values_preview(preview: dict[str, Any] | None) -> dict[str, str]:
    if not isinstance(preview, dict):
        return {}
    res: dict[str, str] = {}
    total_len = 0
    for k, v in preview.items():
        clean_k = _clean_str(str(k), 100)
        clean_v = _clean_str(str(v), MAX_VALUE_BYTES)
        if total_len + len(clean_k) + len(clean_v) > MAX_TOTAL_VALUES_BYTES:
            remaining = max(0, MAX_TOTAL_VALUES_BYTES - total_len - len(clean_k))
            if remaining > 0:
                res[clean_k] = clean_v[:remaining]
            break
        res[clean_k] = clean_v
        total_len += len(clean_k) + len(clean_v)
    return res


def compute_request_hash(
    req_id: str,
    session_id: str,
    tool: str,
    reason_codes: list[str],
    values_preview: dict[str, str] | None,
) -> str:
    data = [
        str(req_id),
        str(session_id),
        str(tool),
        sorted(str(c) for c in (reason_codes or [])),
        values_preview,
    ]
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class BrokerFullError(Exception):
    pass


class RequestNotFoundError(Exception):
    pass


class RequestExpiredError(Exception):
    pass


class AlreadyDecidedError(Exception):
    pass


class HashMismatchError(Exception):
    pass


@dataclass
class PendingRequest:
    id: str
    session_id: str
    tool: str
    reason_codes: list[str]
    explanation: str
    evidence_summary: list[dict]
    sensitivity_flags: list[str]
    values_preview: dict[str, str] | None
    created_time: float
    created_at_iso: str
    expires_time: float
    expires_at_iso: str
    status: str = "pending"
    request_hash: str = ""
    hash_attempts: int = 0
    terminal_event: threading.Event = field(default_factory=threading.Event)
    decided_at_iso: str | None = None
    decided_by_role: str | None = None
    time_to_decision_ms: int | None = None


class ApprovalBroker:
    def __init__(
        self,
        review_store: ReviewStore | None = None,
        max_pending: int = 100,
        max_ttl_seconds: float = 300.0,
        clock: Callable[[], float] = time.time,
    ):
        self.review_store = review_store
        self.max_pending = max_pending
        self.max_ttl_seconds = max_ttl_seconds
        self.clock = clock
        self._lock = threading.RLock()
        self._requests: dict[str, PendingRequest] = {}
        self._sweeper_stop = threading.Event()
        self._sweeper_thread: threading.Thread | None = None

    def start_sweeper(self, interval_seconds: float = 1.0) -> None:
        """Start the service-owned expiry worker exactly once.

        Expiration cannot depend on a later API request: the request preview is
        sensitive and must be wiped as soon as its TTL elapses.  The worker is
        deliberately daemonized, while ``stop_sweeper`` is called by the ASGI
        shutdown hook for a clean server shutdown.
        """
        with self._lock:
            if self._sweeper_thread and self._sweeper_thread.is_alive():
                return
            self._sweeper_stop.clear()

            def _run() -> None:
                while not self._sweeper_stop.wait(max(0.05, float(interval_seconds))):
                    try:
                        self.sweep_expired()
                    except Exception:
                        # A sweep must never take down the dashboard.  Individual
                        # review-store failures are also already handled by sweep.
                        logger.exception("Approval broker expiry sweep failed")

            self._sweeper_thread = threading.Thread(
                target=_run,
                name="firewall-approval-expiry",
                daemon=True,
            )
            self._sweeper_thread.start()

    def stop_sweeper(self, timeout_seconds: float = 2.0) -> None:
        """Stop the expiry worker without blocking server shutdown indefinitely."""
        self._sweeper_stop.set()
        thread = self._sweeper_thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout_seconds)))

    def _now(self) -> float:
        return self.clock()

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def sweep_expired(self) -> int:
        now = self._now()
        now_iso = self._now_iso()
        expired_count = 0
        with self._lock:
            for req in list(self._requests.values()):
                if req.status == "pending" and req.expires_time <= now:
                    req.status = "expired"
                    req.decided_at_iso = now_iso
                    req.decided_by_role = "timeout"
                    req.time_to_decision_ms = int(max(0, (now - req.created_time) * 1000))
                    req.values_preview = None
                    req.terminal_event.set()
                    expired_count += 1
                    if self.review_store:
                        try:
                            self.review_store.update_decision(
                                req.id,
                                "expired",
                                req.decided_at_iso,
                                req.decided_by_role,
                                req.time_to_decision_ms,
                            )
                        except Exception:
                            logger.exception("Failed to update expired decision in review store")
        return expired_count

    def create_request(
        self,
        *,
        session_id: str,
        tool: str,
        reason_codes: list[str],
        explanation: str,
        evidence_summary: list[dict],
        sensitivity_flags: list[str],
        values_preview: dict[str, Any] | None,
        ttl_seconds: float,
    ) -> tuple[str, str]:
        self.sweep_expired()
        now = self._now()
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()

        clamped_ttl = max(1.0, min(float(ttl_seconds), self.max_ttl_seconds))
        expires_time = now + clamped_ttl
        from datetime import timedelta
        expires_dt = now_dt + timedelta(seconds=clamped_ttl)
        expires_iso = expires_dt.isoformat()

        req_id = uuid.uuid4().hex
        sanitized_values = sanitize_values_preview(values_preview)
        req_hash = compute_request_hash(req_id, session_id, tool, reason_codes, sanitized_values)

        with self._lock:
            pending_count = sum(1 for r in self._requests.values() if r.status == "pending")
            if pending_count >= self.max_pending:
                raise BrokerFullError("Broker queue is full")

            req = PendingRequest(
                id=req_id,
                session_id=str(session_id),
                tool=str(tool),
                reason_codes=[str(c) for c in (reason_codes or [])],
                explanation=str(explanation or ""),
                evidence_summary=list(evidence_summary or []),
                sensitivity_flags=[str(f) for f in (sensitivity_flags or [])],
                values_preview=sanitized_values,
                created_time=now,
                created_at_iso=now_iso,
                expires_time=expires_time,
                expires_at_iso=expires_iso,
                status="pending",
                request_hash=req_hash,
            )
            self._requests[req_id] = req

        if self.review_store:
            try:
                self.review_store.add(
                    session_id=session_id,
                    item_type="approval_request",
                    tool=tool,
                    reason_codes=req.reason_codes,
                    segment_ids=[
                        str(e.get("segment_id"))
                        for e in req.evidence_summary
                        if isinstance(e, dict) and e.get("segment_id")
                    ],
                    explanation=req.explanation,
                    evidence_summary=req.evidence_summary,
                    sensitivity_flags=req.sensitivity_flags,
                    custom_id=req_id,
                    expires_at=expires_iso,
                    status="pending",
                )
            except Exception:
                logger.exception("Failed to record approval request in review store")

        return req_id, expires_iso

    def get_decision(self, req_id: str, wait_seconds: float = 0.0) -> str:
        req = self._requests.get(req_id)
        if not req:
            raise RequestNotFoundError("Approval request not found")

        wait = max(0.0, min(float(wait_seconds), 20.0))
        if req.status == "pending" and wait > 0.0:
            remaining = max(0.0, req.expires_time - self._now())
            timeout_to_wait = min(wait, remaining)
            if timeout_to_wait > 0:
                req.terminal_event.wait(timeout=timeout_to_wait)

        self.sweep_expired()
        return req.status

    def cancel_request(self, req_id: str) -> str:
        with self._lock:
            req = self._requests.get(req_id)
            if not req:
                raise RequestNotFoundError("Approval request not found")

            self.sweep_expired()
            if req.status != "pending":
                return req.status

            now = self._now()
            req.status = "cancelled"
            req.decided_at_iso = self._now_iso()
            req.decided_by_role = "agent_cancel"
            req.time_to_decision_ms = int(max(0, (now - req.created_time) * 1000))
            req.values_preview = None
            req.terminal_event.set()

        if self.review_store:
            try:
                self.review_store.update_decision(
                    req.id,
                    "cancelled",
                    req.decided_at_iso,
                    req.decided_by_role,
                    req.time_to_decision_ms,
                )
            except Exception:
                logger.exception("Failed to update cancelled decision in review store")

        return req.status

    def decide(
        self,
        req_id: str,
        *,
        decision: str,
        request_hash: str,
        confirm: bool,
        decided_by_role: str = "reviewer",
    ) -> str:
        if decision not in {"approve", "deny"}:
            raise ValueError("Decision must be 'approve' or 'deny'")
        if decision == "approve" and not confirm:
            raise ValueError("Approval requires explicit confirm=true")

        now = self._now()
        with self._lock:
            req = self._requests.get(req_id)
            if not req:
                raise RequestNotFoundError("Approval request not found")

            if req.status == "pending" and req.expires_time <= now:
                req.status = "expired"
                req.decided_at_iso = self._now_iso()
                req.decided_by_role = "timeout"
                req.time_to_decision_ms = int(max(0, (now - req.created_time) * 1000))
                req.values_preview = None
                req.terminal_event.set()
                if self.review_store:
                    try:
                        self.review_store.update_decision(
                            req.id,
                            "expired",
                            req.decided_at_iso,
                            req.decided_by_role,
                            req.time_to_decision_ms,
                        )
                    except Exception:
                        pass
                raise RequestExpiredError("Approval request has expired")

            if req.status != "pending":
                raise AlreadyDecidedError(f"Request already in terminal state: {req.status}")

            if not hmac.compare_digest(str(request_hash), str(req.request_hash)):
                req.hash_attempts += 1
                raise HashMismatchError("Provided request_hash does not match")

            final_status = "approved" if decision == "approve" else "denied"
            req.status = final_status
            req.decided_at_iso = self._now_iso()
            req.decided_by_role = decided_by_role
            req.time_to_decision_ms = int(max(0, (now - req.created_time) * 1000))
            req.values_preview = None
            req.terminal_event.set()

        if self.review_store:
            try:
                self.review_store.update_decision(
                    req.id,
                    final_status,
                    req.decided_at_iso,
                    req.decided_by_role,
                    req.time_to_decision_ms,
                )
            except Exception:
                logger.exception("Failed to update final decision in review store")

        return final_status

    def list_requests(self, *, status: str = "pending", limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
        self.sweep_expired()
        now = self._now()
        with self._lock:
            items = []
            for r in self._requests.values():
                if status == "all" or r.status == status:
                    sec_remaining = max(0, int(r.expires_time - now)) if r.status == "pending" else 0
                    items.append({
                        "id": r.id,
                        "session_id": r.session_id,
                        "tool": r.tool,
                        "reason_codes": list(r.reason_codes),
                        "created_at": r.created_at_iso,
                        "expires_at": r.expires_at_iso,
                        "seconds_remaining": sec_remaining,
                        "status": r.status,
                    })
            items.sort(key=lambda x: x["created_at"], reverse=True)
            total = len(items)
            paged = items[offset : offset + limit]
            return paged, total

    def get_request_detail(self, req_id: str) -> dict:
        self.sweep_expired()
        now = self._now()
        with self._lock:
            req = self._requests.get(req_id)
            if not req:
                raise RequestNotFoundError("Approval request not found")

            sec_remaining = max(0, int(req.expires_time - now)) if req.status == "pending" else 0
            detail = {
                "id": req.id,
                "session_id": req.session_id,
                "tool": req.tool,
                "reason_codes": list(req.reason_codes),
                "created_at": req.created_at_iso,
                "expires_at": req.expires_at_iso,
                "seconds_remaining": sec_remaining,
                "status": req.status,
            }
            if req.status == "pending":
                detail["explanation"] = req.explanation
                detail["evidence_summary"] = list(req.evidence_summary)
                detail["sensitivity_flags"] = list(req.sensitivity_flags)
                detail["values_preview"] = dict(req.values_preview or {})
                detail["request_hash"] = req.request_hash
            else:
                detail["decided_at"] = req.decided_at_iso
                detail["decided_by_role"] = req.decided_by_role
                detail["time_to_decision_ms"] = req.time_to_decision_ms
            return detail
