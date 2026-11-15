"""Dependency-injection protocols and small audit-sink implementations."""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable
from firewall.types import ScanOutcome
from firewall.audit_schema import validate_event


@runtime_checkable
class Scanner(Protocol):
    def scan(self, content: str, *, doc_id: str, source_type: str, user_task: str,
             context_note: str | None = None, max_judge_calls: int | None = None) -> ScanOutcome: ...


@runtime_checkable
class ApprovalCallback(Protocol):
    def __call__(self, packet: Any, timeout_seconds: float) -> bool: ...


@runtime_checkable
class AuditSink(Protocol):
    def record(self, event: dict[str, Any]) -> None: ...


class NullAuditSink:
    def record(self, event: dict[str, Any]) -> None:
        return None


class InMemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.rejected_events = 0

    def record(self, event: dict[str, Any]) -> None:
        allowed = {"event", "event_type", "tool_name", "tool", "action", "output_id", "reason_codes", "rule_ids",
                   "argument_names", "session_id", "max_level", "level_counts", "segment_ids", "unreviewed_segment_ids",
                   "unscanned_chars", "judge_calls_made", "link_level", "evidence", "user_provided_args",
                   "approval_outcome", "request_id", "sensitivity_flags", "counts", "policy_version", "agent_name",
                   "task_length", "user_task_sha256"}
        if not validate_event(event) or set(event) - allowed:
            self.rejected_events += 1
            self.events.append({"event_type": "audit_event_rejected", "reason_codes": ("AUDIT_EVENT_REJECTED",)})
            return
        if event.get("event_type") == "session_started":
            return
        copied = {}
        for key in ("event", "event_type", "tool_name", "tool", "action", "output_id", "reason_codes", "rule_ids",
                    "argument_names", "session_id", "max_level", "level_counts", "segment_ids",
                    "unreviewed_segment_ids", "unscanned_chars", "judge_calls_made", "link_level", "evidence",
                    "user_provided_args", "approval_outcome", "request_id", "sensitivity_flags", "counts"):
            if key not in event:
                continue
            value = event[key]
            if key in {"reason_codes", "rule_ids", "argument_names", "segment_ids", "unreviewed_segment_ids", "user_provided_args", "sensitivity_flags"}:
                value = tuple(value)
            elif key == "level_counts":
                value = dict(value)
            elif key == "evidence":
                value = tuple(dict(item) for item in value)
            copied[key] = value
        if "event_type" not in copied and "event" in copied:
            copied["event_type"] = copied["event"]
        self.events.append(copied)
