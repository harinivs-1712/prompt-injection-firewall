"""Per-conversation state owned by the host application's firewall instance."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from firewall.types import SegmentRecord


@dataclass
class Session:
    session_id: str = field(default_factory=lambda: str(uuid4()))
    user_task: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    segments: list[dict[str, Any]] = field(default_factory=list)
    blocked_attempts: dict[str, int] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    allowed_tools: frozenset[str] | None = None
    task_permission_source: str | None = None
    matched_task_categories: tuple[str, ...] = ()
    level_counts: dict[str, int] = field(default_factory=lambda: {k: 0 for k in ("none", "low", "medium", "high", "needs_review")})
    unreviewed_segment_ids: list[str] = field(default_factory=list)
    max_level_seen: str = "none"
    original_outputs: dict[str, Any] = field(default_factory=dict)
    held_outputs: dict[str, dict[str, Any]] = field(default_factory=dict)
    judge_calls_used: int = 0
    output_counter: int = 0
    content_counter: int = 0
    last_link_report: Any = None
    confidential: dict[str, set[str]] = field(default_factory=lambda: {"shingles": set(), "tokens": set()})
    confidential_output_seen: bool = False
    halted: bool = False
    blocked_session_count: int = 0
    denied_call_counts: dict[str, int] = field(default_factory=dict)
    approval_count: int = 0
    authorized_calls: dict[str, str] = field(default_factory=dict)
