"""Layer-neutral immutable records shared by the firewall and scanner adapters."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


LEVELS = frozenset({"none", "low", "medium", "high", "needs_review"})


@dataclass(frozen=True)
class SegmentRecord:
    segment_id: str
    doc_id: str
    source_type: str
    start: int
    end: int
    text: str
    suspicion_level: str
    judge_ran: bool
    coverage_reason: str | None = None
    rules_flag: bool | None = None
    piguard_flag: bool | None = None
    instruction_reasons: tuple[str, ...] = ()
    piguard_label: str | None = None
    piguard_score: float | None = None
    judge_is_instruction: bool | None = None
    judge_needed_for_task: bool | None = None
    judge_flag: bool | None = None
    judge_reason: str | None = None

    def __post_init__(self):
        if self.suspicion_level not in LEVELS:
            raise ValueError("invalid suspicion level")
        if type(self.start) is not int or type(self.end) is not int or self.start < 0 or self.end < self.start:
            raise ValueError("invalid segment offsets")
        if not isinstance(self.text, str) or type(self.judge_ran) is not bool:
            raise ValueError("invalid segment record")
        if self.piguard_score is not None and not isinstance(self.piguard_score, (int, float)):
            raise ValueError("invalid PIGuard score")


@dataclass(frozen=True)
class ScanOutcome:
    segments: tuple[SegmentRecord, ...]
    judge_calls_made: int
    coverage_fraction: float

    def __post_init__(self):
        object.__setattr__(self, "segments", tuple(self.segments))
        if type(self.judge_calls_made) is not int or self.judge_calls_made < 0:
            raise ValueError("invalid judge call count")
        if not isinstance(self.coverage_fraction, (int, float)) or not 0 <= self.coverage_fraction <= 1:
            raise ValueError("invalid coverage fraction")


@dataclass(frozen=True)
class OutputResult:
    output_id: str
    action: str
    agent_view: object
    reason_codes: tuple[str, ...]
    max_level: str
    level_counts: Mapping[str, int]
    segment_ids: tuple[str, ...]
    unreviewed_segment_ids: tuple[str, ...]
    unscanned_chars: int
    judge_calls_made: int
    message: str

    def __post_init__(self):
        object.__setattr__(self, "level_counts", MappingProxyType(dict(self.level_counts)))

    def to_audit_dict(self) -> dict:
        return {
            "output_id": self.output_id, "action": self.action,
            "reason_codes": self.reason_codes, "max_level": self.max_level,
            "level_counts": dict(self.level_counts), "segment_ids": self.segment_ids,
            "unreviewed_segment_ids": self.unreviewed_segment_ids,
            "unscanned_chars": self.unscanned_chars, "judge_calls_made": self.judge_calls_made,
        }
