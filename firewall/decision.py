"""Agent-agnostic, value-free decisions returned by the Layer 2 firewall."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


class Action(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    BLOCK = "block"


class ReasonCode(str, Enum):
    # Implemented by the Day 5 fail-closed shell.
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    MISSING_ARGUMENT = "MISSING_ARGUMENT"
    UNEXPECTED_ARGUMENT = "UNEXPECTED_ARGUMENT"
    WRONG_ARGUMENT_TYPE = "WRONG_ARGUMENT_TYPE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    POLICY_INVALID = "POLICY_INVALID"
    RULES_NOT_IMPLEMENTED = "RULES_NOT_IMPLEMENTED"
    # Reserved for later policy, matching, output-handling, and approval work.
    TOOL_NOT_ALLOWED_FOR_TASK = "TOOL_NOT_ALLOWED_FOR_TASK"
    RECIPIENT_NOT_ALLOWED = "RECIPIENT_NOT_ALLOWED"
    DOMAIN_NOT_ALLOWED = "DOMAIN_NOT_ALLOWED"
    AMOUNT_OVER_LIMIT = "AMOUNT_OVER_LIMIT"
    PATH_NOT_ALLOWED = "PATH_NOT_ALLOWED"
    ALWAYS_ASK_TOOL = "ALWAYS_ASK_TOOL"
    ARG_MATCHES_HIGH_SUSPICION_SEGMENT = "ARG_MATCHES_HIGH_SUSPICION_SEGMENT"
    ARG_MATCHES_MEDIUM_SUSPICION_SEGMENT = "ARG_MATCHES_MEDIUM_SUSPICION_SEGMENT"
    ARG_MATCHES_UNREVIEWED_SEGMENT = "ARG_MATCHES_UNREVIEWED_SEGMENT"
    SESSION_TAINTED_HIGH_RISK = "SESSION_TAINTED_HIGH_RISK"
    CONFIDENTIAL_DATA_EXTERNAL = "CONFIDENTIAL_DATA_EXTERNAL"
    TOOL_OUTPUT_HELD = "TOOL_OUTPUT_HELD"
    JUDGE_UNAVAILABLE = "JUDGE_UNAVAILABLE"
    RETRY_LIMIT_REACHED = "RETRY_LIMIT_REACHED"
    USER_DENIED = "USER_DENIED"
    USER_APPROVED = "USER_APPROVED"
    APPROVAL_TIMEOUT = "APPROVAL_TIMEOUT"
    ALL_RULES_PASSED = "ALL_RULES_PASSED"
    INVALID_ARGUMENT_VALUE = "INVALID_ARGUMENT_VALUE"
    ACCOUNT_NOT_ALLOWED = "ACCOUNT_NOT_ALLOWED"
    URL_NOT_ALLOWED = "URL_NOT_ALLOWED"
    CONSTRAINT_VIOLATION = "CONSTRAINT_VIOLATION"
    OUTPUT_PASSED = "OUTPUT_PASSED"
    OUTPUT_MASKED = "OUTPUT_MASKED"
    OUTPUT_HELD = "OUTPUT_HELD"
    OUTPUT_UNREVIEWED = "OUTPUT_UNREVIEWED"
    OUTPUT_OVERSIZE = "OUTPUT_OVERSIZE"
    OUTPUT_NOT_TEXT = "OUTPUT_NOT_TEXT"
    OUTPUT_SCAN_FAILED = "OUTPUT_SCAN_FAILED"
    OUTPUT_SCAN_DISABLED = "OUTPUT_SCAN_DISABLED"
    INTENT_MATCHES_FLAGGED_SEGMENT = "INTENT_MATCHES_FLAGGED_SEGMENT"
    USER_PROVIDED_VALUE = "USER_PROVIDED_VALUE"
    ARG_FROM_UNTRUSTED_UNFLAGGED = "ARG_FROM_UNTRUSTED_UNFLAGGED"
    LINK_SCAN_LIMIT = "LINK_SCAN_LIMIT"
    LINK_LOGGED = "LINK_LOGGED"
    NO_APPROVER = "NO_APPROVER"
    APPROVAL_CALLBACK_ERROR = "APPROVAL_CALLBACK_ERROR"
    SESSION_HALTED = "SESSION_HALTED"
    TASK_FIT_DOUBTFUL = "TASK_FIT_DOUBTFUL"
    AUDIT_EVENT_REJECTED = "AUDIT_EVENT_REJECTED"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"


@dataclass(frozen=True)
class FinalDecision:
    action: str
    reason_codes: tuple[ReasonCode, ...]
    approval: str = "none"
    agent_message: str = "This action was not permitted. Do not retry it; ask the user instead."
    decision: "Decision | None" = None


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(k): _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, set):
        return tuple(sorted((_freeze(v) for v in value), key=repr))
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


@dataclass(frozen=True)
class Decision:
    action: Action
    reason_codes: tuple[ReasonCode, ...]
    message: str
    rule_id: str | None = None
    matched_segment_ids: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)
    rule_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        action = Action(self.action)
        object.__setattr__(self, "action", action)
        codes = self.reason_codes
        if isinstance(codes, (str, ReasonCode)):
            codes = (codes,)
        object.__setattr__(self, "reason_codes", tuple(ReasonCode(x) for x in codes))
        object.__setattr__(self, "matched_segment_ids", tuple(str(x) for x in self.matched_segment_ids))
        object.__setattr__(self, "rule_ids", tuple(self.rule_ids or ((self.rule_id,) if self.rule_id else ())))
        object.__setattr__(self, "details", _freeze(self.details))

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "reason_codes": [item.value for item in self.reason_codes],
            "message": self.message,
            "rule_id": self.rule_id,
            "rule_ids": list(self.rule_ids),
            "matched_segment_ids": list(self.matched_segment_ids),
            "details": _plain(self.details),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, sort_keys=True)

    @classmethod
    def allow(cls, reason_codes=(), message="Allowed.", **kwargs) -> "Decision":
        return cls(Action.ALLOW, tuple(reason_codes), message, **kwargs)

    @classmethod
    def ask(cls, reason_codes=(), message="Needs review.", **kwargs) -> "Decision":
        return cls(Action.ASK, tuple(reason_codes), message, **kwargs)

    @classmethod
    def block(cls, reason_codes=(), message="Blocked.", **kwargs) -> "Decision":
        return cls(Action.BLOCK, tuple(reason_codes), message, **kwargs)
