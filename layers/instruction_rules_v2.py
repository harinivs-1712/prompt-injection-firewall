"""Additive instruction signal families; the frozen v1 module is untouched."""
from __future__ import annotations

import re

from config.filter_v2_config import COOCCUR_CONTEXT_WORDS, FAMILY_PATTERNS
from layers.instruction_rules import instruction_signals as v1_instruction_signals

_WORD_SPAN = re.compile(r"[A-Za-z]+(?:['’][A-Za-z]+)?", re.UNICODE)


def _phrase_pattern(phrase: str) -> re.Pattern[str]:
    escaped = re.escape(phrase.casefold())
    escaped = escaped.replace(r"\ ", r"\s+").replace("'", "['’]")
    return re.compile(r"(?<!\w)" + escaped + r"(?!\w)", re.IGNORECASE)


_FAMILY_RE = {
    name: tuple(_phrase_pattern(term) for term in terms)
    for name, terms in FAMILY_PATTERNS.items()
}
_CONTEXT_RE = tuple(_phrase_pattern(term) for term in COOCCUR_CONTEXT_WORDS)
_OUTWARD_RE = _FAMILY_RE["outward_exposure"]
_SENSITIVE_RE = tuple(
    _phrase_pattern(term) for term in (
        "key", "credential", "password", "token", "list", "record", "file",
        "contact", "report", "appendix", "attachment", "access", "account",
    )
)


def _has_context(text: str) -> bool:
    return any(pattern.search(text) for pattern in _CONTEXT_RE)


def _has_near_outward_sensitive_pair(text: str, max_token_gap: int = 8) -> bool:
    words = [(m.group(0).casefold(), m.start(), m.end()) for m in _WORD_SPAN.finditer(text)]
    def indexes(patterns: tuple[re.Pattern[str], ...]) -> list[int]:
        found: list[int] = []
        for pattern in patterns:
            for match in pattern.finditer(text):
                token_index = next((i for i, (_, start, end) in enumerate(words)
                                    if start <= match.start() < end), None)
                if token_index is not None:
                    found.append(token_index)
        return found

    outward_indexes = indexes(_OUTWARD_RE)
    sensitive_indexes = indexes(_SENSITIVE_RE)
    if not outward_indexes or not sensitive_indexes:
        return False
    return any(abs(i - j) <= max_token_gap for i in outward_indexes for j in sensitive_indexes)


def family_hits(text: str, variant: str = "BROAD") -> list[str]:
    """Return matching family reason tags for BROAD or COOCCUR selection."""
    variant = variant.upper()
    if variant not in {"BROAD", "COOCCUR"}:
        raise ValueError("variant must be BROAD or COOCCUR")
    hits = []
    for family, patterns in _FAMILY_RE.items():
        if family == "outward_exposure":
            matched = _has_near_outward_sensitive_pair(text)
        else:
            matched = any(pattern.search(text) for pattern in patterns)
        if not matched:
            continue
        if variant == "COOCCUR" and not _has_context(text):
            continue
        hits.append(f"family:{family}")
    return hits


def instruction_signals_v2(text: str, variant: str = "BROAD") -> list[str]:
    """Preserve all v1 signals and add the selected v2 family cues."""
    return list(dict.fromkeys(v1_instruction_signals(text) + family_hits(text, variant)))


def is_instruction_like_v2(text: str, variant: str = "BROAD") -> bool:
    return bool(instruction_signals_v2(text, variant))
