"""High-recall instruction-like signal rules for Layer 1.

These signals are screening hints, not security decisions. spaCy is used when
the package and English model are installed; a small tokenizer fallback keeps
the simple lexical checks usable before model setup is complete.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

SPACY_MODEL = "en_core_web_sm"
POLITE_IMPERATIVE_LEADS = frozenset({"please", "kindly"})
ACTION_VERBS = frozenset({
    "send", "forward", "upload", "delete", "pay", "transfer", "reveal",
    "export", "share", "disclose", "email", "submit", "approve", "grant",
    "change", "follow",
})
ASSISTANT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore", re.compile(r"\bignore\b", re.I)),
    ("disregard", re.compile(r"\bdisregard\b", re.I)),
    ("assistant", re.compile(r"\bassistant\b", re.I)),
    ("system_prompt", re.compile(r"\bsystem\s+prompt\b", re.I)),
    ("you_must", re.compile(r"\byou\s+must\b", re.I)),
    ("you_should", re.compile(r"\byou\s+should\b", re.I)),
    ("ai", re.compile(r"\bAI\b", re.I)),
    ("previous_instructions", re.compile(r"\bprevious\s+instructions\b", re.I)),
)
_WORDS_RE = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?|[^\w\s]", re.UNICODE)


@lru_cache(maxsize=1)
def _load_nlp() -> Any | None:
    try:
        import spacy
        return spacy.load(SPACY_MODEL)
    except (ImportError, OSError):
        return None


def instruction_signals(text: str) -> list[str]:
    """Return deduplicated reasons that *text* resembles an instruction."""
    reasons: list[str] = []
    for name, pattern in ASSISTANT_PATTERNS:
        if pattern.search(text):
            reasons.append(f"pattern:{name}")

    nlp = _load_nlp()
    if nlp is not None:
        doc = nlp(text)
        seen_actions: set[str] = set()
        for token in doc:
            lemma = token.lemma_.lower()
            if token.pos_ == "VERB" and lemma in ACTION_VERBS and lemma not in seen_actions:
                reasons.append(f"action_verb:{lemma}")
                seen_actions.add(lemma)
        for sentence in doc.sents:
            lexical_tokens = [t for t in sentence if not t.is_punct and not t.is_space]
            first = lexical_tokens[0] if lexical_tokens else None
            command = first
            if first is not None and first.text.lower() in POLITE_IMPERATIVE_LEADS:
                command = lexical_tokens[1] if len(lexical_tokens) > 1 else None
            # en_core_web_sm can mis-tag an initial imperative (for example,
            # "Forward" as RB or "Delete" as PROPN); preserve this signal for
            # known action verbs when the sentence has no explicit subject.
            # The optional polite lead-in is skipped ("Please forward...").
            is_base_verb = command is not None and (
                command.tag_ == "VB" or command.text.lower() in ACTION_VERBS
            )
            if is_base_verb and not any(
                t.dep_ in {"nsubj", "nsubjpass", "csubj", "csubjpass"} for t in sentence
            ):
                reasons.append("imperative")
    else:
        # Best-effort lexical fallback; full POS and dependency checks require spaCy.
        words = [w.lower() for w in _WORDS_RE.findall(text) if w[:1].isalpha()]
        for verb in sorted(ACTION_VERBS):
            if verb in words:
                reasons.append(f"action_verb:{verb}")
        if words and words[0] in ACTION_VERBS:
            reasons.append("imperative")

    return list(dict.fromkeys(reasons))


def is_instruction_like(text: str) -> bool:
    """Whether any instruction signal was found."""
    return bool(instruction_signals(text))
