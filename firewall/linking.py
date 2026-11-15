"""Value-free provenance matching between external segments and pending calls."""
from __future__ import annotations

import difflib
import re
import unicodedata
from dataclasses import dataclass
from decimal import Decimal
from urllib.parse import urlsplit

from firewall.cleaning import domain_of, normalize_account, normalize_amount, normalize_path, normalize_recipient, normalize_url


_LEVEL_ORDER = {"NONE": 0, "POSSIBLE": 1, "LIKELY": 2, "CONFIRMED": 3}
_SEGMENT_LEVEL = {"none": "NONE", "low": "NONE", "medium": "LIKELY", "high": "CONFIRMED", "needs_review": "POSSIBLE"}
_ZERO_WIDTH = re.compile("[\\u200b-\\u200f\\u202a-\\u202e\\u2060\\ufeff]")
_ADDRESS_TOKEN = re.compile(r"[^\s<>(),;]+@[^\s<>(),;]+")
_URL_TOKEN = re.compile(r"https?://[^\s<>\"']+", re.I)
_IDENT_TOKEN = re.compile(r"(?<!\w)[\w.-]+(?!\w)", re.UNICODE)
_ACCOUNT_TOKEN = re.compile(r"(?<!\w)(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9][A-Za-z0-9_-]{4,}(?!\w)")
_AMOUNT_TOKEN = re.compile(r"(?<!\w)(?:\d{1,3}(?:,\d{2})*,\d{3}|\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?(?!\w)")
_PATH_TOKEN = re.compile(r"(?<!\w)(?:[A-Za-z]:)?[/\\][\w .-]+(?:[/\\][\w .-]+)*")
_IRREGULAR = {"send": {"sent"}, "pay": {"paid"}, "buy": {"bought"}, "give": {"gave"}, "leave": {"left"}}


@dataclass(frozen=True)
class LinkEvidence:
    kind: str
    arg_name: str | None
    segment_id: str
    segment_level: str
    match_type: str
    score: float
    user_provided: bool


@dataclass(frozen=True)
class LinkReport:
    evidence: tuple[LinkEvidence, ...]
    link_level: str
    user_provided_args: tuple[str, ...]
    reason_codes: tuple[str, ...]


def _canonical(value):
    if not isinstance(value, str):
        return ""
    value = unicodedata.normalize("NFKC", value)
    value = _ZERO_WIDTH.sub("", value)
    return "".join(ch.casefold() for ch in value if not ch.isspace())


def _words(value):
    normalized = unicodedata.normalize("NFKC", value).casefold()
    normalized = _ZERO_WIDTH.sub("", normalized)
    return re.findall(r"\b[\w]+\b", normalized)


def _shingles(value, size):
    words = _words(value)
    if len(words) < size:
        return set()
    return {tuple(words[i:i + size]) for i in range(len(words) - size + 1)}


def _significant_digits(value):
    digits = re.sub(r"\D", "", str(value)).lstrip("0")
    return len(digits)


def _path_occurs(target, text):
    haystack = unicodedata.normalize("NFKC", text).replace("\\", "/").casefold()
    needle = unicodedata.normalize("NFKC", target).replace("\\", "/").casefold()
    start = 0
    while True:
        index = haystack.find(needle, start)
        if index < 0:
            return False
        before = haystack[index - 1] if index else ""
        after_index = index + len(needle)
        after = haystack[after_index] if after_index < len(haystack) else ""
        before_ok = not before or before.isspace() or before in "'\"([{:;,"
        after_ok = not after or after.isspace() or after == "/" or after in "'\")]}:,;!?"
        if after == "." and after_index + 1 < len(haystack) and haystack[after_index + 1].isalnum():
            after_ok = False
        if before_ok and after_ok:
            return True
        start = index + 1


def _amounts(text):
    output = []
    for match in _AMOUNT_TOKEN.finditer(text):
        normalized = normalize_amount(match.group(0))
        if normalized is not None:
            output.append(normalized)
    return output


def _candidate_values(arg_type, segment_text, settings):
    canonical_text = _canonical(segment_text)
    if arg_type == "recipient":
        values = []
        for candidate in _ADDRESS_TOKEN.findall(segment_text):
            normalized = normalize_recipient(candidate)
            if normalized:
                values.append(normalized)
        return values
    if arg_type == "url":
        values = []
        for candidate in _URL_TOKEN.findall(segment_text):
            normalized = normalize_url(candidate.rstrip(".,;:!?)]}"))
            if normalized:
                values.append(normalized)
        return values
    if arg_type == "account":
        return [normalize_account(token) for token in _ACCOUNT_TOKEN.findall(segment_text)]
    if arg_type == "amount":
        return _amounts(segment_text)
    if arg_type == "identifier":
        return [token for token in _IDENT_TOKEN.findall(segment_text)
                if len(_canonical(token)) >= settings["min_identifier_len"]]
    if arg_type == "path":
        paths = []
        for candidate in _PATH_TOKEN.findall(segment_text):
            normalized = normalize_path(candidate.rstrip(".,;:!?"))
            if normalized:
                paths.append(normalized)
        return paths
    return canonical_text


def _match(arg_type, value, segment_text, settings):
    """Return a value-free (match_type, score), or None."""
    if arg_type == "recipient":
        normalized = normalize_recipient(value)
        if not normalized:
            return None
        target = _canonical(normalized)
        haystack = _canonical(segment_text)
        if target in haystack:
            return "exact", 1.0
        for candidate in _candidate_values(arg_type, segment_text, settings):
            ratio = difflib.SequenceMatcher(None, target, _canonical(candidate), autojunk=False).ratio()
            if ratio >= settings["fuzzy_threshold"]:
                return "fuzzy", ratio
        return None
    if arg_type == "account":
        target = normalize_account(value)
        if not target or len(target) < settings["min_account_len"]:
            return None
        return ("exact", 1.0) if target in _candidate_values(arg_type, segment_text, settings) else None
    if arg_type == "amount":
        target = normalize_amount(value)
        if target is None:
            return None
        if target == target.to_integral_value() and _significant_digits(target) < settings["min_amount_digits"]:
            return None
        return ("exact", 1.0) if target in _amounts(segment_text) else None
    if arg_type == "url":
        target = normalize_url(value)
        if not target:
            return None
        candidate_urls = _candidate_values(arg_type, segment_text, settings)
        for candidate in candidate_urls:
            if candidate == target:
                return "exact", 1.0
            left, right = urlsplit(target), urlsplit(candidate)
            if left.hostname == right.hostname and left.path and right.path.startswith(left.path.rstrip("/") + "/"):
                return "exact", 1.0
            ratio = difflib.SequenceMatcher(None, _canonical(target), _canonical(candidate), autojunk=False).ratio()
            if ratio >= settings["fuzzy_threshold"]:
                return "fuzzy", ratio
        return None
    if arg_type == "path":
        target = normalize_path(value)
        if not target:
            return None
        if _path_occurs(target, segment_text):
            return "exact", 1.0
        for candidate in _candidate_values(arg_type, segment_text, settings):
            if target == candidate or target.startswith(candidate.rstrip("/") + "/") or candidate.startswith(target.rstrip("/") + "/"):
                return "exact", 1.0
        return None
    if arg_type == "identifier":
        target = str(value)
        if len(_canonical(target)) < settings["min_identifier_len"]:
            return None
        candidates = _candidate_values(arg_type, segment_text, settings)
        if any(_canonical(candidate) == _canonical(target) for candidate in candidates):
            return "exact", 1.0
        best = max((difflib.SequenceMatcher(None, _canonical(target), _canonical(candidate), autojunk=False).ratio()
                    for candidate in candidates), default=0.0)
        return ("fuzzy", best) if best >= settings["fuzzy_threshold"] else None

    arg_text = str(value) if not isinstance(value, (dict, list, tuple)) else " ".join(map(str, value))
    segment_shingles = _shingles(segment_text, settings["shingle_size"])
    arg_shingles = _shingles(arg_text, settings["shingle_size"])
    if len(segment_shingles) < settings["min_shingles"] or not segment_shingles:
        return None
    shared = segment_shingles & arg_shingles
    ratio = len(shared) / len(segment_shingles)
    if len(shared) >= settings["min_shingles"] or ratio >= settings["shingle_containment_threshold"]:
        return "overlap", ratio
    return None


def _level_for(record):
    if record.suspicion_level == "needs_review" or not record.judge_ran:
        return "POSSIBLE"
    return _SEGMENT_LEVEL.get(record.suspicion_level, "NONE")


def _record_from_entry(entry):
    if hasattr(entry, "suspicion_level"):
        return entry
    if isinstance(entry, dict):
        return entry.get("record", entry)
    return None


def _verb_forms(verb, extras):
    forms = {verb}
    forms.update(_IRREGULAR.get(verb, ()))
    if verb.endswith("e"):
        forms.add(verb + "s")
        forms.add(verb + "d")
        forms.add(verb[:-1] + "ing")
    else:
        forms.update({verb + "s", verb + "es", verb + "ed", verb + "ing"})
        if len(verb) > 2 and verb.endswith("y"):
            forms.add(verb[:-1] + "ies")
    forms.update(extras.get(verb, ()))
    return forms


def find_links(session, policy, tool_name, args) -> LinkReport:
    settings = policy.link_matching
    evidence = []
    user_provided_args = []
    reasons = []
    strongest = "NONE"
    segments = session.segments
    scan_limit = False
    for entry in segments[:settings["max_segments"]]:
        record = _record_from_entry(entry)
        if record is None:
            continue
        if len(record.text) > settings["max_chars_per_segment"]:
            scan_limit = True
    if len(segments) > settings["max_segments"]:
        scan_limit = True
    selected = segments[:settings["max_segments"]]

    tool = policy.get_tool(tool_name)
    declared = tool.args if tool is not None else {}
    for arg_name, spec in declared.items():
        if arg_name not in args:
            continue
        raw = args[arg_name]
        values = raw if spec.type == "recipient" and isinstance(raw, list) else [raw]
        user_values = {index for index, value in enumerate(values)
                       if _match(spec.type, value, session.user_task, settings)}
        if user_values:
            user_provided_args.append(arg_name)
            reasons.append("USER_PROVIDED_VALUE")
        for entry in selected:
            record = _record_from_entry(entry)
            if record is None or len(record.text) > settings["max_chars_per_segment"]:
                continue
            for value_index, value in enumerate(values):
                if value_index in user_values:
                    continue
                matched = _match(spec.type, value, record.text, settings)
                if not matched:
                    continue
                match_type, score = matched
                level = _level_for(record)
                if level == "CONFIRMED":
                    kind, reason = "arg_match", "ARG_MATCHES_HIGH_SUSPICION_SEGMENT"
                elif level == "LIKELY":
                    kind, reason = "arg_match", "ARG_MATCHES_MEDIUM_SUSPICION_SEGMENT"
                elif level == "POSSIBLE":
                    kind, reason = "arg_match", "ARG_MATCHES_UNREVIEWED_SEGMENT"
                else:
                    kind, reason = "arg_match", "ARG_FROM_UNTRUSTED_UNFLAGGED"
                candidate = LinkEvidence(kind, arg_name, record.segment_id, record.suspicion_level,
                                         match_type, max(0.0, min(1.0, float(score))), False)
                old_index = next((i for i, old in enumerate(evidence)
                                  if old.arg_name == arg_name and old.segment_id == record.segment_id and old.kind == kind), None)
                if old_index is None:
                    evidence.append(candidate)
                elif candidate.score > evidence[old_index].score:
                    evidence[old_index] = candidate
                reasons.append(reason)
                if _LEVEL_ORDER[level] > _LEVEL_ORDER[strongest]:
                    strongest = level

    extras = policy.verb_forms
    for entry in selected:
        record = _record_from_entry(entry)
        if record is None or record.suspicion_level not in {"medium", "high"}:
            continue
        text_words = set(_words(record.text))
        for verb, tools in policy.verb_to_tool.items():
            if tool_name not in tools:
                continue
            forms = _verb_forms(verb.casefold(), extras)
            if forms & text_words:
                level = "LIKELY" if record.suspicion_level == "high" else "POSSIBLE"
                evidence.append(LinkEvidence("intent_match", None, record.segment_id,
                                             record.suspicion_level, "verb", 1.0, False))
                reasons.append("INTENT_MATCHES_FLAGGED_SEGMENT")
                if _LEVEL_ORDER[level] > _LEVEL_ORDER[strongest]:
                    strongest = level

    if policy.session_taint and tool is not None and (tool.risk == "high" or tool.side_effects):
        for entry in selected:
            record = _record_from_entry(entry)
            if record is not None and record.suspicion_level in {"medium", "high"}:
                evidence.append(LinkEvidence("session_taint", None, record.segment_id,
                                             record.suspicion_level, "taint", 1.0, False))
                reasons.append("SESSION_TAINTED_HIGH_RISK")
                strongest = max((strongest, "POSSIBLE"), key=lambda level: _LEVEL_ORDER[level])

    if scan_limit:
        reasons.append("LINK_SCAN_LIMIT")
        strongest = max((strongest, "POSSIBLE"), key=lambda level: _LEVEL_ORDER[level])
    # Evidence can share a segment/argument; retain only strongest level for that pair.
    deduped = {}
    for item in evidence:
        key = (item.kind, item.arg_name, item.segment_id)
        previous = deduped.get(key)
        if previous is None or _LEVEL_ORDER[_level_for_evidence(item)] > _LEVEL_ORDER[_level_for_evidence(previous)]:
            deduped[key] = item
    return LinkReport(tuple(deduped.values()), strongest, tuple(dict.fromkeys(user_provided_args)),
                      tuple(dict.fromkeys(reasons)))


def _level_for_evidence(item):
    if item.kind == "intent_match":
        return "LIKELY" if item.segment_level == "high" else "POSSIBLE"
    if item.kind == "session_taint":
        return "POSSIBLE"
    if item.segment_level == "high":
        return "CONFIRMED"
    if item.segment_level == "medium":
        return "LIKELY"
    if item.segment_level == "needs_review" or item.match_type == "taint":
        return "POSSIBLE"
    return "NONE"
