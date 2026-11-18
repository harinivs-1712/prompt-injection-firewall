"""Sanitized view helpers for splitting stored text at span boundaries."""
from __future__ import annotations

from typing import Any


def merge_spans(spans: list[dict[str, Any]], text_len: int) -> list[dict[str, Any]]:
    """Merge overlapping and adjacent spans, discarding spans outside the text."""
    valid: list[dict[str, Any]] = []
    for s in spans:
        if not isinstance(s, dict):
            continue
        start = s.get("start")
        end = s.get("end")
        if not isinstance(start, int) or not isinstance(end, int):
            continue
        # Discard spans completely outside the text or inverted
        if start < 0 or start >= text_len or end <= start:
            continue
        end = min(text_len, end)
        lvl = str(s.get("level") or "medium").lower()
        level_str = "high" if lvl == "high" else "medium"
        valid.append({"start": start, "end": end, "level": level_str})

    if not valid:
        return []

    valid.sort(key=lambda x: (x["start"], x["end"]))
    merged: list[dict[str, Any]] = []
    for s in valid:
        if not merged:
            merged.append(dict(s))
            continue
        cur = merged[-1]
        # Overlapping or adjacent
        if s["start"] <= cur["end"]:
            cur["end"] = max(cur["end"], s["end"])
            if cur["level"] == "high" or s["level"] == "high":
                cur["level"] = "high"
        else:
            merged.append(dict(s))
    return merged


def split_text_into_pieces(text: str, merged_spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Split text into plain text chunks and labeled suspicious pieces."""
    if not text:
        return []
    pieces: list[dict[str, Any]] = []
    idx = 0
    text_len = len(text)
    for span in merged_spans:
        start = max(0, min(text_len, span["start"]))
        end = max(0, min(text_len, span["end"]))
        if start > idx:
            pieces.append({"text": text[idx:start], "level": None})
        if end > start:
            pieces.append({"text": text[start:end], "level": span.get("level")})
        idx = max(idx, end)
    if idx < text_len:
        pieces.append({"text": text[idx:text_len], "level": None})
    return pieces


def build_masked_pieces(
    original_text: str | None,
    masked_text: str | None,
    merged_spans: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Split masked text into pieces corresponding to unmasked text and masked spans."""
    if not masked_text:
        return []
    if not original_text or not merged_spans:
        return [{"text": masked_text, "level": None}]

    pieces: list[dict[str, Any]] = []
    pos = 0
    orig_pos = 0
    aligned = True

    for i, s in enumerate(merged_spans):
        prefix = original_text[orig_pos : s["start"]]
        if prefix:
            if not masked_text[pos:].startswith(prefix):
                aligned = False
                break
            pieces.append({"text": prefix, "level": None})
            pos += len(prefix)
        orig_pos = s["end"]

        next_s_start = merged_spans[i + 1]["start"] if i + 1 < len(merged_spans) else len(original_text)
        sep = original_text[orig_pos:next_s_start]

        if sep:
            find_idx = masked_text.find(sep, pos)
            if find_idx == -1:
                aligned = False
                break
            masked_chunk = masked_text[pos:find_idx]
            pieces.append({"text": masked_chunk, "level": s["level"]})
            pos = find_idx
        else:
            masked_chunk = masked_text[pos:]
            pieces.append({"text": masked_chunk, "level": s["level"]})
            pos = len(masked_text)

    if aligned and pos <= len(masked_text):
        remaining = masked_text[pos:]
        if remaining:
            pieces.append({"text": remaining, "level": None})
        return pieces

    return [{"text": masked_text, "level": None}]
