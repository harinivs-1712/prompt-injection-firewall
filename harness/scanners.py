"""Deterministic no-network scanners for output-inspection examples and tests."""
from __future__ import annotations

import re

from firewall.types import ScanOutcome, SegmentRecord


class ScriptedScanner:
    def scan(self, content, *, doc_id, source_type, user_task, context_note=None, max_judge_calls=None):
        spans, start = [], 0
        for match in re.finditer(r"(?<=[.!?])\s+|\n+", content):
            if content[start:match.start()].strip():
                spans.append((start, match.start()))
            start = match.end()
        if content[start:].strip():
            spans.append((start, len(content)))
        records = []
        for index, (begin, end) in enumerate(spans):
            text = content[begin:end]
            if "[[HIGH]]" in text:
                level, judged = "high", True
            elif "[[MEDIUM]]" in text:
                level, judged = "medium", True
            elif "[[UNREVIEWED]]" in text:
                level, judged = "needs_review", False
            else:
                level, judged = "none", True
            records.append(SegmentRecord(f"{doc_id}-s{index:04d}", doc_id, source_type,
                                         begin, end, text, level, judged,
                                         "reviewed" if judged else "budget_exhausted", False, False))
        reviewed = sum(item.judge_ran for item in records)
        coverage = reviewed / len(records) if records else 1.0
        return ScanOutcome(tuple(records), 0, coverage)


class FailingScanner:
    def scan(self, content, *, doc_id, source_type, user_task, context_note=None, max_judge_calls=None):
        raise RuntimeError("simulated scanner failure")
