"""Lazy adapter from the frozen Layer 1 scan pipeline to neutral firewall types."""
from __future__ import annotations

import importlib
import os
from typing import Any

from firewall.types import ScanOutcome, SegmentRecord


class ScannerUnavailable(RuntimeError):
    """The configured scanner could not produce a trusted scan result."""


class Layer1Scanner:
    def __init__(self, mode="all", offline_cache_only=True, judge=None, legacy_cache=False):
        if mode not in {"all", "cascade"}:
            raise ValueError("mode must be 'all' or 'cascade'")
        if type(offline_cache_only) is not bool or type(legacy_cache) is not bool:
            raise TypeError("scanner flags must be booleans")
        self.mode = mode
        self.offline_cache_only = offline_cache_only
        self.judge = judge
        self.legacy_cache = legacy_cache

    def scan(self, content, *, doc_id, source_type, user_task, context_note=None, max_judge_calls=None):
        try:
            judge = None
            if not self.offline_cache_only:
                if not os.environ.get("GEMINI_API_KEY"):
                    raise ScannerUnavailable("Live scan mode requires GEMINI_API_KEY.")
                judge = self.judge
                if judge is None:
                    layer1_judge = importlib.import_module("firewall.layer1.judge")
                    judge = layer1_judge.GeminiJudge(rpm=5)
            scan_module = importlib.import_module("firewall.layer1.scan")
            result = scan_module.scan(
                content, doc_id=doc_id, source_type=source_type, user_task=user_task,
                context_note=context_note, mode=self.mode, max_judge_calls=max_judge_calls,
                judge=judge, legacy_cache=self.legacy_cache,
            )
            rows = getattr(result, "segments", None)
            summary = getattr(result, "summary", None)
            if rows is None and isinstance(result, dict):
                rows, summary = result.get("segments"), result.get("summary", {})
            if not isinstance(rows, (list, tuple)) or not isinstance(summary, dict):
                raise ValueError("invalid scan result")
            segments = tuple(SegmentRecord(
                segment_id=str(row["segment_id"]), doc_id=str(row.get("doc_id", doc_id)),
                source_type=str(row.get("source_type", source_type)), start=int(row["start"]),
                end=int(row["end"]), text=row["text"], suspicion_level=row["suspicion_level"],
                judge_ran=bool(row.get("judge_ran", False)),
                coverage_reason=row.get("judge_coverage_reason"),
                rules_flag=row.get("rules_flag"), piguard_flag=row.get("piguard_flag"),
                instruction_reasons=tuple(str(x) for x in row.get("instruction_reasons", ())),
                piguard_label=row.get("piguard_label"), piguard_score=row.get("piguard_score"),
                judge_is_instruction=row.get("judge_is_instruction"),
                judge_needed_for_task=row.get("judge_needed_for_task"),
                judge_flag=row.get("judge_flag"), judge_reason=row.get("judge_reason"),
            ) for row in rows)
            return ScanOutcome(segments, int(summary.get("judge_calls_made", 0)),
                               float(summary.get("coverage_fraction", 1.0)))
        except ScannerUnavailable:
            raise
        except Exception:
            raise ScannerUnavailable("Layer 1 scan failed; content was not cleared for the agent.") from None
