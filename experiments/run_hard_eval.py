"""Run the frozen Gemini judge once for every held-out hard-eval segment."""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import judge_config
from experiments.hard_eval_common import (
    CASCADE_PATH, HARD_CACHE_PATH, HARD_TASKS_PATH, JUDGED_ALL_PATH,
    RUN_METADATA_PATH, SCORED_PATH, verify_frozen_manifest,
)
from experiments.run_judge import JUDGE_OUTPUT_FIELDS, JudgeCache, _to_cache_item, cache_key
from layers.judge import GeminiJudge, build_judge_prompt


class JudgeLike(Protocol):
    def judge_segment(self, user_task: str, context_note: str, segment_text: str) -> dict[str, Any]: ...


class HardEvalRequestFailed(RuntimeError):
    """A judge request failed; stop rather than spending retries on later segments."""


class CompositeCache:
    """Read the existing shared cache without modifying it; append locally."""

    def __init__(self, local_path: Path, existing_path: Path) -> None:
        self.local = JudgeCache(local_path)
        self.existing = JudgeCache(existing_path)

    def get(self, key):
        # A failed response is diagnostic state, not a reusable judge result.
        # Treat it as a cache miss so a resumed run retries transient API errors.
        item = self.local.get(key) or self.existing.get(key)
        if item is not None and item.get("judge_output", {}).get("judge_error"):
            return None
        return item

    def append(self, item):
        self.local.append(item)


def is_selected(record: dict[str, Any]) -> bool:
    return bool(record.get("is_instruction_like")) or float(record.get("piguard_injection_score", 0.0)) >= judge_config.PIGUARD_THRESHOLD


def _task_for(tasks: dict[str, Any], record: dict[str, Any]) -> dict[str, str]:
    task = tasks.get(record["doc_id"])
    if not task or not task.get("user_task") or not task.get("context_note"):
        raise KeyError(f"Missing static task/context for {record['doc_id']}")
    return task


def merge_cached(records: list[dict[str, Any]], tasks: dict[str, Any], cache: CompositeCache) -> list[dict[str, Any]]:
    merged = []
    for record in records:
        row = {**record, **JUDGE_OUTPUT_FIELDS}
        task = _task_for(tasks, record)
        cached = cache.get(cache_key(judge_config.MODEL_NAME, judge_config.PROMPT_VERSION, record["segment_id"], task["user_task"]))
        if cached:
            row.update(cached["judge_output"])
            row["judge_ran"] = True
            row["judge_model"] = cached["model"]
        merged.append(row)
    return merged


def _cascade_view(judged_all: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for row in judged_all:
        if is_selected(row):
            result.append(row)
        else:
            result.append({**row, **JUDGE_OUTPUT_FIELDS})
    return result


def judge_missing(
    records: list[dict[str, Any]], tasks: dict[str, Any], cache: CompositeCache,
    judge: JudgeLike, limit: int | None = None,
) -> tuple[list[dict[str, Any]], int, int, float]:
    """Judge each uncached segment once, appending each result immediately."""
    pending = []
    seen_ids = set()
    for row in records:
        if row["segment_id"] in seen_ids:
            raise ValueError(f"Duplicate hard-eval segment ID: {row['segment_id']}")
        seen_ids.add(row["segment_id"])
        task = _task_for(tasks, row)
        key = cache_key(judge_config.MODEL_NAME, judge_config.PROMPT_VERSION, row["segment_id"], task["user_task"])
        if cache.get(key) is None:
            pending.append(row)
    if limit is not None:
        pending = pending[:limit]
    started = time.monotonic()
    logical_calls = api_calls = 0
    for row in pending:
        task = _task_for(tasks, row)
        outcome = judge.judge_segment(task["user_task"], task["context_note"], row["text"])
        item = _to_cache_item(row, task, outcome, "hard_eval")
        cache.append(item)
        logical_calls += 1
        api_calls += int(item.get("api_call_count", 0))
        state = "ERROR" if outcome.get("judge_error") else "judged"
        print(f"{state}: {row['segment_id']}", flush=True)
        if outcome.get("judge_error"):
            error_type = item.get("error_type") or "UnknownJudgeError"
            raise HardEvalRequestFailed(
                f"Judge request failed for {row['segment_id']} ({error_type}); "
                "successful responses remain resumable in the hard-eval cache."
            )
    elapsed = time.monotonic() - started
    return merge_cached(records, tasks, cache), logical_calls, api_calls, elapsed


def estimate_seconds(calls: int, rpm: int) -> int:
    return 0 if calls <= 0 else math.ceil(calls * 60 / rpm)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Judge every held-out segment once; derive cascade afterwards.")
    parser.add_argument("--rpm", type=int, default=judge_config.RPM_LIMIT)
    parser.add_argument("--limit", type=int, default=None, help="Maximum new judgments for this resumable run.")
    parser.add_argument("--dry-run", action="store_true", help="Print counts/ETA and do not call Gemini.")
    parser.add_argument("--yes", action="store_true", help="Confirm the API calls after the preflight estimate.")
    parser.add_argument("--allow-changed", action="store_true", help="Proceed with a loud warning if frozen Layer 1 changed.")
    args = parser.parse_args(argv)
    if args.rpm < 1:
        parser.error("--rpm must be at least 1")
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must be nonnegative")
    try:
        manifest_status = verify_frozen_manifest(allow_changed=args.allow_changed)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if not SCORED_PATH.exists():
        print(f"Missing {SCORED_PATH}; run experiments/score_hard_eval.py first.", file=sys.stderr)
        return 1
    records = json.loads(SCORED_PATH.read_text(encoding="utf-8"))
    tasks = json.loads(HARD_TASKS_PATH.read_text(encoding="utf-8"))
    if len(records) > 450:
        print(f"STOP: {len(records)} all-segment judge calls would exceed the approximately 450-call budget. Shorten documents; none were skipped.", file=sys.stderr)
        return 1
    if len({row["segment_id"] for row in records}) != len(records):
        print("Duplicate segment IDs found; refusing to judge twice.", file=sys.stderr)
        return 1

    cache = CompositeCache(HARD_CACHE_PATH, judge_config.JUDGE_CACHE_PATH)
    uncached = []
    for row in records:
        task = _task_for(tasks, row)
        if cache.get(cache_key(judge_config.MODEL_NAME, judge_config.PROMPT_VERSION, row["segment_id"], task["user_task"])) is None:
            uncached.append(row)
    selected_count = sum(is_selected(row) for row in records)
    scheduled = min(len(uncached), args.limit) if args.limit is not None else len(uncached)
    print(f"Segments total: {len(records)}; cache hits: {len(records)-len(uncached)}; uncached all-segment calls needed: {len(uncached)}.")
    print(f"Test 1 cascade call count: {selected_count}/{len(records)} segments; estimated time at {args.rpm} RPM: {estimate_seconds(selected_count,args.rpm)} seconds.")
    print(f"Test 2 judge-on-all call count: {len(records)}/{len(records)} segments; estimated time at {args.rpm} RPM: {estimate_seconds(len(records),args.rpm)} seconds.")
    print(f"This run would make {scheduled} new logical request(s); estimated time: {estimate_seconds(scheduled,args.rpm)} seconds.")
    if len(uncached) > 450:
        print("STOP: more than about 450 uncached judge calls are needed. Shorten the documents instead of skipping segments.", file=sys.stderr)
        return 1
    if args.dry_run or not args.yes:
        if not args.dry_run:
            print("No API calls made. Re-run with --yes after reviewing the count and estimate.")
        return 0

    if not os.environ.get(judge_config.API_KEY_ENV):
        print(f"Error: {judge_config.API_KEY_ENV} is not set in this terminal; no Gemini requests were made.", file=sys.stderr)
        return 1
    try:
        judge = GeminiJudge(rpm=args.rpm)
        judged, logical_calls, api_calls, elapsed = judge_missing(records, tasks, cache, judge, limit=args.limit)
    except HardEvalRequestFailed as exc:
        print(f"Judge run stopped: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        # SDK exception strings are withheld to avoid accidentally exposing credentials.
        print(f"Judge run stopped ({type(exc).__name__}); any completed requests remain resumable in the hard-eval cache.", file=sys.stderr)
        return 1
    cascade = _cascade_view(judged)
    cached_items = []
    for row in records:
        task = _task_for(tasks, row)
        item = cache.get(cache_key(judge_config.MODEL_NAME, judge_config.PROMPT_VERSION, row["segment_id"], task["user_task"]))
        if item is not None:
            cached_items.append(item)
    cumulative_api_calls = sum(int(item.get("api_call_count", 0)) for item in cached_items)
    cumulative_latency_ms = sum(
        sum(int(value) for value in item.get("attempt_latencies_ms", []))
        for item in cached_items
    )
    JUDGED_ALL_PATH.write_text(json.dumps(judged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    CASCADE_PATH.write_text(json.dumps(cascade, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    RUN_METADATA_PATH.write_text(json.dumps({
        "manifest_sha256": manifest_status["manifest_sha256"],
        "changed_components": manifest_status["changed_components"],
        "warning": manifest_status.get("warning"),
        "total_segments": len(records),
        "cascade_selected_segments": selected_count,
        "judge_ran_segments": sum(bool(row.get("judge_ran")) for row in judged),
        "new_logical_calls_this_run": logical_calls,
        "api_calls_including_retries_this_run": api_calls,
        "elapsed_seconds_this_run": round(elapsed, 3),
        "cumulative_logical_judgments": len(cached_items),
        "cumulative_api_calls_including_retries": cumulative_api_calls,
        "cumulative_request_latency_ms": cumulative_latency_ms,
        "rpm": args.rpm,
        "test1_estimated_seconds": estimate_seconds(selected_count, args.rpm),
        "test2_estimated_seconds": estimate_seconds(len(records), args.rpm),
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Saved both judge views. New logical calls: {logical_calls}; API calls including retries: {api_calls}; elapsed: {elapsed:.1f}s.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
