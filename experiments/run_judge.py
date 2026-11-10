"""Run the context-aware judge on selected Day 2 segments or legit controls."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import judge_config as cfg
from layers.judge import GeminiJudge, build_judge_prompt

JUDGE_OUTPUT_FIELDS = {
    "judge_ran": False,
    "judge_is_instruction": None,
    "judge_needed_for_task": None,
    "judge_reason": None,
    "judge_flag": None,
    "judge_error": False,
    "judge_model": cfg.MODEL_NAME,
    "judge_latency_ms": None,
}


class JudgeLike(Protocol):
    def judge_segment(self, user_task: str, context_note: str, segment_text: str) -> dict[str, Any]: ...


def cache_key(model: str, prompt_version: str, segment_id: str, user_task: str) -> tuple[str, str, str, str]:
    return model, prompt_version, segment_id, user_task


def select_segments(
    records: list[dict[str, Any]], split: str = "all", threshold: float = cfg.PIGUARD_THRESHOLD,
) -> list[dict[str, Any]]:
    """Select the OR of rule and PIGuard candidates, restricted to a split."""
    if split not in {"tuning", "test", "all"}:
        raise ValueError("split must be tuning, test, or all")
    selected = []
    for record in records:
        if split != "all" and record.get("split") != split:
            continue
        if bool(record.get("is_instruction_like")) or float(record.get("piguard_injection_score", 0.0)) >= threshold:
            selected.append(record)
    return selected


class JudgeCache:
    """Append-only JSONL cache; records contain no raw API key or full prompt."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.records: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        if path.exists():
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    try:
                        item = json.loads(line)
                        key = cache_key(item["model"], item["prompt_version"], item["segment_id"], item["user_task"])
                        self.records[key] = item
                    except (json.JSONDecodeError, KeyError, TypeError):
                        continue

    def get(self, key: tuple[str, str, str, str]) -> dict[str, Any] | None:
        return self.records.get(key)

    def append(self, item: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
            handle.flush()
        key = cache_key(item["model"], item["prompt_version"], item["segment_id"], item["user_task"])
        self.records[key] = item


def _unjudged(record: dict[str, Any]) -> dict[str, Any]:
    return {**record, **JUDGE_OUTPUT_FIELDS}


def _apply_cached(record: dict[str, Any], cached: dict[str, Any]) -> dict[str, Any]:
    result = _unjudged(record)
    result.update(cached["judge_output"])
    result["judge_ran"] = True
    result["judge_model"] = cached["model"]
    return result


def _to_cache_item(
    record: dict[str, Any], task: dict[str, str], outcome: dict[str, Any], dataset: str,
) -> dict[str, Any]:
    output = {field: outcome.get(field) for field in (
        "judge_is_instruction", "judge_needed_for_task", "judge_reason", "judge_flag",
        "judge_error", "judge_latency_ms",
    )}
    output["judge_ran"] = True
    output["judge_model"] = cfg.MODEL_NAME
    return {
        "model": cfg.MODEL_NAME,
        "prompt_version": cfg.PROMPT_VERSION,
        "segment_id": record["segment_id"],
        "doc_id": record["doc_id"],
        "user_task": task["user_task"],
        "dataset": dataset,
        "judge_output": output,
        "api_call_count": int(outcome.get("_api_call_count", 0)),
        "token_usage": outcome.get("_token_usage", {}),
        "attempt_latencies_ms": outcome.get("_attempt_latencies_ms", []),
        "error_type": outcome.get("_error_type"),
    }


def load_tasks() -> dict[str, dict[str, str]]:
    return json.loads(cfg.TASKS_PATH.read_text(encoding="utf-8"))


def load_main_records() -> list[dict[str, Any]]:
    return json.loads(cfg.SCORED_SEGMENTS_PATH.read_text(encoding="utf-8"))


def load_legit_records(tasks: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    from layers.segmenter import make_segments

    labels = json.loads(cfg.LEGIT_LABELS_PATH.read_text(encoding="utf-8"))
    records: list[dict[str, Any]] = []
    for document in labels["documents"]:
        doc_id = document["doc_id"]
        text = (cfg.ROOT / "data" / "labeled_legit" / f"{doc_id}.txt").read_text(encoding="utf-8")
        if doc_id not in tasks:
            raise KeyError(f"No static task/context configured for {doc_id}")
        records.extend(make_segments(doc_id, text, window=3, stride=1))
    return records


def _task_for(tasks: dict[str, dict[str, str]], record: dict[str, Any]) -> dict[str, str]:
    task = tasks.get(record["doc_id"])
    if not task or not task.get("user_task") or not task.get("context_note"):
        raise KeyError(f"Missing user_task/context_note for {record['doc_id']} in config/tasks.json")
    return task


def _merge_run(
    records: list[dict[str, Any]],
    tasks: dict[str, dict[str, str]],
    cache: JudgeCache,
    judge: JudgeLike | None,
    selected: list[dict[str, Any]],
    limit: int | None,
    dataset: str,
) -> tuple[list[dict[str, Any]], int, int]:
    merged = [_unjudged(record) for record in records]
    index_by_id = {record["segment_id"]: index for index, record in enumerate(records)}

    # Rebuild all previous results from the cache, including records in the split
    # not selected by this invocation, so tuning and test runs accumulate safely.
    for record in records:
        task = _task_for(tasks, record)
        key = cache_key(cfg.MODEL_NAME, cfg.PROMPT_VERSION, record["segment_id"], task["user_task"])
        cached = cache.get(key)
        if cached is not None:
            merged[index_by_id[record["segment_id"]]] = _apply_cached(record, cached)

    new_records = [
        record for record in selected
        if cache.get(cache_key(cfg.MODEL_NAME, cfg.PROMPT_VERSION, record["segment_id"], _task_for(tasks, record)["user_task"])) is None
    ]
    if limit is not None:
        new_records = new_records[:limit]
    if new_records and judge is None:
        raise RuntimeError(f"{cfg.API_KEY_ENV} is not set; no Gemini requests were made.")

    logical_requests = 0
    api_calls = 0
    for record in new_records:
        task = _task_for(tasks, record)
        outcome = judge.judge_segment(task["user_task"], task["context_note"], record["text"])  # type: ignore[union-attr]
        cache_item = _to_cache_item(record, task, outcome, dataset)
        cache.append(cache_item)
        logical_requests += 1
        api_calls += cache_item["api_call_count"]
        merged[index_by_id[record["segment_id"]]] = _apply_cached(record, cache_item)
        status = "error" if outcome.get("judge_error") else "judged"
        print(f"{status}: {record['segment_id']}")
    return merged, logical_requests, api_calls


def _write_json(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _dry_run(
    selected: list[dict[str, Any]], tasks: dict[str, dict[str, str]], cache: JudgeCache, limit: int | None,
) -> None:
    uncached = []
    for record in selected:
        task = _task_for(tasks, record)
        key = cache_key(cfg.MODEL_NAME, cfg.PROMPT_VERSION, record["segment_id"], task["user_task"])
        if cache.get(key) is None:
            uncached.append((record, task))
    if limit is not None:
        uncached = uncached[:limit]
    for index, (record, task) in enumerate(uncached[:3], start=1):
        system, message = build_judge_prompt(task["user_task"], task["context_note"], record["text"])
        print(f"--- Prompt {index} / {len(uncached)} ---")
        print("SYSTEM INSTRUCTION:")
        print(system)
        print("\nUSER MESSAGE:")
        print(message)
    print(f"Would make {len(uncached)} logical judge request(s); no API requests made.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Gemini's context-aware judge on selected segments.")
    parser.add_argument("--split", choices=("tuning", "test", "all"), default="all")
    parser.add_argument("--limit", type=int, default=None, help="Maximum new segments to judge in this run.")
    parser.add_argument("--dry-run", action="store_true", help="Print up to three full prompts; never call Gemini.")
    parser.add_argument("--rpm", type=int, default=cfg.RPM_LIMIT, help=f"Maximum requests per minute (default {cfg.RPM_LIMIT}).")
    parser.add_argument("--dataset", choices=("main", "legit"), default="main", help="Judge Day 2 candidates or all content-dependent examples.")
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit < 0:
        parser.error("--limit must be nonnegative")
    if args.rpm < 1:
        parser.error("--rpm must be at least 1")

    tasks = load_tasks()
    if args.dataset == "main":
        records = load_main_records()
        selected = select_segments(records, split=args.split, threshold=cfg.PIGUARD_THRESHOLD)
        output_path = cfg.JUDGED_OUTPUT_PATH
    else:
        records = load_legit_records(tasks)
        if args.split != "all":
            parser.error("--split applies to the Day 2 dataset; use --dataset legit with --split all")
        selected = records
        output_path = cfg.LEGIT_JUDGED_OUTPUT_PATH

    cache = JudgeCache(cfg.JUDGE_CACHE_PATH)
    if args.dry_run:
        _dry_run(selected, tasks, cache, args.limit)
        return 0

    # Do not even construct an SDK client when the chosen work is fully cached.
    uncached = []
    for record in selected:
        task = _task_for(tasks, record)
        if cache.get(cache_key(cfg.MODEL_NAME, cfg.PROMPT_VERSION, record["segment_id"], task["user_task"])) is None:
            uncached.append(record)
    if args.limit is not None:
        uncached = uncached[:args.limit]
    judge: GeminiJudge | None = None
    if uncached:
        try:
            judge = GeminiJudge(rpm=args.rpm)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    try:
        merged, logical, api_calls = _merge_run(records, tasks, cache, judge, selected, args.limit, args.dataset)
    except Exception as exc:
        # Never print SDK exception text: it is unnecessary and must not risk
        # exposing authentication material through a future SDK error message.
        from layers.judge import ModelUnavailableError
        if isinstance(exc, ModelUnavailableError):
            print(f"Error: {exc}", file=sys.stderr)
        else:
            print(f"Error while running judge ({type(exc).__name__}); details were withheld.", file=sys.stderr)
        return 1
    _write_json(output_path, merged)
    print(f"Saved {len(merged)} record(s) to {output_path}")
    print(f"This run judged {logical} new segment(s) using {api_calls} API call(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
