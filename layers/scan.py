"""Unified, offline-safe Layer 1 scan pipeline for untrusted external content."""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from config import judge_config, layer1_settings, threat_config
from config.rules_config import RULES_VERSION
from layers.instruction_rule_router import instruction_signals
from layers.judge import JUDGE_RESPONSE_SCHEMA, JUDGE_SYSTEM_INSTRUCTION, JUDGE_USER_TEMPLATE, judge_flag
from layers.piguard_scorer import MODEL_NAME as PIGUARD_MODEL
from layers.segmenter import make_segments
from layers.suspicion import assess_suspicion

MANIFEST_PATH = layer1_settings.ROOT / "config" / "layer1_final_manifest.json"
_VALID_SOURCE_TYPES = frozenset(layer1_settings.DEFAULT_CONTEXT_NOTES)
_CACHE_MEMORY: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
_PIGUARD_SCORER: Any | None = None


class JudgeLike(Protocol):
    def judge_segment(self, user_task: str, context_note: str, segment_text: str) -> dict[str, Any]: ...


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_components() -> dict[str, Any]:
    """Return the hashes/settings protected by the Layer 1 freeze."""
    root = layer1_settings.ROOT
    return {
        "segmenter": _sha(root / "layers" / "segmenter.py"),
        "segment_settings": {
            "window": layer1_settings.WINDOW,
            "stride": layer1_settings.STRIDE,
            "settings_sha256": _sha(root / "config" / "layer1_settings.py"),
        },
        "rules": {
            "version": RULES_VERSION,
            "router_sha256": _sha(root / "layers" / "instruction_rule_router.py"),
            "rules_config_sha256": _sha(root / "config" / "rules_config.py"),
            "v1_sha256": _sha(root / "layers" / "instruction_rules.py"),
            "v2_sha256": _sha(root / "layers" / "instruction_rules_v2.py"),
        },
        "piguard": {
            "scorer_sha256": _sha(root / "layers" / "piguard_scorer.py"),
            "model": PIGUARD_MODEL,
            "threshold": judge_config.PIGUARD_THRESHOLD,
        },
        "judge": {
            "prompt_sha256": hashlib.sha256((
                JUDGE_SYSTEM_INSTRUCTION + "\0" + JUDGE_USER_TEMPLATE + "\0" +
                json.dumps(JUDGE_RESPONSE_SCHEMA, sort_keys=True)
            ).encode("utf-8")).hexdigest(),
            "prompt_version": judge_config.PROMPT_VERSION,
            "model": judge_config.MODEL_NAME,
        },
        "level_table": {
            "config_sha256": _sha(root / "config" / "threat_config.json"),
            "name": threat_config.ACTIVE_LEVEL_TABLE,
        },
        "scan_settings_sha256": _sha(root / "config" / "layer1_settings.py"),
    }


def _manifest_digest(components: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(components, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def verify_manifest(*, allow_changed: bool = False) -> dict[str, Any]:
    """Verify frozen settings, returning a warning only when explicitly allowed."""
    if not MANIFEST_PATH.exists():
        raise RuntimeError(f"Layer 1 final manifest is missing: {MANIFEST_PATH}")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    current = manifest_components()
    frozen = manifest.get("components", {})
    changed = sorted(key for key in set(current) | set(frozen) if current.get(key) != frozen.get(key))
    if manifest.get("manifest_sha256") != _manifest_digest(frozen):
        changed.append("manifest_sha256")
    changed = sorted(set(changed))
    if changed and not allow_changed:
        raise RuntimeError("Layer 1 frozen manifest mismatch: " + ", ".join(changed))
    return {"manifest_sha256": manifest.get("manifest_sha256"), "changed_components": changed,
            "warning": "Manifest mismatch allowed: " + ", ".join(changed) if changed else None}


def _cache_key(segment_id: str, user_task: str, text_hash: str) -> tuple[str, str, str, str, str]:
    return judge_config.MODEL_NAME, judge_config.PROMPT_VERSION, segment_id, user_task, text_hash


def _load_cache(*, legacy_cache: bool) -> dict[tuple[str, str, str, str, str], dict[str, Any]]:
    items = dict(_CACHE_MEMORY)
    paths = [layer1_settings.SCAN_CACHE_PATH]
    if legacy_cache:
        paths.extend(layer1_settings.LEGACY_CACHE_PATHS)
    for path in paths:
        if not path.exists():
            continue
        try:
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    try:
                        item = json.loads(line)
                        if item.get("model") != judge_config.MODEL_NAME or item.get("prompt_version") != judge_config.PROMPT_VERSION:
                            continue
                        segment_id, task = item["segment_id"], item["user_task"]
                        text_hash = item.get("text_hash")
                        if text_hash is None:
                            if not legacy_cache:
                                continue
                            # Mark legacy entries with an empty hash; they are matched only under the explicit opt-in.
                            text_hash = ""
                        output = item.get("judge_output", item)
                        key = (judge_config.MODEL_NAME, judge_config.PROMPT_VERSION, segment_id, task, text_hash)
                        items[key] = output
                    except (json.JSONDecodeError, KeyError, TypeError):
                        continue
        except OSError:
            continue
    return items


def _cache_get(cache: dict, segment_id: str, task: str, text_hash: str, *, legacy_cache: bool):
    result = cache.get(_cache_key(segment_id, task, text_hash))
    if result is None and legacy_cache:
        result = cache.get(_cache_key(segment_id, task, ""))
    return result


def _valid_judgment(output: dict[str, Any]) -> bool:
    return (not bool(output.get("judge_error", False)) and
            type(output.get("judge_is_instruction")) is bool and
            type(output.get("judge_needed_for_task")) is bool and
            isinstance(output.get("judge_reason"), str) and
            type(output.get("judge_flag")) is bool)


def _append_cache(segment_id: str, task: str, text_hash: str, output: dict[str, Any]) -> None:
    item = {
        "model": judge_config.MODEL_NAME, "prompt_version": judge_config.PROMPT_VERSION,
        "segment_id": segment_id, "user_task": task, "text_hash": text_hash,
        "judge_output": output,
    }
    path = layer1_settings.SCAN_CACHE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(item, ensure_ascii=False) + "\n")
    _CACHE_MEMORY[_cache_key(segment_id, task, text_hash)] = output


def _priority(record: dict[str, Any]) -> tuple[int, float, int]:
    rules, pig = record["rules_flag"], record["piguard_flag"]
    kind = "both" if rules and pig else "rules_only" if rules else "piguard_only" if pig else "unflagged"
    try:
        rank = layer1_settings.JUDGE_PRIORITY.index(kind)
    except ValueError:
        rank = len(layer1_settings.JUDGE_PRIORITY)
    score_order = -record["piguard_score"] if kind == "piguard_only" else 0.0
    return (rank, score_order, record["_order"])


def _new_piguard_scorer():
    """Instantiate PIGuard without allowing a model download from the CLI path."""
    from layers.piguard_scorer import BATCH_SIZE, PIGuardScorer
    old_hub = os.environ.get("HF_HUB_OFFLINE")
    old_transformers = os.environ.get("TRANSFORMERS_OFFLINE")
    if layer1_settings.OFFLINE_CACHE_ONLY:
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
    try:
        return PIGuardScorer(batch_size=BATCH_SIZE)
    finally:
        if old_hub is None:
            os.environ.pop("HF_HUB_OFFLINE", None)
        else:
            os.environ["HF_HUB_OFFLINE"] = old_hub
        if old_transformers is None:
            os.environ.pop("TRANSFORMERS_OFFLINE", None)
        else:
            os.environ["TRANSFORMERS_OFFLINE"] = old_transformers


@dataclass
class ScanResult:
    segments: list[dict[str, Any]]
    summary: dict[str, Any]
    mode: str
    versions: dict[str, Any]

    def segments_overlapping(self, start: int, end: int) -> list[dict[str, Any]]:
        if start < 0 or end < start:
            raise ValueError("span must satisfy 0 <= start <= end")
        return [row for row in self.segments if row["start"] < end and row["end"] > start]

    def max_level(self) -> str:
        return max((row["suspicion_level"] for row in self.segments),
                   key=lambda level: threat_config.LEVEL_ORDER.index(level), default="none")

    def unreviewed_segments(self) -> list[dict[str, Any]]:
        return [row for row in self.segments if not row["judge_ran"]]

    def to_dict(self) -> dict[str, Any]:
        return {"segments": self.segments, "summary": self.summary, "mode": self.mode, "versions": self.versions}

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def scan(
    content: str,
    *,
    doc_id: str,
    source_type: str,
    user_task: str,
    context_note: str | None = None,
    mode: str | None = None,
    max_judge_calls: int | None = None,
    judge: JudgeLike | None = None,
    store: Any | None = None,
    legacy_cache: bool = False,
    allow_changed: bool = False,
) -> ScanResult:
    """Analyze an untrusted external document; never scan the trusted user task."""
    started = time.perf_counter()
    manifest_status = verify_manifest(allow_changed=allow_changed)
    if not isinstance(content, str):
        raise TypeError("content must be a string")
    if source_type not in _VALID_SOURCE_TYPES:
        raise ValueError(f"source_type must be one of {sorted(_VALID_SOURCE_TYPES)}")
    if not user_task.strip():
        raise ValueError("user_task must not be empty")
    if context_note is None:
        context_note = layer1_settings.DEFAULT_CONTEXT_NOTES[source_type]
    selected_mode = (mode or layer1_settings.JUDGE_MODE).lower()
    if selected_mode not in {"all", "cascade"}:
        raise ValueError("mode must be 'all' or 'cascade'")
    budget = layer1_settings.MAX_JUDGE_CALLS_PER_DOC if max_judge_calls is None else max_judge_calls
    if budget is not None and (type(budget) is not int or budget < 0):
        raise ValueError("max_judge_calls must be a nonnegative integer or None")

    segments = make_segments(doc_id, content, window=layer1_settings.WINDOW, stride=layer1_settings.STRIDE)
    rule_reasons = [instruction_signals(row["text"], version=RULES_VERSION) for row in segments]
    global _PIGUARD_SCORER
    if segments:
        if _PIGUARD_SCORER is None:
            _PIGUARD_SCORER = _new_piguard_scorer()
        piguard_rows = _PIGUARD_SCORER.score([row["text"] for row in segments])
    else:
        piguard_rows = []
    if len(piguard_rows) != len(segments):
        raise RuntimeError("PIGuard result count did not match segment count")

    records: list[dict[str, Any]] = []
    for i, (segment, reasons, pig) in enumerate(zip(segments, rule_reasons, piguard_rows)):
        score = float(pig["piguard_injection_score"])
        records.append({
            "segment_id": segment["segment_id"], "doc_id": doc_id, "source_type": source_type,
            "start": int(segment["start"]), "end": int(segment["end"]), "text": segment["text"],
            "text_hash": hashlib.sha256(segment["text"].encode("utf-8")).hexdigest(),
            "trust": threat_config.trust_for_source(source_type),
            "rules_flag": bool(reasons), "rules_reasons": list(reasons),
            "piguard_label": str(pig["piguard_label"]), "piguard_score": score,
            "piguard_flag": score >= judge_config.PIGUARD_THRESHOLD,
            "truncated": bool(pig.get("truncated", False)),
            "judge_ran": False, "judge_coverage_reason": "not_selected",
            "judge_is_instruction": None, "judge_needed_for_task": None, "judge_flag": None,
            "judge_reason": None, "judge_error": False,
            "suspicion_level": "none", "level_reasons": [], "_order": i,
        })

    cache = _load_cache(legacy_cache=legacy_cache)
    if selected_mode == "all":
        candidates = records[:]
    else:
        candidates = [row for row in records if row["rules_flag"] or row["piguard_flag"]]
    candidate_ids = {row["segment_id"] for row in candidates}
    for row in records:
        row["judge_coverage_reason"] = "not_selected" if row["segment_id"] not in candidate_ids else "not_cached"

    cached_rows: dict[str, dict[str, Any]] = {}
    uncached_candidates = []
    for row in candidates:
        result = _cache_get(cache, row["segment_id"], user_task, row["text_hash"], legacy_cache=legacy_cache)
        if result is not None and _valid_judgment(result):
            cached_rows[row["segment_id"]] = result
        else:
            uncached_candidates.append(row)

    to_call = sorted(uncached_candidates, key=_priority)
    if budget is not None:
        allowed = {row["segment_id"] for row in to_call[:budget]}
        for row in to_call[budget:]:
            row["judge_coverage_reason"] = "budget_exhausted"
        to_call = [row for row in to_call if row["segment_id"] in allowed]

    calls_made = 0
    cache_hits = 0
    for row in candidates:
        cached = cached_rows.get(row["segment_id"])
        if cached is None:
            continue
        cache_hits += 1
        row.update({key: cached.get(key) for key in (
            "judge_is_instruction", "judge_needed_for_task", "judge_flag", "judge_reason", "judge_error"
        )})
        row["judge_ran"] = True
        row["judge_error"] = False
        row["judge_coverage_reason"] = "reviewed"

    if judge is not None:
        for row in to_call:
            calls_made += 1
            try:
                outcome = judge.judge_segment(user_task, context_note, row["text"])
            except Exception:
                row["judge_error"] = True
                row["judge_coverage_reason"] = "judge_unavailable"
                continue
            if outcome.get("judge_error"):
                invalid_output = outcome.get("_error_type") == "InvalidJudgeOutput"
                row["judge_error"] = True
                row["judge_ran"] = invalid_output
                row["judge_coverage_reason"] = "reviewed" if invalid_output else "judge_unavailable"
                continue
            is_instruction = outcome.get("judge_is_instruction", outcome.get("is_instruction"))
            needed = outcome.get("judge_needed_for_task", outcome.get("needed_for_task"))
            reason = outcome.get("judge_reason", outcome.get("reason"))
            flag = outcome.get("judge_flag")
            if flag is None and type(is_instruction) is bool and type(needed) is bool:
                flag = judge_flag(is_instruction, needed)
            normalized = {
                "judge_is_instruction": is_instruction,
                "judge_needed_for_task": needed,
                "judge_flag": flag,
                "judge_reason": reason,
                "judge_error": False,
            }
            if not _valid_judgment(normalized):
                row["judge_error"] = True
                row["judge_ran"] = True
                row["judge_coverage_reason"] = "reviewed"
                continue
            row.update(normalized)
            row["judge_ran"] = True
            row["judge_coverage_reason"] = "reviewed"
            _append_cache(row["segment_id"], user_task, row["text_hash"], normalized)

    for row in records:
        # A missing all-mode verdict must not silently become "none".
        suspicion = assess_suspicion(
            rules_flag=row["rules_flag"], piguard_flag=row["piguard_flag"],
            judge_ran=row["judge_ran"], judge_flag=row["judge_flag"],
            judge_error=row["judge_error"],
        )
        if selected_mode == "all" and not row["judge_ran"]:
            row["suspicion_level"] = "needs_review"
            row["level_reasons"] = [*suspicion["level_reasons"], "judge-on-all coverage is missing"]
        else:
            row["suspicion_level"] = suspicion["suspicion_level"]
            row["level_reasons"] = suspicion["level_reasons"]
        row.pop("_order", None)
        if store is not None:
            store.add_segment(row)

    level_counts = {level: sum(row["suspicion_level"] == level for row in records)
                    for level in threat_config.LEVEL_ORDER}
    unreviewed = {}
    for row in records:
        if not row["judge_ran"]:
            reason = row["judge_coverage_reason"]
            unreviewed[reason] = unreviewed.get(reason, 0) + 1
    reviewed = sum(row["judge_ran"] for row in records)
    summary = {
        "suspicion_counts": level_counts,
        "judge_calls_made": calls_made,
        "cache_hits": cache_hits,
        "coverage_fraction": reviewed / len(records) if records else 1.0,
        "unreviewed_count_by_reason": unreviewed,
        "segment_count": len(records),
        "elapsed_seconds": round(time.perf_counter() - started, 4),
    }
    versions = {
        "rules_version": RULES_VERSION,
        "piguard_model": PIGUARD_MODEL,
        "piguard_threshold": judge_config.PIGUARD_THRESHOLD,
        "judge_model": judge_config.MODEL_NAME,
        "prompt_version": judge_config.PROMPT_VERSION,
        "level_table": threat_config.ACTIVE_LEVEL_TABLE,
        "manifest_sha256": manifest_status["manifest_sha256"],
        "manifest_warning": manifest_status["warning"],
        "offline_cache_only": layer1_settings.OFFLINE_CACHE_ONLY and judge is None,
    }
    return ScanResult(records, summary, selected_mode, versions)
