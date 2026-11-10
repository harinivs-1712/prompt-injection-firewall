"""SQLite-backed threat context and segment provenance store.

Source matching is best-effort: exact and fuzzy text matching can connect a
tool argument to a segment, but it cannot recover provenance after paraphrase.
"""
from __future__ import annotations

import difflib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from config import threat_config
from layers.labeling import label_records
from layers.suspicion import apply_suspicion

_WHITESPACE_RE = re.compile(r"\s+")
_JUDGE_COLUMNS = (
    "judge_ran", "judge_is_instruction", "judge_needed_for_task", "judge_reason",
    "judge_flag", "judge_error", "judge_model", "judge_latency_ms",
)


def _normalize(value: str) -> str:
    return _WHITESPACE_RE.sub(" ", value).strip().casefold()


class ThreatStore:
    """Persist scored external segments for future Layer 2 provenance checks."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path or threat_config.THREAT_STORE_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.db_path)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS segments (
                segment_id TEXT PRIMARY KEY,
                doc_id TEXT NOT NULL,
                start INTEGER NOT NULL,
                end INTEGER NOT NULL,
                text TEXT NOT NULL,
                trust TEXT NOT NULL,
                suspicion_level TEXT NOT NULL,
                level_rank INTEGER NOT NULL,
                level_reasons_json TEXT NOT NULL,
                rules_flag INTEGER NOT NULL,
                piguard_score REAL,
                judge_ran INTEGER NOT NULL,
                judge_is_instruction INTEGER,
                judge_needed_for_task INTEGER,
                judge_reason TEXT,
                judge_flag INTEGER,
                judge_error INTEGER NOT NULL,
                judge_model TEXT,
                judge_latency_ms INTEGER,
                source_type TEXT NOT NULL,
                record_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_segments_doc_span
                ON segments(doc_id, start, end);
            CREATE INDEX IF NOT EXISTS idx_segments_level
                ON segments(level_rank, doc_id, start);
            """
        )
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "ThreatStore":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    @staticmethod
    def _bool_int(value: Any) -> int | None:
        return None if value is None else int(bool(value))

    def _prepare_record(self, record: dict[str, Any]) -> dict[str, Any]:
        source_type = record.get(
            "source_type",
            threat_config.SOURCE_TYPE_BY_DOC_ID.get(record["doc_id"], threat_config.DEFAULT_SOURCE_TYPE),
        )
        trust = threat_config.trust_for_source(source_type)
        prepared = {**record, "source_type": source_type, "trust": trust}
        if "suspicion_level" not in prepared or "level_reasons" not in prepared:
            prepared = apply_suspicion(prepared)
        return prepared

    def add_segment(self, record: dict[str, Any]) -> None:
        """Insert or replace one segment, preserving its source fields as JSON."""
        item = self._prepare_record(record)
        level = item["suspicion_level"]
        if level not in threat_config.LEVEL_ORDER:
            raise ValueError(f"Unknown suspicion level: {level}")
        values = (
            item["segment_id"], item["doc_id"], int(item["start"]), int(item["end"]),
            item.get("text", ""), item["trust"], level, threat_config.LEVEL_ORDER.index(level),
            json.dumps(item.get("level_reasons", []), ensure_ascii=False),
            int(bool(item.get("is_instruction_like", item.get("rules_flag")))), item.get("piguard_score", item.get("piguard_injection_score")),
            int(bool(item.get("judge_ran"))),
            self._bool_int(item.get("judge_is_instruction")),
            self._bool_int(item.get("judge_needed_for_task")), item.get("judge_reason"),
            self._bool_int(item.get("judge_flag")), int(bool(item.get("judge_error"))),
            item.get("judge_model"), item.get("judge_latency_ms"), item["source_type"],
            json.dumps(item, ensure_ascii=False),
        )
        self._connection.execute(
            """INSERT INTO segments VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            ) ON CONFLICT(segment_id) DO UPDATE SET
                doc_id=excluded.doc_id, start=excluded.start, end=excluded.end,
                text=excluded.text, trust=excluded.trust,
                suspicion_level=excluded.suspicion_level, level_rank=excluded.level_rank,
                level_reasons_json=excluded.level_reasons_json, rules_flag=excluded.rules_flag,
                piguard_score=excluded.piguard_score, judge_ran=excluded.judge_ran,
                judge_is_instruction=excluded.judge_is_instruction,
                judge_needed_for_task=excluded.judge_needed_for_task,
                judge_reason=excluded.judge_reason, judge_flag=excluded.judge_flag,
                judge_error=excluded.judge_error, judge_model=excluded.judge_model,
                judge_latency_ms=excluded.judge_latency_ms, source_type=excluded.source_type,
                record_json=excluded.record_json""",
            values,
        )
        self._connection.commit()

    @staticmethod
    def _decode(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return json.loads(row["record_json"])

    def get_segment(self, segment_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT record_json FROM segments WHERE segment_id = ?", (segment_id,)
        ).fetchone()
        return self._decode(row)

    def segments_for_doc(self, doc_id: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT record_json FROM segments WHERE doc_id = ? ORDER BY start, segment_id", (doc_id,)
        ).fetchall()
        return [json.loads(row["record_json"]) for row in rows]

    def segments_by_level(self, min_level: str) -> list[dict[str, Any]]:
        if min_level not in threat_config.LEVEL_ORDER:
            raise ValueError(f"Unknown suspicion level: {min_level}")
        rank = threat_config.LEVEL_ORDER.index(min_level)
        rows = self._connection.execute(
            "SELECT record_json FROM segments WHERE level_rank >= ? ORDER BY level_rank DESC, doc_id, start",
            (rank,),
        ).fetchall()
        return [json.loads(row["record_json"]) for row in rows]

    def segments_overlapping(self, doc_id: str, start: int, end: int) -> list[dict[str, Any]]:
        if start < 0 or end < start:
            raise ValueError("span must satisfy 0 <= start <= end")
        rows = self._connection.execute(
            """SELECT record_json FROM segments
               WHERE doc_id = ? AND start < ? AND end > ? ORDER BY start, segment_id""",
            (doc_id, end, start),
        ).fetchall()
        return [json.loads(row["record_json"]) for row in rows]

    @staticmethod
    def _fuzzy_contains(needle: str, haystack: str, min_ratio: float) -> bool:
        if len(needle) < 4:
            return False
        radius = max(1, int(len(needle) * (1.0 - min_ratio)) + 1)
        lower, upper = max(1, len(needle) - radius), len(needle) + radius
        for size in range(lower, upper + 1):
            if size > len(haystack):
                continue
            for start in range(0, len(haystack) - size + 1):
                candidate = haystack[start:start + size]
                if difflib.SequenceMatcher(None, needle, candidate, autojunk=False).ratio() >= min_ratio:
                    return True
        return False

    def find_sources(self, value: str, min_ratio: float = 0.85) -> list[dict[str, Any]]:
        """Find segments containing an exact or fuzzy normalized value.

        Matching is best-effort and cannot trace values that have been
        paraphrased or transformed beyond the configured fuzzy threshold.
        """
        if not 0.0 <= min_ratio <= 1.0:
            raise ValueError("min_ratio must be between 0 and 1")
        needle = _normalize(value)
        if not needle:
            return []
        rows = self._connection.execute("SELECT record_json FROM segments ORDER BY doc_id, start").fetchall()
        found = []
        for row in rows:
            record = json.loads(row["record_json"])
            haystack = _normalize(record.get("text", ""))
            if needle in haystack or self._fuzzy_contains(needle, haystack, min_ratio):
                found.append(record)
        return found


def enrich_segments(
    records: list[dict[str, Any]], labels: dict[str, Any], table_name: str | None = None,
) -> list[dict[str, Any]]:
    """Attach full-span labels, split, default trust, source type, and suspicion."""
    output = label_records(records, labels)
    enriched = []
    for record in output:
        source_type = threat_config.SOURCE_TYPE_BY_DOC_ID.get(
            record["doc_id"], threat_config.DEFAULT_SOURCE_TYPE
        )
        item = {
            **record,
            "trust": threat_config.trust_for_source(source_type),
            "source_type": source_type,
        }
        item.update(apply_suspicion(item, table_name=table_name))
        enriched.append(item)
    return enriched


def rebuild_threat_store_from_json(
    json_path: str | Path | None = None,
    db_path: str | Path | None = None,
    table_name: str | None = None,
) -> ThreatStore:
    """Rebuild the complete store from the cached judged-segment JSON.

    The judge cache and source JSON are read only. Re-running this replaces
    SQLite contents from the JSON source and current label/config data.
    """
    source = Path(json_path or threat_config.JUDGED_SEGMENTS_PATH)
    raw_records = json.loads(source.read_text(encoding="utf-8"))
    labels = json.loads(threat_config.LABELS_PATH.read_text(encoding="utf-8"))
    records = enrich_segments(raw_records, labels, table_name=table_name)
    store = ThreatStore(db_path=db_path)
    store._connection.execute("DELETE FROM segments")
    store._connection.commit()
    for record in records:
        store.add_segment(record)
    return store
