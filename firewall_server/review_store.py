"""Short-lived, opt-in review evidence store, separate from the audit log."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

MAX_TEXT = 50_000
STATUSES = frozenset({"pending", "viewed", "resolved", "expired", "archived"})
ITEM_TYPES = frozenset({"held_output", "masked_output", "flagged_content", "approval_request"})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clean_text(value: str) -> tuple[str, bool]:
    cleaned = "".join(char for char in value if char in "\n\t" or ord(char) >= 32)
    return cleaned[:MAX_TEXT], len(cleaned) > MAX_TEXT


class ReviewStore:
    def __init__(self, path: str | Path, *, store_text: bool = False, retention_hours: int = 24, readonly: bool = False):
        self.path, self.store_text, self.retention_hours, self.readonly = str(path), bool(store_text), int(retention_hours), bool(readonly)
        self._lock = threading.RLock()
        if self.readonly:
            if not Path(self.path).is_file(): raise ValueError("Review database does not exist")
        else:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("""CREATE TABLE IF NOT EXISTS review_items(
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, session_id TEXT NOT NULL,
                item_type TEXT NOT NULL, tool TEXT, output_id TEXT, status TEXT NOT NULL, max_level TEXT,
                reason_codes TEXT NOT NULL, segment_ids TEXT NOT NULL, level_counts TEXT NOT NULL,
                text_sha256 TEXT, original_text TEXT, masked_text TEXT, text_truncated INTEGER NOT NULL DEFAULT 0)""")

    def _connect(self):
        if self.readonly:
            db = sqlite3.connect(Path(self.path).resolve().as_uri() + "?mode=ro", uri=True, check_same_thread=False)
            db.execute("PRAGMA query_only=ON")
        else:
            db = sqlite3.connect(self.path, check_same_thread=False)
        db.row_factory = sqlite3.Row
        return db

    def add(self, *, session_id: str, item_type: str, tool: str | None = None, output_id: str | None = None,
            max_level: str | None = None, reason_codes=(), segment_ids=(), level_counts=None,
            original_text: str | None = None, masked_text: str | None = None) -> str:
        if self.readonly: raise RuntimeError("review store is read-only")
        if item_type not in ITEM_TYPES:
            raise ValueError("invalid review item type")
        created, identifier = _now(), str(uuid.uuid4())
        source = original_text if isinstance(original_text, str) else masked_text if isinstance(masked_text, str) else None
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest() if source is not None else None
        truncated = False
        if self.store_text:
            if isinstance(original_text, str): original_text, truncated = _clean_text(original_text)
            if isinstance(masked_text, str):
                masked_text, mask_truncated = _clean_text(masked_text); truncated = truncated or mask_truncated
        else:
            original_text = masked_text = None
        values = (identifier, created.isoformat(), (created + timedelta(hours=self.retention_hours)).isoformat(), session_id,
                  item_type, tool, output_id, "pending", max_level, json.dumps(list(reason_codes)),
                  json.dumps(list(segment_ids)), json.dumps(level_counts or {}), digest, original_text, masked_text, int(truncated))
        with self._lock, closing(self._connect()) as db:
            db.execute("INSERT INTO review_items VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)
            db.commit()
        return identifier

    def purge_expired(self) -> int:
        if self.readonly: raise RuntimeError("review store is read-only")
        with self._lock, closing(self._connect()) as db:
            removed = db.execute("DELETE FROM review_items WHERE expires_at <= ?", (_now().isoformat(),)).rowcount
            if removed >= 100: db.execute("VACUUM")
            db.commit()
            return int(removed)

    @staticmethod
    def _row(row, *, include_text=False):
        item = dict(row)
        if item["expires_at"] <= _now().isoformat(): return None
        for key in ("reason_codes", "segment_ids", "level_counts"):
            item[key] = json.loads(item[key])
        item["text_truncated"] = bool(item["text_truncated"])
        item["has_text"] = bool(item.get("original_text") is not None or item.get("masked_text") is not None)
        if not include_text:
            item.pop("original_text", None); item.pop("masked_text", None)
        return item

    def list(self, *, status=None, session_id=None, item_type=None, limit=50, offset=0):
        clauses, values = [], []
        for field, value in (("status", status), ("session_id", session_id), ("item_type", item_type)):
            if value is not None: clauses.append(field + "=?"); values.append(value)
        sql = "SELECT * FROM review_items" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        with self._lock, closing(self._connect()) as db:
            rows = db.execute(sql, (*values, limit, offset)).fetchall()
            total = db.execute("SELECT count(*) FROM review_items" + (" WHERE " + " AND ".join(clauses) if clauses else ""), values).fetchone()[0]
        return [item for row in rows if (item := self._row(row))], int(total)

    def get(self, identifier: str, *, include_text=False):
        with self._lock, closing(self._connect()) as db: row = db.execute("SELECT * FROM review_items WHERE id=?", (identifier,)).fetchone()
        return self._row(row, include_text=include_text) if row else None


class ReviewRecorder:
    """Best-effort host helper; failures never enter the agent execution path."""
    def __init__(self, store: ReviewStore): self.store, self.errors = store, 0
    def record_output_result(self, firewall, session, output_result, tool: str):
        try:
            action = str(output_result.action).upper()
            if action not in {"HOLD", "MASK"}: return {"stored": False}
            original = firewall.get_original_output(session, output_result.output_id, reviewer=True)
            item = self.store.add(session_id=session.session_id, item_type="held_output" if action == "HOLD" else "masked_output",
                                  tool=tool, output_id=output_result.output_id, max_level=output_result.max_level,
                                  reason_codes=output_result.reason_codes, segment_ids=output_result.segment_ids,
                                  level_counts=dict(output_result.level_counts), original_text=original if isinstance(original, str) else None,
                                  masked_text=output_result.agent_view if isinstance(output_result.agent_view, str) else None)
            return {"stored": True, "id": item}
        except Exception:
            self.errors += 1; return {"stored": False, "error": "review_recording_failed"}
    def record_approval_request(self, session, decision, explanation: str, evidence_summary=(), tool: str | None = None):
        try:
            return {"stored": True, "id": self.store.add(session_id=session.session_id, item_type="approval_request", tool=tool,
                reason_codes=[str(x.value if hasattr(x, "value") else x) for x in decision.reason_codes],
                segment_ids=[str(x.get("segment_id")) for x in evidence_summary if x.get("segment_id")])}
        except Exception:
            self.errors += 1; return {"stored": False, "error": "review_recording_failed"}
