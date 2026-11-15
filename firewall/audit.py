"""Append-only SQLite audit store with metadata whitelist and a hash chain."""
from __future__ import annotations
import hashlib, json, sqlite3, threading
from datetime import datetime, timezone
from contextlib import contextmanager
from firewall.audit_schema import validate_event

EVENT_TYPES = {"session_started", "tool_check", "tool_authorized", "approval_requested", "approval_outcome", "output_inspected", "loop_guard_triggered", "session_halted", "session_resumed", "audit_event_rejected", "tool_output_inspection"}
ALLOWED = {"event", "event_type", "tool_name", "tool", "action", "output_id", "reason_codes", "rule_ids", "argument_names", "user_provided_args", "session_id", "max_level", "level_counts", "segment_ids", "unreviewed_segment_ids", "unscanned_chars", "judge_calls_made", "link_level", "evidence", "approval_outcome", "counts", "request_id", "task_length", "user_task_sha256", "policy_version", "agent_name", "sensitivity_flags", "output_sensitivity"}

def _canonical(obj): return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

class SQLiteAuditStore:
    def __init__(self, path, *, store_user_task=False):
        self.path = str(path); self.store_user_task = bool(store_user_task); self._lock = threading.RLock(); self.rejected_events = 0; self._closed = False
        with self._connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS sessions(session_id TEXT PRIMARY KEY, started_at TEXT, policy_version TEXT, agent_name TEXT, user_task_sha256 TEXT, user_task_length INTEGER, user_task TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, session_id TEXT, event_type TEXT, tool TEXT, action TEXT, reason_codes TEXT, rule_ids TEXT, link_level TEXT, evidence TEXT, approval_outcome TEXT, output_id TEXT, max_level TEXT, counts TEXT, prev_hash TEXT, row_hash TEXT)")
            for table in ("sessions", "audit_events"):
                db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_append_only_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT, 'append-only audit table'); END")
                db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_append_only_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT, 'append-only audit table'); END")
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        return db
    @contextmanager
    def _connection(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("audit store is closed")
            db=self._connect()
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
    def close(self):
        """Checkpoint WAL data and prevent further access; safe to call repeatedly."""
        with self._lock:
            if self._closed:
                return
            db=self._connect()
            try:
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                db.close()
            self._closed=True
    def __enter__(self):
        if self._closed: raise RuntimeError("audit store is closed")
        return self
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
    def record_session(self, session_id, policy_version, agent_name, task):
        task = task if isinstance(task, str) else ""
        data = (session_id, datetime.now(timezone.utc).isoformat(), policy_version[:200], agent_name[:200], hashlib.sha256(task.encode()).hexdigest(), len(task), task if self.store_user_task else None)
        with self._lock, self._connection() as db:
            db.execute("INSERT OR IGNORE INTO sessions VALUES(?,?,?,?,?,?,?)", data)
    def record(self, event):
        with self._lock:
            valid = validate_event(event) and not (set(event)-ALLOWED)
            safe = dict(event) if valid else {"event_type":"audit_event_rejected", "reason_codes":["AUDIT_EVENT_REJECTED"]}
            if valid:
                for value in safe.values():
                    if isinstance(value, str) and len(value)>200: valid=False
                safe = safe if valid else {"event_type":"audit_event_rejected", "reason_codes":["AUDIT_EVENT_REJECTED"]}
            if not valid: self.rejected_events += 1
            event_type = safe.get("event_type", safe.get("event", "tool_check"))
            if event_type not in EVENT_TYPES: event_type = "audit_event_rejected"; safe={"reason_codes":["AUDIT_EVENT_REJECTED"]}; self.rejected_events += 1
            prev = ""
            with self._connection() as db:
                row = db.execute("SELECT row_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
                if row: prev=row[0]
                record = {"ts":datetime.now(timezone.utc).isoformat(), "session_id":safe.get("session_id"), "event_type":event_type,
                    "tool":safe.get("tool", safe.get("tool_name")), "action":safe.get("action"),
                    "reason_codes":safe.get("reason_codes", []), "rule_ids":safe.get("rule_ids", []),
                    "link_level":safe.get("link_level"), "evidence":safe.get("evidence", []),
                    "approval_outcome":safe.get("approval_outcome"), "output_id":safe.get("output_id"),
                    "max_level":safe.get("max_level"), "counts":safe.get("counts", {})}
                canonical = _canonical(record); digest=hashlib.sha256((prev+canonical).encode()).hexdigest()
                db.execute("INSERT INTO audit_events(ts,session_id,event_type,tool,action,reason_codes,rule_ids,link_level,evidence,approval_outcome,output_id,max_level,counts,prev_hash,row_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (record["ts"],record["session_id"],event_type,record["tool"],record["action"],_canonical(record["reason_codes"]),_canonical(record["rule_ids"]),record["link_level"],_canonical(record["evidence"]),record["approval_outcome"],record["output_id"],record["max_level"],_canonical(record["counts"]),prev,digest))
    def verify_chain(self):
        with self._lock, self._connection() as db:
            previous=""
            for row in db.execute("SELECT * FROM audit_events ORDER BY id"):
                record={"ts":row["ts"],"session_id":row["session_id"],"event_type":row["event_type"],"tool":row["tool"],"action":row["action"],"reason_codes":json.loads(row["reason_codes"]),"rule_ids":json.loads(row["rule_ids"]),"link_level":row["link_level"],"evidence":json.loads(row["evidence"]),"approval_outcome":row["approval_outcome"],"output_id":row["output_id"],"max_level":row["max_level"],"counts":json.loads(row["counts"])}
                actual=hashlib.sha256((previous+_canonical(record)).encode()).hexdigest()
                if row["prev_hash"] != previous or row["row_hash"] != actual: return False, row["id"]
                previous=actual
            return True, None
    def list_events(self, session_id=None, tool=None, action=None, since=None, limit=100, offset=0):
        clauses=[]; values=[]
        for key,val in (("session_id",session_id),("tool",tool),("action",action)):
            if val is not None: clauses.append(f"{key}=?"); values.append(val)
        if since is not None: clauses.append("ts>=?"); values.append(since)
        sql="SELECT * FROM audit_events"+(" WHERE "+" AND ".join(clauses) if clauses else "")+" ORDER BY id LIMIT ? OFFSET ?"; values += [max(0,min(int(limit),1000)),max(0,int(offset))]
        with self._connection() as db: return [dict(r) for r in db.execute(sql, values)]
    def list_sessions(self, limit=100, offset=0):
        with self._connection() as db: return [dict(r) for r in db.execute("SELECT session_id,started_at,policy_version,agent_name,user_task_sha256,user_task_length FROM sessions ORDER BY started_at DESC LIMIT ? OFFSET ?", (max(0,min(int(limit),1000)),max(0,int(offset))))]
    def session_summary(self, session_id):
        rows=self.list_events(session_id=session_id,limit=1000)
        counts={x:0 for x in ("allow","ask","block","denied")}
        for row in rows:
            if row["action"] in counts: counts[row["action"]]+=1
        rank={"NONE":0,"POSSIBLE":1,"LIKELY":2,"CONFIRMED":3}
        levels=[r["link_level"] or "NONE" for r in rows]
        max_link=max(levels,key=lambda v:rank.get(v,0),default="NONE")
        return {"session_id":session_id,"counts":counts,"approvals":sum(r["approval_outcome"] is not None for r in rows),"max_link_level":max_link,"held_outputs":sum(r["event_type"] in {"output_inspected","tool_output_inspection"} and r["action"]=="HOLD" for r in rows)}
    def stats(self):
        actions={}; reasons={}
        with self._connection() as db:
            rows=db.execute("SELECT action,reason_codes FROM audit_events").fetchall()
        for row in rows:
            if row["action"]: actions[row["action"]]=actions.get(row["action"],0)+1
            for code in json.loads(row["reason_codes"]): reasons[code]=reasons.get(code,0)+1
        return {"actions":actions,"reason_codes":reasons,"events":len(rows)}
