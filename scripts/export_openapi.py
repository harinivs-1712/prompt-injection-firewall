"""Export OpenAPI schema from firewall_server to frontend/src/api/openapi.json."""

from __future__ import annotations

import json
from pathlib import Path

from firewall_server.app import create_app
from firewall_server.settings import Settings


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    audit_db = root / "var" / "demo" / "audit.db"
    review_db = root / "var" / "demo" / "review.db"
    policy_path = root / "policies" / "default_agent_policy.yaml"

    # Ensure demo db files exist or are referenced safely
    audit_db.parent.mkdir(parents=True, exist_ok=True)
    if not audit_db.exists():
        import sqlite3
        with sqlite3.connect(audit_db) as db:
            db.execute("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY, ts TEXT, session_id TEXT, event_type TEXT, tool TEXT, action TEXT, reason_codes TEXT, rule_ids TEXT, link_level TEXT, evidence TEXT, approval_outcome TEXT, output_id TEXT, max_level TEXT, counts TEXT, prev_hash TEXT, row_hash TEXT)")
    if not review_db.exists():
        import sqlite3
        with sqlite3.connect(review_db) as db:
            db.execute("CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY, request_id TEXT, session_id TEXT, tool TEXT, reason_codes TEXT, explanation TEXT, evidence_summary TEXT, sensitivity_flags TEXT, values_preview TEXT, status TEXT, created_at REAL, decided_at REAL, decision TEXT, decided_by TEXT, timeout_seconds REAL, original_output TEXT)")

    settings = Settings(
        audit_db=audit_db,
        review_db=review_db,
        policy=policy_path,
        viewer_token="viewer-token-dev-secret-12345",
        reviewer_token="reviewer-token-dev-secret-12345",
        cors_origins=("http://127.0.0.1:5173",),
        enable_docs=True,
        enable_broker=True,
        agent_token="agent-token-dev-secret-12345",
    )
    app = create_app(settings)
    schema = app.openapi()

    out_path = root / "frontend" / "src" / "api" / "openapi.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    print(f"Exported OpenAPI schema to {out_path} ({len(schema.get('paths', {}))} paths)")


if __name__ == "__main__":
    main()
