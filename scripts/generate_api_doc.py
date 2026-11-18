"""Generate docs/api.md and docs/api_generated.md from the offline FastAPI app.openapi() schema."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from firewall.audit import SQLiteAuditStore
from firewall_server.app import create_app
from firewall_server.review_store import ReviewStore
from firewall_server.settings import Settings


def generate_markdown() -> str:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        audit = SQLiteAuditStore(root / "audit.sqlite")
        audit.close()
        ReviewStore(root / "review.sqlite")
        settings = Settings(
            audit_db=root / "audit.sqlite",
            review_db=root / "review.sqlite",
            policy=ROOT / "policies" / "example_agent.yaml",
            viewer_token="v" * 24,
            reviewer_token="r" * 24,
            agent_token="a" * 24,
            cors_origins=("http://localhost:5173", "http://127.0.0.1:5173"),
            enable_docs=True,
            enable_broker=True,
            store_text=True,
        )
        app = create_app(settings)
        schema = app.openapi()

    lines = [
        "# Layer 3 API Specification",
        "",
        f"**Title**: {schema.get('info', {}).get('title', 'Firewall review API')}  ",
        f"**Version**: {schema.get('info', {}).get('version', '0.1.0')}  ",
        "",
        "This API is localhost-only, serving read-only audit logs, the review evidence store, and real-time human approval brokering.",
        "All data returned by the API represents external content or security metadata and must be treated as hostile.",
        "",
        "## Security Scaffolding",
        "",
        "- **Authentication**: HTTP Bearer tokens with strict role separation:",
        "  - `viewer`: Read-only access to audit logs and review items.",
        "  - `reviewer`: Includes `viewer` permissions plus access to approvals listing, details, and decision endpoints.",
        "  - `agent`: Host-process only; restricted strictly to broker request creation, decision polling, and cancellation.",
        "- **Loopback only**: By default only binds to `127.0.0.1`, `localhost`, and `::1`. Remote binding requires `--allow-remote`, TLS, and a reverse proxy.",
        "- **Trusted Host**: Enforced via `TrustedHostMiddleware` to prevent DNS-rebinding attacks.",
        "- **CORS**: Restricted to configured origins (`GET`, `POST`, `OPTIONS` for review dashboard; agent endpoints strictly forbid `Origin` headers).",
        "- **Rate limiting & Throttle**: Max 5 failed authentication attempts before receiving `429 Too Many Requests`. Action-based rate limits protect request creation and decision endpoints.",
        "- **Response headers**: Every response includes `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and `Cross-Origin-Resource-Policy: same-origin`.",
        "",
        "## Endpoints",
        "",
        "| Method | Path | Summary | Auth Required |",
        "|---|---|---|---|",
    ]

    paths = schema.get("paths", {})
    for path, methods in sorted(paths.items()):
        for method, spec in sorted(methods.items()):
            summary = spec.get("summary") or spec.get("description") or "API endpoint"
            if path == "/health":
                auth = "None"
            elif path.startswith("/api/v1/broker/"):
                auth = "Bearer (agent only)"
            elif path.startswith("/api/v1/approvals/stats"):
                auth = "Bearer (viewer or reviewer)"
            elif path.startswith("/api/v1/approvals"):
                auth = "Bearer (reviewer only)"
            else:
                auth = "Bearer (viewer or reviewer)"
            lines.append(f"| `{method.upper()}` | `{path}` | {summary} | {auth} |")

    lines.extend([
        "",
        "### Endpoint Details",
        "",
        "#### Health & Audit Logs",
        "- `GET /health`: Unauthenticated health check returning server status and version.",
        "- `GET /api/v1/summary`: Aggregate counts from the audit store (sessions, events, decisions, top reason codes, held outputs, halts).",
        "- `GET /api/v1/sessions`: Paginated list of session metadata (`limit`, `offset`).",
        "- `GET /api/v1/sessions/{session_id}`: Single session details and compact event timeline.",
        "- `GET /api/v1/sessions/{session_id}/events`: Filterable event log (`event_type`, `action`, `tool`, `limit`, `offset`).",
        "- `GET /api/v1/audit/verify`: Bounded audit log cryptographic hash-chain verification (`max_rows`).",
        "",
        "#### Review Evidence Store & Sanitized View",
        "- `GET /api/v1/review/items`: Metadata-only list of flagged or held content (`status`, `session_id`, `item_type`, `limit`, `offset`). Never returns content text.",
        "- `GET /api/v1/review/items/{id}`: Detailed view of a review item. Stored text is returned ONLY if text retention was enabled; always flagged with `untrusted_content: true` and `render: plain_text_only`.",
        "- `GET /api/v1/review/items/{id}/view`: Sanitized comparison view. Returns pre-split `original_pieces` and `masked_pieces` at merged span boundaries so frontends do not perform UTF-16 character arithmetic.",
        "",
        "#### Approval Broker (Agent Role)",
        "- `POST /api/v1/broker/requests`: Host agent submits an ASK decision packet. Returns `request_id` and `expires_at`. Rejects browser requests carrying `Origin` headers.",
        "- `GET /api/v1/broker/requests/{id}/decision`: Agent long-polls decision endpoint (up to 20 seconds wait). Returns current status.",
        "- `POST /api/v1/broker/requests/{id}/cancel`: Agent cancels pending approval request upon host timeout.",
        "",
        "#### Reviewer Approvals (Reviewer Role)",
        "- `GET /api/v1/approvals`: List pending or all approval requests (`status=pending|all`). Returns metadata only; never values.",
        "- `GET /api/v1/approvals/{id}`: Full review packet while pending (explanation, evidence summary, sensitivity flags, values preview, request hash). Returns metadata only after decision.",
        "- `POST /api/v1/approvals/{id}/decision`: Human reviewer decision (`decision: 'approve'|'deny'`, `request_hash`, `confirm: true`). Requires `confirm=true` for approve.",
        "- `GET /api/v1/approvals/stats`: Aggregated approval metrics (counts by outcome, median decision latency, expired counts).",
        "",
        "#### Policy & Eval",
        "- `GET /api/v1/policy`: Sanitized summary of active firewall policy and advisory lint warnings.",
        "- `GET /api/v1/config`: Non-sensitive configuration (judge mode, release version, startup audit verification status).",
        "- `GET /api/v1/eval/results`: Fixed Day 10 offline evaluation results, known gaps, and settings.",
        "",
        "## Frontend rules",
        "",
        "Render every string from the API as plain text (React text nodes, never `dangerouslySetInnerHTML`, no markdown/HTML rendering, no auto-linking, no image/URL loading from content). External content may contain malicious HTML, CSS, JavaScript, or Markdown formatting designed to exploit dashboard operators.",
    ])

    return "\n".join(lines) + "\n"


def main() -> int:
    content = generate_markdown()
    for fname in ("api.md", "api_generated.md"):
        p = ROOT / "docs" / fname
        p.write_text(content, encoding="utf-8")
        print(f"Wrote API documentation to {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
