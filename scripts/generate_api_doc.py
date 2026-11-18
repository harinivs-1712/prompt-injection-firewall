"""Generate docs/api.md from the offline FastAPI app.openapi() schema."""
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
            root / "audit.sqlite",
            root / "review.sqlite",
            ROOT / "policies" / "example_agent.yaml",
            "v" * 24,
            "r" * 24,
            ("http://localhost:5173",),
            enable_docs=True,
        )
        app = create_app(settings)
        schema = app.openapi()

    lines = [
        "# Layer 3 API Specification",
        "",
        f"**Title**: {schema.get('info', {}).get('title', 'Firewall review API')}  ",
        f"**Version**: {schema.get('info', {}).get('version', '0.1.0')}  ",
        "",
        "This API is localhost-only, read-only, and designed for the Layer 3 security review dashboard.",
        "All data returned by the API represents external content or security metadata and must be treated as hostile.",
        "",
        "## Security Scaffolding",
        "",
        "- **Authentication**: HTTP Bearer tokens (`viewer` for read-only access, `reviewer` for review actions).",
        "- **Loopback only**: By default only binds to `127.0.0.1`, `localhost`, and `::1`. Remote binding requires `--allow-remote`, TLS, and a reverse proxy.",
        "- **Trusted Host**: Enforced via `TrustedHostMiddleware` to prevent DNS-rebinding attacks.",
        "- **CORS**: Restricted to configured origins (`GET`, `OPTIONS` only; no credentials/cookies).",
        "- **Rate limiting**: Max 5 failed authentication attempts per minute per IP before receiving `429 Too Many Requests`.",
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
            summary = spec.get("summary") or spec.get("description") or "Read-only endpoint"
            auth = "None" if path == "/health" else "Bearer (viewer or reviewer)"
            lines.append(f"| `{method.upper()}` | `{path}` | {summary} | {auth} |")

    lines.extend([
        "",
        "### Endpoint Details",
        "",
        "- `GET /health`: Unauthenticated health check returning server status and version.",
        "- `GET /api/v1/summary`: Aggregate counts from the audit store (sessions, events, decisions, top reason codes, held outputs, halts).",
        "- `GET /api/v1/sessions`: Paginated list of session metadata (`limit`, `offset`).",
        "- `GET /api/v1/sessions/{session_id}`: Single session details and compact event timeline.",
        "- `GET /api/v1/sessions/{session_id}/events`: Filterable event log (`event_type`, `action`, `tool`, `limit`, `offset`).",
        "- `GET /api/v1/audit/verify`: Bounded audit log cryptographic hash-chain verification (`max_rows`).",
        "- `GET /api/v1/review/items`: Metadata-only list of flagged or held content (`status`, `session_id`, `item_type`, `limit`, `offset`). Never returns content text.",
        "- `GET /api/v1/review/items/{id}`: Detailed view of a review item. Stored text is returned ONLY if text retention was enabled; always flagged with `untrusted_content: true` and `render: plain_text_only`.",
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
    output_path = ROOT / "docs" / "api.md"
    content = generate_markdown()
    output_path.write_text(content, encoding="utf-8")
    print(f"Wrote API documentation from app.openapi() to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
