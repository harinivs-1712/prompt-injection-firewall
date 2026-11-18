# Layer 3 API Specification

**Title**: Firewall review API  
**Version**: 0.1.0  

This API is localhost-only, read-only, and designed for the Layer 3 security review dashboard.
All data returned by the API represents external content or security metadata and must be treated as hostile.

## Security Scaffolding

- **Authentication**: HTTP Bearer tokens (`viewer` for read-only access, `reviewer` for review actions).
- **Loopback only**: By default only binds to `127.0.0.1`, `localhost`, and `::1`. Remote binding requires `--allow-remote`, TLS, and a reverse proxy.
- **Trusted Host**: Enforced via `TrustedHostMiddleware` to prevent DNS-rebinding attacks.
- **CORS**: Restricted to configured origins (`GET`, `OPTIONS` only; no credentials/cookies).
- **Rate limiting**: Max 5 failed authentication attempts per minute per IP before receiving `429 Too Many Requests`.
- **Response headers**: Every response includes `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and `Cross-Origin-Resource-Policy: same-origin`.

## Endpoints

| Method | Path | Summary | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/audit/verify` | Audit Verify | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/config` | Configuration | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/eval/results` | Evaluation | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/policy` | Policy | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/review/items` | Review Items | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/review/items/{identifier}` | Review Item | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/sessions` | Sessions | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/sessions/{session_id}` | Session | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/sessions/{session_id}/events` | Session Events | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/summary` | Summary | Bearer (viewer or reviewer) |
| `GET` | `/health` | Health | None |

### Endpoint Details

- `GET /health`: Unauthenticated health check returning server status and version.
- `GET /api/v1/summary`: Aggregate counts from the audit store (sessions, events, decisions, top reason codes, held outputs, halts).
- `GET /api/v1/sessions`: Paginated list of session metadata (`limit`, `offset`).
- `GET /api/v1/sessions/{session_id}`: Single session details and compact event timeline.
- `GET /api/v1/sessions/{session_id}/events`: Filterable event log (`event_type`, `action`, `tool`, `limit`, `offset`).
- `GET /api/v1/audit/verify`: Bounded audit log cryptographic hash-chain verification (`max_rows`).
- `GET /api/v1/review/items`: Metadata-only list of flagged or held content (`status`, `session_id`, `item_type`, `limit`, `offset`). Never returns content text.
- `GET /api/v1/review/items/{id}`: Detailed view of a review item. Stored text is returned ONLY if text retention was enabled; always flagged with `untrusted_content: true` and `render: plain_text_only`.
- `GET /api/v1/policy`: Sanitized summary of active firewall policy and advisory lint warnings.
- `GET /api/v1/config`: Non-sensitive configuration (judge mode, release version, startup audit verification status).
- `GET /api/v1/eval/results`: Fixed Day 10 offline evaluation results, known gaps, and settings.

## Frontend rules

Render every string from the API as plain text (React text nodes, never `dangerouslySetInnerHTML`, no markdown/HTML rendering, no auto-linking, no image/URL loading from content). External content may contain malicious HTML, CSS, JavaScript, or Markdown formatting designed to exploit dashboard operators.
