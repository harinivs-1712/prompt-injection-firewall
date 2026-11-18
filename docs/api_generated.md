# Layer 3 API Specification

**Title**: Firewall review API  
**Version**: 0.1.0  

This API is localhost-only, serving read-only audit logs, the review evidence store, and real-time human approval brokering.
All data returned by the API represents external content or security metadata and must be treated as hostile.

## Security Scaffolding

- **Authentication**: HTTP Bearer tokens with strict role separation:
  - `viewer`: Read-only access to audit logs and review items.
  - `reviewer`: Includes `viewer` permissions plus access to approvals listing, details, and decision endpoints.
  - `agent`: Host-process only; restricted strictly to broker request creation, decision polling, and cancellation.
- **Loopback only**: By default only binds to `127.0.0.1`, `localhost`, and `::1`. Remote binding requires `--allow-remote`, TLS, and a reverse proxy.
- **Trusted Host**: Enforced via `TrustedHostMiddleware` to prevent DNS-rebinding attacks.
- **CORS**: Restricted to configured origins (`GET`, `POST`, `OPTIONS` for review dashboard; agent endpoints strictly forbid `Origin` headers).
- **Rate limiting & Throttle**: Max 5 failed authentication attempts before receiving `429 Too Many Requests`. Action-based rate limits protect request creation and decision endpoints.
- **Response headers**: Every response includes `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and `Cross-Origin-Resource-Policy: same-origin`.

## Endpoints

| Method | Path | Summary | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/approvals` | Approvals List | Bearer (reviewer only) |
| `GET` | `/api/v1/approvals/stats` | Approvals Stats | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/approvals/{identifier}` | Approval Detail | Bearer (reviewer only) |
| `POST` | `/api/v1/approvals/{identifier}/decision` | Approval Decision | Bearer (reviewer only) |
| `GET` | `/api/v1/audit/verify` | Audit Verify | Bearer (viewer or reviewer) |
| `POST` | `/api/v1/broker/requests` | Broker Create Request | Bearer (agent only) |
| `POST` | `/api/v1/broker/requests/{identifier}/cancel` | Broker Cancel Request | Bearer (agent only) |
| `GET` | `/api/v1/broker/requests/{identifier}/decision` | Broker Get Decision | Bearer (agent only) |
| `GET` | `/api/v1/config` | Configuration | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/eval/results` | Evaluation | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/policy` | Policy | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/review/items` | Review Items | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/review/items/{identifier}` | Review Item | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/review/items/{identifier}/view` | Review Item View | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/sessions` | Sessions | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/sessions/{session_id}` | Session | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/sessions/{session_id}/events` | Session Events | Bearer (viewer or reviewer) |
| `GET` | `/api/v1/summary` | Summary | Bearer (viewer or reviewer) |
| `GET` | `/health` | Health | None |

### Endpoint Details

#### Health & Audit Logs
- `GET /health`: Unauthenticated health check returning server status and version.
- `GET /api/v1/summary`: Aggregate counts from the audit store (sessions, events, decisions, top reason codes, held outputs, halts).
- `GET /api/v1/sessions`: Paginated list of session metadata (`limit`, `offset`).
- `GET /api/v1/sessions/{session_id}`: Single session details and compact event timeline.
- `GET /api/v1/sessions/{session_id}/events`: Filterable event log (`event_type`, `action`, `tool`, `limit`, `offset`).
- `GET /api/v1/audit/verify`: Bounded audit log cryptographic hash-chain verification (`max_rows`).

#### Review Evidence Store & Sanitized View
- `GET /api/v1/review/items`: Metadata-only list of flagged or held content (`status`, `session_id`, `item_type`, `limit`, `offset`). Never returns content text.
- `GET /api/v1/review/items/{id}`: Detailed view of a review item. Stored text is returned ONLY if text retention was enabled; always flagged with `untrusted_content: true` and `render: plain_text_only`.
- `GET /api/v1/review/items/{id}/view`: Sanitized comparison view. Returns pre-split `original_pieces` and `masked_pieces` at merged span boundaries so frontends do not perform UTF-16 character arithmetic.

#### Approval Broker (Agent Role)
- `POST /api/v1/broker/requests`: Host agent submits an ASK decision packet. Returns `request_id` and `expires_at`. Rejects browser requests carrying `Origin` headers.
- `GET /api/v1/broker/requests/{id}/decision`: Agent long-polls decision endpoint (up to 20 seconds wait). Returns current status.
- `POST /api/v1/broker/requests/{id}/cancel`: Agent cancels pending approval request upon host timeout.

#### Reviewer Approvals (Reviewer Role)
- `GET /api/v1/approvals`: List pending or all approval requests (`status=pending|all`). Returns metadata only; never values.
- `GET /api/v1/approvals/{id}`: Full review packet while pending (explanation, evidence summary, sensitivity flags, values preview, request hash). Returns metadata only after decision.
- `POST /api/v1/approvals/{id}/decision`: Human reviewer decision (`decision: 'approve'|'deny'`, `request_hash`, `confirm: true`). Requires `confirm=true` for approve.
- `GET /api/v1/approvals/stats`: Aggregated approval metrics (counts by outcome, median decision latency, expired counts).

#### Policy & Eval
- `GET /api/v1/policy`: Sanitized summary of active firewall policy and advisory lint warnings.
- `GET /api/v1/config`: Non-sensitive configuration (judge mode, release version, startup audit verification status).
- `GET /api/v1/eval/results`: Fixed Day 10 offline evaluation results, known gaps, and settings.

## Frontend rules

Render every string from the API as plain text (React text nodes, never `dangerouslySetInnerHTML`, no markdown/HTML rendering, no auto-linking, no image/URL loading from content). External content may contain malicious HTML, CSS, JavaScript, or Markdown formatting designed to exploit dashboard operators.
