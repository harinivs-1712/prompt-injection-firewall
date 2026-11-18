# Layer 3 Backend Documentation

## 1. Purpose

The `firewall_server` package provides a lightweight, localhost-only, read-only FastAPI service that serves as the backend for the Layer 3 security review dashboard. It exposes audit statistics, session event timelines, and reviewable evidence (flagged and held content) without ever exposing write capabilities, confidential arguments, or raw uninspected inputs.

## 2. Architecture

```text
+-------------------+        +--------------------+        +---------------------+
|     Host App      | -----> |  Firewall (L1/L2)  | -----> |    Audit SQLite     |
|  (AI Agent Run)   |        |  (Decision Engine) |        | (Append-Only/Hash)  |
+-------------------+        +--------------------+        +---------------------+
          |                             |
          v                             v
+-------------------+        +--------------------+
|  ReviewRecorder   | -----> |   Review SQLite    |
| (Host-side Helper)|        | (Opt-in Temp Store)|
+-------------------+        +--------------------+
                                        |
                                        v
                             +--------------------+
                             |  firewall_server   | <----- Dashboard UI (React)
                             | (FastAPI Read-Only)|
                             +--------------------+
```

- **Host App -> Firewall -> Audit SQLite DB**: The firewall logs decisions, rule IDs, reason codes, and suspicion levels into an append-only SQLite audit log guarded by SHA-256 hash chaining. It deliberately stores NO argument values and NO content text.
- **Host App -> ReviewRecorder -> Review SQLite DB**: The audit log stores no text by design. For human operators to review held or masked content, `ReviewRecorder` writes metadata and opt-in truncated plain text to an isolated, short-lived review database.
- **Dashboard -> firewall_server -> Read-Only SQLite connections**: The FastAPI server opens both databases strictly read-only (`?mode=ro`, `PRAGMA query_only=ON`) and exposes JSON endpoints to the dashboard.

## 3. Security Model

- **Localhost-Only by Default**: Binds to `127.0.0.1`, `localhost`, or `::1`. Remote binding requires an explicit `--allow-remote` flag, along with TLS termination and a reverse proxy.
- **Two Token Roles**:
  - `viewer`: Can read summary, session timelines, verified audit records, policy summaries, and review items metadata.
  - `reviewer`: Superset of viewer; reserved for Day 13 approval actions.
  Tokens are passed via standard HTTP Bearer headers and verified using constant-time comparison (`hmac.compare_digest`).
- **Read-Only Database Connections**: Opened with SQLite URI `mode=ro` and `PRAGMA query_only=ON`. The API process cannot modify, insert, or delete any records.
- **Why the Review Store is Separate**: The audit database is an immutable security ledger that must remain free of untrusted attack strings or sensitive user data. The review store is short-lived, opt-in, purgeable, and isolated.
- **Retention & Privacy Defaults**:
  - `FIREWALL_REVIEW_STORE_TEXT=0` by default: No content text is stored unless explicitly opted-in.
  - `FIREWALL_REVIEW_RETENTION_HOURS=24`: Expired items are ignored upon query and purged via the purge CLI.
  - Argument values are NEVER stored in either database.
- **Hostile Data Scaffolding**: All external content is treated as untrusted and potentially hostile:
  - Text fields are capped at 50,000 characters.
  - Control characters (except tab and newline) are stripped.
  - Marked with `"untrusted_content": true` and `"render": "plain_text_only"`.
- **Response Headers**:
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: no-store`
  - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
  - `Referrer-Policy: no-referrer`
  - `Cross-Origin-Resource-Policy: same-origin`
- **Rate Limiting & Anti-Brute-Force**: Over 5 authentication failures per minute per client IP triggers a `429 Too Many Requests` cooldown response.
- **What is NOT Protected**:
  - Root/system compromise of the hosting machine.
  - Reverse-proxy or TLS misconfiguration if `--allow-remote` is used.
  - In-memory approval argument values displayed to operators before approval/denial.

## 4. How to Seed the Demo Database

To generate a synthetic demo containing normal sessions, held outputs, masked outputs, attacks blocked by linking, approval requests, denied approvals, and halted sessions:

```powershell
python scripts/seed_demo_db.py --force --store-text
```

The script runs completely offline using simulated policies and zero LLM calls.

## 5. How to Run the Server

Set minimum 24-character viewer and reviewer tokens in your environment, then start the server:

```powershell
$env:FIREWALL_VIEWER_TOKEN = "replace-with-a-long-viewer-token-0001"
$env:FIREWALL_REVIEWER_TOKEN = "replace-with-a-different-reviewer-token-0002"

python -m firewall_server --audit-db var/demo/audit.sqlite --review-db var/demo/review.sqlite --policy policies/example_agent.yaml
```

To purge expired review items:
```powershell
python -m firewall_server.purge --review-db var/demo/review.sqlite
```

To run the smoke test against the running server:
```powershell
python scripts/smoke_api.py
```

## 6. Endpoints Overview

| Endpoint | Method | Role | Description |
|---|---|---|---|
| `/health` | `GET` | Open | Health check returning status and firewall version |
| `/api/v1/summary` | `GET` | Viewer | Total counts of sessions, events, actions, and halts |
| `/api/v1/sessions` | `GET` | Viewer | Paginated session metadata list |
| `/api/v1/sessions/{session_id}` | `GET` | Viewer | Single session metadata and compact event timeline |
| `/api/v1/sessions/{session_id}/events` | `GET` | Viewer | Filterable event stream (`event_type`, `action`, `tool`) |
| `/api/v1/audit/verify` | `GET` | Viewer | Verifies cryptographic hash chain on audit log |
| `/api/v1/review/items` | `GET` | Viewer | Metadata list of held/flagged items (no text) |
| `/api/v1/review/items/{id}` | `GET` | Viewer | Review item detail (opt-in sanitized text only) |
| `/api/v1/policy` | `GET` | Viewer | Sanitized policy rules, limits, and lint warnings |
| `/api/v1/config` | `GET` | Viewer | Runtime configuration (judge mode, release info) |
| `/api/v1/eval/results` | `GET` | Viewer | Day 10 offline evaluation benchmarks and gap reports |

## 7. Frontend Rules

Render every string from the API as plain text:
- Always use React text nodes or standard text bindings.
- NEVER use `dangerouslySetInnerHTML`.
- Do NOT enable Markdown, HTML, or BBCode rendering for any fields.
- Do NOT auto-link URLs in review items.
- Do NOT load external images, stylesheets, or media referenced in review text.
