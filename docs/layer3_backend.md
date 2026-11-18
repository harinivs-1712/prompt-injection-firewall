# Layer 3 Backend Documentation

## 1. Purpose

The `firewall_server` package provides a lightweight, localhost-only FastAPI service that serves as the backend for the Layer 3 security review dashboard and human approval broker. It exposes audit statistics, session event timelines, reviewable evidence (flagged and held content), and real-time approval queues without ever storing confidential argument values, raw uninspected inputs, or writing to the authoritative audit ledger.

## 2. Architecture

```text
+-------------------+        +--------------------+        +---------------------+
|     Host App      | -----> |  Firewall (L1/L2)  | -----> |    Audit SQLite     |
|  (AI Agent Run)   |        |  (Decision Engine) |        | (Append-Only/Hash)  |
+-------------------+        +--------------------+        +---------------------+
          |                            |
          | (ApprovalCallback)         | (OutputResult)
          v                            v
+-------------------+        +--------------------+
|  Approval Broker  |        |   ReviewRecorder   |
| (In-Memory Queue) |        | (Host-side Helper) |
+-------------------+        +--------------------+
          |                            |
          |                            v
          |                  +--------------------+
          |                  |   Review SQLite    |
          |                  | (Opt-in Temp Store)|
          |                  +--------------------+
          |                            |
          +-------------+--------------+
                        v
             +--------------------+
             |  firewall_server   | <----- Dashboard UI (React)
             | (FastAPI Service)  |
             +--------------------+
```

- **Host App -> Firewall -> Audit SQLite DB**: The firewall logs decisions, rule IDs, reason codes, and suspicion levels into an append-only SQLite audit log guarded by SHA-256 hash chaining. It deliberately stores NO argument values and NO content text. The server maintains strictly read-only access to this database (`?mode=ro`, `PRAGMA query_only=ON`).
- **Host App -> ReviewRecorder -> Review SQLite DB**: The audit log stores no text by design. For human operators to review held or masked content, `ReviewRecorder` writes metadata and opt-in truncated plain text to an isolated, short-lived review database.
- **Host App -> Broker -> Dashboard**: When the firewall encounters an ASK decision requiring human intervention, `BrokerApprovalCallback` posts the ephemeral in-memory packet to `firewall_server/broker.py`. The reviewer inspects it on the dashboard and approves/denies with cryptographic hash binding.

## 3. Security Model

- **Localhost-Only by Default**: Binds to `127.0.0.1`, `localhost`, or `::1`. Remote binding requires an explicit `--allow-remote` flag, along with TLS termination and a reverse proxy.
- **Three Token Roles**:
  - `viewer`: Read-only access to audit summaries, session timelines, policy configs, and review items.
  - `reviewer`: Superset of viewer; authorizes decision making (`POST /api/v1/approvals/{id}/decision`) and viewing pending approval queues.
  - `agent`: Host-process only token used by `BrokerApprovalCallback` to create requests, poll decisions, and issue timeouts/cancels. Agent endpoints strictly reject requests carrying an `Origin` header (they cannot be called from browsers).
  Tokens are verified using constant-time comparison (`hmac.compare_digest`).
- **In-Memory Volatile Argument Values**: Argument values in approval packets exist ONLY in volatile server memory while pending. They are NEVER written to disk, SQLite, logs, or error responses, and are immediately wiped (`None`) upon reaching any terminal state (`approved`, `denied`, `expired`, `cancelled`).
- **Cryptographic Request Binding**: Every approval decision requires `request_hash = SHA-256(canonical JSON(id, session_id, tool, sorted reason_codes, values_preview))`. If the hash does not match, the decision is rejected (`409 HASH_MISMATCH`) and the request stays pending.
- **Explicit Confirmation**: Approvals require `confirm: true`. A submission of `decision: "approve"` with `confirm: false` fails with `422 Unprocessable Entity`.
- **Fail Closed Everywhere**: Any timeout, client disconnection, server error, or queue saturation defaults to `DENIED` on the host side.
- **Sanitized Comparison View**: `GET /api/v1/review/items/{id}/view` delivers pre-split `original_pieces` and `masked_pieces` split at merged span boundaries so frontends do not perform UTF-16 character arithmetic on emoji or astral characters.
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

## 4. How to Seed the Demo Database

To generate a synthetic demo containing normal sessions, held outputs, masked outputs, attacks blocked by linking, approval requests, denied approvals, and halted sessions:

```powershell
python scripts/seed_demo_db.py --force --store-text
```

## 5. How to Run the Approval Flow Demo

To run an automated end-to-end demonstration where the agent executes tool calls against the firewall with `BrokerApprovalCallback` and an automated reviewer approves one action and denies another:

```powershell
python scripts/demo_approval_flow.py
```

To run in manual mode with curl instructions:

```powershell
python scripts/demo_approval_flow.py --manual
```

## 6. How to Run the Server

Set minimum 24-character viewer, reviewer, and agent tokens in your environment, then start the server:

```powershell
$env:FIREWALL_VIEWER_TOKEN = "replace-with-a-long-viewer-token-0001"
$env:FIREWALL_REVIEWER_TOKEN = "replace-with-a-different-reviewer-token-0002"
$env:FIREWALL_AGENT_TOKEN = "replace-with-a-different-agent-token-0003"
$env:FIREWALL_ENABLE_BROKER = "1"

python -m firewall_server --audit-db var/demo/audit.sqlite --review-db var/demo/review.sqlite --policy policies/example_agent.yaml --enable-broker
```

To run the smoke test against the running server:
```powershell
python scripts/smoke_api.py
```

## 7. Endpoints Overview

| Endpoint | Method | Role | Description |
|---|---|---|---|
| `/health` | `GET` | Open | Health check returning status and firewall version |
| `/api/v1/summary` | `GET` | Viewer | Total counts of sessions, events, actions, and halts |
| `/api/v1/sessions` | `GET` | Viewer | Paginated session metadata list |
| `/api/v1/sessions/{session_id}` | `GET` | Viewer | Single session metadata and compact event timeline |
| `/api/v1/sessions/{session_id}/events` | `GET` | Viewer | Filterable event stream (`event_type`, `action`, `tool`) |
| `/api/v1/audit/verify` | `GET` | Viewer | Cryptographic verification of the append-only audit hash chain |
| `/api/v1/review/items` | `GET` | Viewer | Paginated list of flagged, held, or approval metadata |
| `/api/v1/review/items/{id}` | `GET` | Viewer | Detail of a single review item |
| `/api/v1/review/items/{id}/view` | `GET` | Viewer | Sanitized view with pre-split original and masked pieces |
| `/api/v1/broker/requests` | `POST` | Agent | Create in-memory approval request for an ASK decision |
| `/api/v1/broker/requests/{id}/decision` | `GET` | Agent | Long-poll for human reviewer decision (max 20s) |
| `/api/v1/broker/requests/{id}/cancel` | `POST` | Agent | Host-side cancel upon timeout |
| `/api/v1/approvals` | `GET` | Reviewer | List pending or all approval requests (metadata only) |
| `/api/v1/approvals/{id}` | `GET` | Reviewer | Review packet while pending; metadata only after terminal |
| `/api/v1/approvals/{id}/decision` | `POST` | Reviewer | Submit human decision (`approve`/`deny`) with hash and confirm |
| `/api/v1/approvals/stats` | `GET` | Viewer | Aggregated approval stats (median latency, outcomes, fatigue) |
| `/api/v1/policy` | `GET` | Viewer | Active firewall policy rules, tools, and lint warnings |
| `/api/v1/config` | `GET` | Viewer | Judge mode, release version, and startup verification state |
| `/api/v1/eval/results` | `GET` | Viewer | Layer 2 evaluation benchmarks and gap documentation |
