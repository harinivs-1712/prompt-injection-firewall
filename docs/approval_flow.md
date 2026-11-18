# Layer 3 Approval Flow & Human Decision Architecture

## 1. Sequence Overview

The approval flow connects an agent host process executing tool calls to the human review dashboard via a synchronous, localhost-only approval broker:

```text
+-----------------------+                         +----------------------+                         +------------------------+
|      Agent Host       |                         |    firewall_server   |                         |    Review Dashboard    |
| (Firewall + Callback) |                         |  (In-Memory Broker)  |                         |   (Human Operator)     |
+-----------------------+                         +----------------------+                         +------------------------+
           |                                                 |                                                  |
           | 1. check_tool_call() -> ASK                     |                                                  |
           |------------------------------------------------>|                                                  |
           | 2. POST /broker/requests (Bearer agent)         |                                                  |
           |    [values_preview in body, ephemeral]          |                                                  |
           |    -------------------------------------------->|                                                  |
           |                                                 |                                                  |
           |                                                 | 3. GET /approvals?status=pending                 |
           |                                                 |    (Bearer reviewer)                             |
           |                                                 |<-------------------------------------------------|
           |                                                 |    Metadata list (never values)                  |
           |                                                 |------------------------------------------------->|
           |                                                 |                                                  |
           |                                                 | 4. GET /approvals/{id}                           |
           |                                                 |    Full packet + request_hash                    |
           |                                                 |<-------------------------------------------------|
           |                                                 |------------------------------------------------->|
           |                                                 |                                                  |
           | 5. GET /broker/requests/{id}/decision           |                                                  |
           |    (Long-poll wait_seconds=15)                  |                                                  |
           |------------------------------------------------>|                                                  |
           |                                                 | 6. POST /approvals/{id}/decision                 |
           |                                                 |    {decision, request_hash, confirm: true}       |
           |                                                 |<-------------------------------------------------|
           |                                                 |    Terminal status (approved / denied)           |
           |                                                 |------------------------------------------------->|
           |                                                 |                                                  |
           | 7. Decision returns to long-poll                |                                                  |
           |<------------------------------------------------|                                                  |
           |                                                 |                                                  |
           | 8. authorize_tool_call resolves                 |                                                  |
           |    (ALLOW if approved, else DENIED)             |                                                  |
           |    Authoritative write to SQLite audit log      |                                                  |
```

## 2. Broker State Machine

Pending requests follow a strict, one-way state transition model enforced under an in-memory re-entrant lock:

```text
                           +-----------+
                           |  PENDING  |
                           +-----------+
                            /    |    \
          Human Decision   /     |     \  Client Timeout / Cancel
        (Hash + Confirm)  /      |      \
                         v       |       v
               +------------+    |    +-------------+
               |  APPROVED  |    |    |  CANCELLED  |
               +------------+    |    +-------------+
               |   DENIED   |    |
               +------------+    | TTL Expiration
                                 v
                          +-------------+
                          |   EXPIRED   |
                          +-------------+
```

### Transition Invariants:
1. **One-Way Terminal Transition**: Once in a terminal state (`approved`, `denied`, `expired`, `cancelled`), the state is immutable. Concurrent or subsequent decisions return HTTP `409 Conflict` (`ALREADY_DECIDED`).
2. **Cryptographic Binding via `request_hash`**: Decisions must supply `request_hash = SHA-256(canonical JSON(id, session_id, tool, sorted reason_codes, values_preview))`. If the hash does not match (e.g., operator acted on stale or tampered state), the server rejects with `409 HASH_MISMATCH`, the request remains pending, and the mismatch is counted.
3. **Explicit Confirmation**: Approvals require `confirm: true`. A submission of `decision: "approve"` with `confirm: false` fails with `422 Unprocessable Entity`.
4. **Bounded Queue & Sweeper**: At most `FIREWALL_BROKER_MAX_PENDING` requests may remain in pending state. When full, submissions fail with `503 Service Unavailable` (`BROKER_FULL`). An active sweeper transitions overdue items to `expired`.
5. **Immediate Memory Wipe**: Upon reaching ANY terminal state, `values_preview` is immediately set to `None` in memory. Detail queries for completed requests return metadata only.

## 3. Data Privacy & Storage Lifecycle

Argument values exist exclusively in volatile memory while a request is actively pending:

| Component | While Pending | After Decision / Expiry |
|---|---|---|
| **Server Memory (`ApprovalBroker`)** | `values_preview` present (capped, control chars stripped) | `values_preview = None` (immediately wiped) |
| **Audit Database (`audit.sqlite`)** | Audit event records request metadata (id, tool, reason codes) | Authoritative final outcome (`allow` / `denied`), reason codes, zero values |
| **Review Store (`review.sqlite`)** | Row written with `item_type: approval_request`, metadata only | Row updated with `status`, `decided_at`, `decided_by_role`, `time_to_decision_ms` |
| **Logs & Error Bodies** | Tokens and argument values strictly redacted | Tokens and argument values strictly redacted |

## 4. The Two Records

1. **Firewall SQLite Audit Log (Authoritative)**:
   - Written directly by the agent host's `Firewall` engine.
   - Contains cryptographic hash chains over consecutive audit events.
   - Enforces tamper evidence for compliance and forensics.
   - Stores NO argument values or content text.
2. **Review Store (Dashboard Metadata & Telemetry)**:
   - Maintained by `firewall_server` on a dedicated database.
   - Records UI timestamps, decision roles (`reviewer`, `timeout`, `agent_cancel`), and decision latency (`time_to_decision_ms`).
   - Powers the `/api/v1/approvals/stats` endpoint to monitor operator latency and approval fatigue.

## 5. Threat Model & Countermeasures

| Threat | Impact | Countermeasure |
|---|---|---|
| **Stolen Agent Token** | Attacker could spoof tool approval requests | Agent token is restricted strictly to broker endpoints; rejected on reviewer/audit endpoints; Origin header rejected with 403; fail-closed timeout ensures requests expire. |
| **Compromised Dashboard Session** | Attacker could attempt automated approval of held tools | Approvals require `confirm: true`, cryptographic `request_hash` binding, reviewer role token, CORS origin restrictions, and action rate limiting. |
| **Approval Fatigue & "Rubber Stamping"** | Operator approves all prompts without inspecting arguments | Offline evaluation demonstrated that **79% of prompt injection attacks execute successfully under an approve-everything strategy**. The system records time-to-decision metrics, highlights high-risk indicators first, and enforces default denial. |
| **Hostile Content Injection** | Attacker crafts malicious strings in tool arguments | Values preview is sanitized server-side (control characters stripped, capped at 20 KB). The frontend must render all text strictly as plain text nodes. |

## 6. Day 14 UI Implementation Rules

When rendering human review screens in the frontend:
1. **Plain Text Nodes Only**: Render every string as React text nodes (`<div>{text}</div>`). Never use `dangerouslySetInnerHTML`, never render markdown, and disable automatic linkification.
2. **Deny is Default Focus**: The "Deny" button must receive default keyboard focus. Keyboard shortcuts (e.g. Enter) must never trigger an approval.
3. **Two-Step Approval**: Approving an action requires a deliberate second user interaction (e.g. checkbox confirmation or confirmation modal) to generate `confirm: true`.
4. **Reasons and Countdown First**: Prominently display the remaining countdown timer and the specific firewall reason codes/risk flags before presenting argument values.
5. **No External Resource Loading**: Never load images, iframes, stylesheets, or external URLs referenced inside argument values or tool outputs.
