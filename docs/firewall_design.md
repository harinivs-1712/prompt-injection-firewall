# Layer 2 firewall package: design

## Integration boundary

The `firewall` package is agent-agnostic and exposes two integration points:

1. `Firewall.scan_content(session, content, source_type, ...)` analyzes external content before it enters the agent context. The host injects a scanner implementing the neutral `Scanner` protocol. `firewall.adapters.layer1.Layer1Scanner` adapts the frozen Layer 1 implementation lazily; importing `firewall` does not import Layer 1.
2. `Firewall.check_tool_call(session, tool_name, args)` runs before the host executes a tool. It checks policy structure, task permission, argument values and constraints, and any `always_ask` rule. The host must execute a tool only after an `ALLOW` result; `ASK` needs a user decision and `BLOCK` must not execute.
3. After a tool executes, the host must pass its result to `Firewall.inspect_tool_output(session, tool_name, output)` and give the agent only `OutputResult.agent_view`. Tool output is untrusted even when the tool itself is trusted.

The host application remains responsible for ensuring every content ingress and every tool invocation passes through these points. Calls that bypass the wrapper are outside this package's protection boundary.

## Policy-driven and fail-closed

Agent-specific tool names, task categories, and limits live in a strict JSON/YAML policy, not in firewall logic. Argument validation uses a registry (`firewall/arg_types.py`) so a host can register a type without changing engine code. Unknown keys, unknown types, and invalid constraints are rejected with a field path. Loaded policy objects are immutable.

The deterministic rule engine combines structural checks, task permission, argument validation, and `always_ask`. Any `BLOCK` objection wins over `ASK`; `ASK` wins over `ALLOW`. A call is allowed only if every check completes without an objection. If a check or audit adapter fails, the result is `ASK / INTERNAL_ERROR`. Decision messages, details, and audit events contain argument names only, never argument values. The engine does not import Layer 1, model SDKs, or network clients.

Built-in argument types include recipient, amount, account, path, URL, identifier, free text, integer, number, enum, and text pattern. Constraints are type-specific and strict: numeric bounds, allowed enum values, regex full matches, and maximum string length. A text pattern checks length before matching. Value violations use `defaults.violation_actions.value` unless a type has a more specific action setting. Invalid representations and unsafe path patterns are blocked.

`start_session(task, allowed_tools=...)` accepts an optional host-provided tool allowlist. Without it, the engine unions tools allowed by every task category whose whole-word or phrase keywords match. If none match, the fallback permits only low-risk tools with no side effects. Tools marked `always_ask` still ask even when other checks pass.

## Planned work

- **Day 5 and Day 6 (implemented):** package, strict policy loader, extensible argument types, deterministic rule checks, safe audit records, and offline harness.
- **Day 7 (implemented):** Layer 1 scanner adapter, output inspection, output masking/holding, session-level judge budget, and offline scripted harness.
- **Day 8 (implemented):** provenance and intent links between tool arguments and suspicious or unreviewed segments.
- **Day 9:** approval flow, sensitivity checks, and persistent audit logging.

Value normalization helpers are pure and do not touch the filesystem or network. Path normalization is lexical; it does not resolve symlinks or prove filesystem access. URL/domain parsing is input normalization, not a network request.

## Scope and limitations

Only content passed to `scan_content` and tool calls passed to `check_tool_call` are covered. This package does not intercept arbitrary agent behavior by itself. Path normalization is lexical and does not resolve symlinks or prove filesystem access. The hard-rule harness uses synthetic hand-written traces and fake tools, so its counts are demonstration results rather than a general safety benchmark. Approving every ASK result can allow harmful actions; host approval UX and tool execution control remain integration responsibilities.

## Tool-output inspection and Layer 1 adapter

`inspect_tool_output()` scans tool-returned text before the agent sees it. Strings are split into bounded chunks; for dictionaries and lists, string values are scanned recursively, while keys and non-string scalar values are not. Depth, string-count, chunk-size, total-size, and session judge-call limits are policy controlled. Bytes and other non-text values are returned inside a wrapper marked unreviewed because they are not inspected.

The default output actions pass levels `none`, `low`, and `medium` unchanged; hold high-suspicion output; and pass `needs_review` or unreviewed segments with an explicit mark. Policies may mask high-suspicion character spans in the agent copy instead of holding. Oversized output is truncated by default, with a notice; the omitted part is recorded as unscanned. `scan_output: false` bypasses inspection for a declared tool and creates an audit record. Undeclared tools still use inspection defaults.

The original output is kept in session memory for the host. `get_original_output(..., reviewer=True)` is the explicit reviewer-only access path. `OutputResult.to_audit_dict()` excludes original output and agent view. Audit events contain metadata only: tool/output IDs, action, levels, segment IDs, reason codes, call counts, and unscanned character counts.

The adapter follows the frozen `layers.scan.scan(content, *, doc_id, source_type, user_task, context_note=None, mode=None, max_judge_calls=None, judge=None, store=None, legacy_cache=False, allow_changed=False)` signature. It maps returned segment dictionaries and summary fields into `SegmentRecord` and `ScanOutcome`. `mode` and `legacy_cache` are forwarded; `offline_cache_only` is enforced by withholding a judge unless explicitly disabled. Live mode requires both `offline_cache_only=False` and `GEMINI_API_KEY`; tests use fake modules and never make calls. `create_default_firewall()` supplies this adapter when the host does not inject its own scanner.

### Agent view versus original

The agent must receive only `agent_view`. A held result contains a fixed placeholder, never the original. A masked result changes only the union of flagged spans in a copy. The host may retrieve the untouched original only for a review workflow with `reviewer=True`. Do not pass `original_outputs` or reviewer access into the agent context.

Output inspection happens **after** the tool has run, so it cannot undo side effects. Masking removes only flagged spans; remaining text can still influence the agent. Holding output may prevent useful work. Scanning consumes judge calls and respects both the Layer 1 mode and session budget. Unreviewed content is passed with a mark by default; Day 8 is intended to connect that taint to later risky tool calls. JSON keys and non-string values are not scanned, oversized or depth-limited content can remain unscanned, and character-span matching is best-effort.

## Day 8: provenance linking and final decision flow

For a structurally valid tool call, the firewall runs the Day 6 hard checks first, then `R-LINK`, then combines every result with **BLOCK > ASK > ALLOW**. R-LINK cannot make a hard-rule block or an `always_ask` result less strict. `ALL_RULES_PASSED` appears only when the final result is ALLOW. The host still executes a tool only after an ALLOW result (or after its own user approval of ASK).

R-LINK compares declared arguments with text in all session segments. It supports normalized exact/fuzzy recipient, URL, identifier and path matches; exact account and amount matches; and word-shingle overlap for free text and other registered types. User-typed values are marked and excluded from argument-link evidence. Whole-word verbs from `verb_to_tool` can create intent evidence. Optionally, medium/high session content taints high-risk or side-effecting calls even when no argument value was copied. A value found only in low/none content is recorded as informational and does not raise the link level by itself.

The default `link_policy` action table is:

| Tool risk | NONE | POSSIBLE | LIKELY | CONFIRMED |
|---|---|---|---|---|
| low | allow | allow | allow_log | ask |
| medium | allow | allow_log | ask | block |
| high | allow | ask | ask | block |

`allow_log` allows the call while recording link evidence. `link_matching` controls thresholds and resource caps; exceeding a segment or text cap returns POSSIBLE with `LINK_SCAN_LIMIT` and requires at least ASK. `Firewall.explain()` produces a short summary from reason codes, segment IDs, and levels without argument or segment text.

Matching is best-effort. Rewritten, paraphrased, or split values can lose their trail; calls without copied values rely on simple English verb matching and session taint. Session taint can increase approval prompts. Cascade scans can leave more segments unreviewed, producing more POSSIBLE links and asks. Segment text remains in session memory for matching. A value found only in unflagged external content may pass if hard rules pass. ASK is not the same as safe because a user can approve it carelessly.

## How to write a policy for a new agent

1. List the tools the host exposes and name each tool in the policy.
2. Assign a risk level and state whether the operation has side effects. Set `always_ask` for operations that need approval every time.
3. Assign a registered argument type to each argument. Use `register_type()` in host setup when a domain needs a custom validator.
4. Set limits and constraints: allowed destinations, path prefixes, numeric bounds, enum values, regex patterns, and violation actions.
5. Define task categories with allowed tools and whole-word or phrase keywords. The host may instead pass an explicit `allowed_tools` set for a session.
6. Write five normal and five attack traces, run the offline harness, and inspect both decisions and fake-tool logs before connecting real tools.

## Day 9: sensitive-data egress, approval, audit, and loop guard

For an attempted tool call the complete order is: structural validation; hard policy checks (task permission, typed arguments, and `always_ask`); provenance linking (`R-LINK`); confidential-data egress (`R-SENS`); optional trusted-metadata task-fit advice; strictest decision wins; human approval only for ASK; loop-guard accounting; append-only audit. BLOCK is never offered to an approver. `check_tool_call()` returns a decision without asking a person; integrations should use `authorize_tool_call()` when approval handling is wanted.

### Policy fields

- `limits.internal_domains`: domains treated as internal for egress routing. If omitted, allowed recipient domains are used. Malformed or unparseable destinations count as external.
- `tools.<tool>.egress.args`: arguments whose contents leave the system. `destination_args` names arguments that identify where the data goes. `scope: external` marks every destination external; otherwise `scope` defaults to `by_destination`. Each argument name must exist in the tool's `args`.
- `sensitivity.enabled`, `action` (`ask` or `block`), and `taint_mode` (`overlap_only` or `any_confidential_in_session`) control R-SENS. `shingle_size`, `min_overlap_shingles`, and `min_token_len` set matching thresholds. Defaults are 5, 3, and 6.
- `approval.timeout_seconds` defaults to 120 seconds; `preview_max_chars` defaults to 200. `block_overridable` must remain false. Preview values are only passed in memory to the trusted approval callback and are never logged.
- `loop_guard.max_blocked_per_tool`, `max_blocked_per_session`, and `max_denied_same_call` default to 3, 8, and 2. `on_limit` only accepts `halt`. A reviewer can resume a halted session; other callers cannot.

### Sensitivity behavior

When a policy marks a tool output `output_sensitivity: confidential`, the firewall stores SHA-256 hashes of normalized word shingles and recognizable tokens in session memory. It does not store output text in these fingerprints. Before a declared egress call, R-SENS compares outgoing arguments with those hashes. In `overlap_only`, enough matching shingles or any matching token to an external destination triggers the configured ASK or BLOCK. `any_confidential_in_session` triggers on every external egress after confidential output was seen. Internal destinations do not trigger R-SENS. This rule can only make a decision stricter.

### Audit and approvals

`SQLiteAuditStore(path)` writes an append-only SQLite log in WAL mode. Rows contain identifiers, rule and reason codes, action, link evidence metadata, approval outcome, and summary counts. By default, only a hash and length of the user task are kept; a host can opt into storing its text with `store_user_task=True`. Argument values and document/output text are not audit fields. Events are checked against a strict whitelist; invalid events become a minimal `AUDIT_EVENT_REJECTED` record. `verify_chain()` detects row edits or reordering. Read-only methods provide `list_events`, `session_summary`, `list_sessions`, and `stats` for a later dashboard.

`authorize_tool_call()` requests approval for ASK only. The callback receives a `ReviewPacket` with a bounded, control-character-cleaned preview. A true result allows this exact call; false, no approver, timeout, exception, or a non-boolean answer denies it. A separate call must pass through checks again. Audit write failure also fails closed. Repeated blocked or denied attempts can halt the session; while halted, every call is blocked until `resume_session(..., reviewer=True)`.

The optional task-fit checker receives only the trusted user task and policy metadata (tool description and argument types), never argument values or external content. Only `does_not_fit` adds ASK; unknown, exceptions, and timeouts do not loosen any other rule.

### Day 9 limits

Shingle/token overlap can miss paraphrases and summaries. Detection depends on policy authors marking confidential outputs and declaring all egress arguments. Approval safety depends on a careful human; approve-everything is the worst case. The review preview contains sensitive values, so approval interfaces must be trusted and must not log it. Timeouts deny. The audit log contains codes and IDs rather than content, so investigations may need separate evidence. A hash chain detects edits but cannot detect deletion of the entire database. Halted sessions block all calls until reviewer resume. The optional task-fit checker sees trusted metadata only.
