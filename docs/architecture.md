# Architecture

## Three layers

1. **Layer 1 — content analysis:** `firewall.layer1` segments incoming documents and tool outputs, runs instruction and PIGuard analysis, optionally asks a judge, records suspicion, and keeps source offsets and provenance.
2. **Layer 2 — tool-call security:** the agent-agnostic `firewall` package checks tool names, arguments, task permissions, hard policy rules, links to suspicious content, confidential-data egress, approvals, loop limits, and audit events.
3. **Layer 3 — review and operations (planned):** a future API and dashboard can expose read-only audit queries and human review. It is not implemented in this release; see [the Layer 3 plan](layer3_plan.md).

The shared threat context/provenance data lives in the session: content segments carry IDs, source, trust/suspicion status, and influence evidence. The audit store records metadata and identifiers, not segment text or argument values.

## Trust model

Only the user's typed task is trusted as task intent. All external content—including documents, webpages, email, and tool outputs—is untrusted by default. Untrusted means “do not treat as authoritative instructions”; it does not mean every passage is malicious. The scanner may classify content at different suspicion levels. Tool arguments supplied directly by a user are separately marked so they are not mistaken for values copied from external content.

## Decision flow

```text
structural validation
  -> deterministic hard rules
  -> provenance/linking checks
  -> confidential-data sensitivity checks
  -> optional trusted-metadata task-fit advice
  -> strictest result wins (BLOCK > ASK > ALLOW)
  -> approval callback for ASK only
  -> loop-guard accounting
  -> metadata-only audit
```

An LLM judge can advise Layer 1 content classification. It cannot override Layer 2's deterministic policy rules. Layer 2 runs the above checks and does not require an LLM.

## Integration boundary: what is and is not protected

The host must call `Firewall.scan_content()` before placing external text into agent context. Before executing a tool, it must call `check_tool_call()` or `authorize_tool_call()` and follow the returned decision. After execution, it must send the tool result through `inspect_tool_output()` and provide only `OutputResult.agent_view` to the agent. Only content passed through `scan_content()` and tool calls passed through the firewall are covered. Direct tool invocation, hidden context paths, or uninspected tool output bypass the protection boundary.

Output inspection happens after the tool has run and cannot undo side effects. The firewall does not sandbox arbitrary Python, operate the host's tools, authenticate a human reviewer, or guarantee that a permitted action is safe. The evaluation is scripted, synthetic, and limited to its stated scenarios.
