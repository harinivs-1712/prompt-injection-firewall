# Offline demo output

This transcript uses placeholder scenarios, a scripted scanner, and no network or API calls.

## Normal task

- `search_notes`: **ALLOW** — ALL_RULES_PASSED

## Flagged output and linked call

- Tool output inspection: **HOLD**; linked send: **BLOCK** — ARG_MATCHES_HIGH_SUSPICION_SEGMENT, SESSION_TAINTED_HIGH_RISK

## Confidential read and approval

- Confidential read: **PASS**; external send authorization: **ALLOW** — CONFIDENTIAL_DATA_EXTERNAL, USER_APPROVED
- Approval prompts: 1

## Audit

- Audit hash chain valid: **(True, None)**
- Audit records store metadata and reason codes, not the demo content or argument values.
