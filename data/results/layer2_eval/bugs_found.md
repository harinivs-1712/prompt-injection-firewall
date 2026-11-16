# Bugs found

**Confirmed audit validation defect (frozen firewall code; not modified):** When segment-level intent or session-taint provenance evidence is included in a `tool_check` audit event, `firewall/audit_schema.py` validates every present `arg_name` with `_safe_name`, which rejects `None`. These evidence records legitimately have no argument name. SQLite records an `audit_event_rejected` event instead of the original metadata. The row hash chain remains valid, but the provenance event is lost. In this evaluation this occurred 384 times across guarded synthetic runs and 6 times in the real Layer 1 subset (390 rejected events total) (the same 3 attack documents in both modes). Rejected metadata records contained no argument values. Fix by allowing null `arg_name` for evidence kinds that do not refer to an argument, then add a regression test. Left unfixed to preserve the frozen firewall inputs.

No other firewall bug was confirmed during this evaluation.

