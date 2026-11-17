# Layer 3 plan

Layer 3 is future work. The release currently provides the Layer 2 audit store and approval callback interfaces, but no FastAPI service or React dashboard.

- Add a read-only audit query API around `SQLiteAuditStore.list_events()`, `session_summary()`, `list_sessions()`, and `stats()`.
- Add a separate review store for flagged segment text and reviewer notes. The audit log deliberately stores no content text.
- Add an approval broker that receives `ReviewPacket` values and returns a bounded approval outcome to `authorize_tool_call()`.
- Render all untrusted text as plain text; never inject it as HTML or executable markup.
- Bind the development dashboard to localhost by default and protect reviewer endpoints with authentication tokens.
- Keep the audit API read-only and separate reviewer content access from audit metadata.
