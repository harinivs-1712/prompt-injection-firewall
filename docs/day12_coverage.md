# Day 12 Implementation Coverage Table

This document maps every requirement of the Day 12 task (Layer 3 FastAPI Backend, Review Store, and Security Scaffolding) to its implementation file and verification test.

| Requirement Area | Specification Details | Implementation File | Verification Test / Script | Status |
|---|---|---|---|---|
| **Startup Refusals** | Missing tokens refused | `firewall_server/settings.py` | `TestStartupAndConfig.test_startup_refuses_missing_tokens` | **Done** |
| **Startup Refusals** | Short tokens (< 24 chars) refused | `firewall_server/settings.py` | `TestStartupAndConfig.test_startup_refuses_short_tokens` | **Done** |
| **Startup Refusals** | Equal viewer and reviewer tokens refused | `firewall_server/settings.py` | `TestStartupAndConfig.test_startup_refuses_equal_tokens` | **Done** |
| **Startup Refusals** | Obvious weak tokens refused | `firewall_server/settings.py` | `TestStartupAndConfig.test_startup_refuses_weak_tokens` | **Done** |
| **Startup Refusals** | Non-local host without `--allow-remote` refused | `firewall_server/settings.py` | `TestStartupAndConfig.test_startup_refuses_nonlocal_host_without_flag` | **Done** |
| **Startup Refusals** | Missing audit DB refused (never auto-creates) | `firewall_server/settings.py` | `TestStartupAndConfig.test_startup_refuses_missing_audit_db`, `test_server_never_creates_audit_db` | **Done** |
| **Docs UI Toggle** | `/docs` & `/openapi.json` disabled by default | `firewall_server/app.py` | `TestStartupAndConfig.test_docs_disabled_by_default`, `test_docs_enabled_with_flag` | **Done** |
| **Authentication** | Bearer tokens with constant-time comparison (`hmac.compare_digest`) | `firewall_server/security.py` | `TestAuthAndSecurity.test_missing_or_bad_token_returns_401` | **Done** |
| **Authorization Roles**| `viewer` (read-only) & `reviewer` (superset) | `firewall_server/security.py` | `TestAuthAndSecurity.test_roles_viewer_and_reviewer_work` | **Done** |
| **Auth Throttle** | >5 failures/min per IP -> 429 response + cooldown | `firewall_server/security.py` | `TestAuthAndSecurity.test_failed_auth_throttle_returns_429` | **Done** |
| **Host Header Check** | `TrustedHostMiddleware` blunts DNS-rebinding | `firewall_server/app.py` | `TestAuthAndSecurity.test_host_header_enforcement` | **Done** |
| **CORS Policy** | Allowed origins only, GET/OPTIONS, no credentials | `firewall_server/app.py` | `TestAuthAndSecurity.test_cors_headers` | **Done** |
| **Security Headers** | `nosniff`, `no-store`, `CSP: default-src 'none'`, `Referrer-Policy: no-referrer`, `CORP: same-origin` | `firewall_server/app.py` | `TestAuthAndSecurity.test_security_headers_on_all_responses` | **Done** |
| **Request Limits** | Query string > 4096 chars -> 414; GET with body -> 405 | `firewall_server/app.py` | `TestAuthAndSecurity.test_query_length_and_get_body_rejection` | **Done** |
| **Error Handling** | Generic `{error, code}`, no stack traces or values | `firewall_server/app.py` | `TestAuthAndSecurity.test_missing_or_bad_token_returns_401` | **Done** |
| **Log Redaction** | `TokenRedactionFilter` scrubs configured tokens from logs | `firewall_server/security.py` | `TestAuthAndSecurity.test_security_headers_on_all_responses` | **Done** |
| **Read-Only DB** | Opened with URI `?mode=ro` and `PRAGMA query_only=ON` | `firewall_server/app.py` | `TestReadOnlyAndPrivacy.test_databases_opened_read_only` | **Done** |
| **Review Store Schema**| SQLite WAL mode, `review_items` table with hashes/metadata | `firewall_server/review_store.py` | `TestReadOnlyAndPrivacy.test_opt_in_stored_text_with_control_chars_stripped` | **Done** |
| **Privacy Defaults** | Text stored only if opted-in (`FIREWALL_REVIEW_STORE_TEXT=1`); no arg values | `firewall_server/review_store.py` | `TestReadOnlyAndPrivacy.test_audit_db_and_review_db_contain_no_argument_values` | **Done** |
| **Text Sanitization**| Strips control characters (except `\n`, `\t`), caps at 50k chars | `firewall_server/review_store.py` | `TestReadOnlyAndPrivacy.test_opt_in_stored_text_with_control_chars_stripped`, `test_text_cap_and_truncation_flag` | **Done** |
| **Retention & Purge**| Configured retention hours, expired items 404, purge CLI | `firewall_server/review_store.py`, `firewall_server/purge.py` | `TestReadOnlyAndPrivacy.test_review_retention_and_purge` | **Done** |
| **ReviewRecorder** | Host helper, catches errors, public APIs only | `firewall_server/review_store.py` | `TestReviewRecorder.test_recorder_never_raises_on_database_error`, `test_recorder_uses_only_public_firewall_apis` | **Done** |
| **Endpoint: `/health`**| Open endpoint, returns status and version | `firewall_server/app.py` | `TestAuthAndSecurity.test_health_is_open` | **Done** |
| **Endpoint: `/summary`**| Totals from audit stats, session counts, action counts | `firewall_server/app.py` | `TestReadEndpoints.test_summary_endpoint` | **Done** |
| **Endpoint: `/sessions`**| Paginated session list (`limit`, `offset`) | `firewall_server/app.py` | `TestReadEndpoints.test_sessions_list_and_detail` | **Done** |
| **Endpoint: `/sessions/{id}`**| Session summary + compact timeline | `firewall_server/app.py` | `TestReadEndpoints.test_sessions_list_and_detail` | **Done** |
| **Endpoint: `/events`**| Events with validated filters (`event_type`, `action`, `tool`) | `firewall_server/app.py` | `TestReadEndpoints.test_session_events_filtering` | **Done** |
| **Endpoint: `/audit/verify`**| Cryptographic hash-chain verification with max_rows cap | `firewall_server/app.py` | `TestReadEndpoints.test_audit_verify_endpoint`, `test_audit_verify_tampered_db` | **Done** |
| **Endpoint: `/review/items`**| Metadata only, newest first, filterable, no text | `firewall_server/app.py` | `TestReadEndpoints.test_review_items_list_and_detail` | **Done** |
| **Endpoint: `/review/items/{id}`**| Detailed item, opt-in text, `plain_text_only`, `untrusted_content: true` | `firewall_server/app.py` | `TestReadEndpoints.test_review_items_list_and_detail`, `test_hostile_content_handling_full` | **Done** |
| **Endpoint: `/policy`**| Sanitized policy summary + advisory lint warnings | `firewall_server/app.py` | `TestReadEndpoints.test_policy_and_lint_endpoint` | **Done** |
| **Endpoint: `/config`**| Judge mode, release version, startup chain status | `firewall_server/app.py` | `TestReadEndpoints.test_config_endpoint` | **Done** |
| **Endpoint: `/eval/results`**| Day 10 benchmark results, known gaps, settings | `firewall_server/app.py` | `TestReadEndpoints.test_eval_results_endpoint` | **Done** |
| **Seed Demo Script** | Realistic offline scenarios into `var/demo/` using Firewall | `scripts/seed_demo_db.py` | `TestImportHygiene.test_seeded_demo_databases_validity` | **Done** |
| **Smoke API Script** | Offline httpx tester hitting all endpoints, no leaked tokens | `scripts/smoke_api.py` | Verified against running server (all 200 OK) | **Done** |
| **API Doc Generator**| Generates `docs/api.md` from `app.openapi()` offline | `scripts/generate_api_doc.py` | Output committed in `docs/api.md` | **Done** |
| **Backend Documentation**| Architecture, security model, frontend rules, run commands | `docs/layer3_backend.md` | Documented and verified | **Done** |
| **Import Hygiene** | `firewall_server` imports no heavy libs; `firewall` imports no FastAPI | `firewall_server/__init__.py` | `TestImportHygiene.test_import_firewall_server_loads_no_heavy_libraries`, `test_import_firewall_loads_no_fastapi` | **Done** |
