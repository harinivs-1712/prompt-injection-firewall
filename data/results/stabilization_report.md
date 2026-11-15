# Test stabilization report

## Scope and safety

This work focused on test-run stability and the offline Layer 1 adapter integration. The test suite ran with Hugging Face and Transformers offline mode enabled and with `GEMINI_API_KEY` removed. No API or network calls were made. Existing documents, cached judge outputs, labels, Layer 1 code, and configuration were read-only; the only new `data/` outputs are this report and `layer1_integration_report.md`.

## Reproduction and diagnosis

Three full-suite runs before the fixes all passed: 313 passed and 4 skipped in 77.86s, 65.83s, and 65.39s. Firewall tests and the older evaluation tests also passed separately and in reverse order. The two suspected Day 9 tests each passed five isolated repeats.

The earlier reported stall was not reproduced, so its exact original cause is not proven. A concrete cleanup defect was found: SQLite connections opened with `with sqlite3.connect(...)` were not actually closed by that context manager. That could leave file handles open and cause intermittent file-lock behavior, especially on Windows. The fix now closes every audit connection deterministically and explicitly closes the test's raw SQLite connections. The approval timeout test also used a long sleep; it now waits on an event that the fixture releases during teardown, avoiding unnecessary lingering work.

## Changes made

- `SQLiteAuditStore` now closes each per-operation SQLite connection, supports explicit/context-manager close, checkpoints the WAL when closing, and rejects use after close.
- The hanging approver harness uses an event-based wait, with deterministic fixture teardown.
- A test-only autouse fixture closes audit stores created in each test and fails when a test leaks a live non-daemon thread.
- The approval and SQLite audit tests now cover deterministic teardown, a database path containing spaces, and explicit `doc_id`/context propagation.
- Test startup sets the Hugging Face and Transformers offline flags before test collection.
- The real Layer 1 integration subprocess now receives the project import path; its report is created only after checking the recorded levels against the saved all/cascade outputs.
- Added `pytest-timeout` to `requirements-dev.txt`, timeout configuration in `pytest.ini`, offline test instructions in `README.md`, and this report.

## Post-fix full-suite repeats

| Run | Result | Duration | Log |
|---|---:|---:|---|
| 1 | 315 passed, 4 skipped | 64.76s | `logs/stabilization_final_run1.txt` |
| 2 | 315 passed, 4 skipped | 64.12s | `logs/stabilization_final_run2.txt` |
| 3 | 315 passed, 4 skipped | 63.27s | `logs/stabilization_final_run3.txt` |

The four skips are three existing Day 8 policy cases rejected by the intentionally strict policy validator and the opt-in real Layer 1 integration test, which was run separately twice below.

The slowest tests in the third post-fix run were:

| Test | Duration |
|---|---:|
| `test_rule_signals_cover_imperative_action_and_plain_fact` | 11.79s |
| `test_composition_offsets_tasks_placeholders_and_blind_overlap_audit` | 10.47s |
| `test_scored_output_contract_without_downloading_model` | 8.06s |
| `test_heldout_hash_manifest_composition_offsets_domains_and_review_csv` | 8.05s |
| `test_invalid_replies_exhaust_retries_and_combined_counts_error` | 7.00s |
| `test_harness_blocks_attacks_and_executes_approved_normal_traces` | 2.66s |
| `test_link_matching_2000_segments_performance` | 1.54s |
| `test_offline_cached_simulation_never_calls_judge` | 1.12s |
| `test_task_fit_unknown_exception_timeout_do_not_change_decision` | 1.02s |
| `test_same_engine_runs_three_example_policies_and_known_gap_is_honest` | 0.78s |
| `test_sqlite_audit_chain_redaction_whitelist_and_queries` | 0.74s |
| `test_import_hygiene_for_core_adapter_and_factory` | 0.43s |
| `test_firewall_import_has_no_heavy_or_layer1_imports` | 0.42s |
| `test_sqlite_is_append_only_and_hash_chain_detects_edit_in_copy` | 0.31s |
| `test_threat_store_roundtrip_queries_and_fuzzy_source_match` | 0.22s |

The Day 9 approval timeout test completed in 1.02s in this run. The complete duration list is in the run log.

## Offline real Layer 1 integration

The opt-in integration test was run twice. Both passed: 1 passed in 118.43s and 1 passed in 75.28s. It scanned eight read-only held-out documents in both `all` and `cascade` modes using local assets and saved cache entries; all 8/8 all-mode and 8/8 cascade-mode segment-level suspicion results matched the saved outputs. The attack output was held, a tool argument copied from a flagged HIGH segment was blocked through R-LINK, and the ordinary control output passed with a normal tool call allowed. Per-document details are in `data/results/layer1_integration_report.md`.

One integration attempt initially failed because the subprocess could not import the project package; passing `PYTHONPATH` fixed it. A later run passed. The first passing integration run exceeded the configured 100-second faulthandler dump threshold while the subprocess was still running; it completed successfully at 118.43s. Repeats took 75.28s, so the runtime varies with local model/cache performance.

The frozen Layer 1 manifest check passed. Firewall tests also passed with `ResourceWarning` promoted to an error: 144 passed and 4 skipped in 14.92s (`logs/firewall_resourcewarnings_final.txt`).

## Environment limitation and remaining risk

Installing `pytest-timeout` was attempted, but package installation failed because DNS/network access was unavailable. The dependency is recorded in `requirements-dev.txt`; until it is installed, this environment reports that the `timeout` and `timeout_method` pytest configuration options are unknown. Full runs still completed three times under Python's development mode and pytest's faulthandler timeout, and the integration subprocess has its own 180-second timeout. Install development dependencies with `python -m pip install -r requirements-dev.txt` in a network-enabled environment to activate pytest-timeout's per-test enforcement.

No full-suite hang was reproduced, so the SQLite cleanup defect and sleep-based approval wait are concrete stability improvements, not proof of the original stall's sole cause. Local inference remains the largest runtime source; the initial integration run shows that it can exceed 100 seconds. The historical test skips remain documented above.
