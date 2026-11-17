# Release 0.1.0

- **Version:** 0.1.0
- **Git base:** `4289c22` (`Add Layer 2 evaluation`) on branch `refactor/layer1-into-firewall`. The release refactor has not been committed or tagged yet.
- **Package:** installable core Layer 2 package; Layer 1 model integrations are optional dependencies.
- **License:** `LICENSE` is a placeholder containing “TODO: choose a license”. A license has not been selected.

## Offline verification

- Full-suite run 1: 335 passed, 4 skipped, 3 warnings in 108.72 seconds.
- Full-suite run 2: 335 passed, 4 skipped, 3 warnings in 86.66 seconds.
- Full-suite run 3: 335 passed, 4 skipped, 3 warnings in 85.54 seconds.
- `scripts/verify_release.py`: passed offline, including manifest, import hygiene, version agreement, lint, demo, audit-chain, and editable-install checks.
- Day 10 frozen fingerprint replay: ran in a temporary directory with the extended release files reported as manifest changes. The evaluator completed its base settings simulation before the shell session ended; final fingerprint output was not retained. The frozen saved results remain unchanged.

## Day 10 headline table (copied verbatim)

| Setting | Attack success (95% Wilson CI) | Harmful steps executed | Normal task success (95% Wilson CI) | False asks on normal steps | False blocks on normal steps | Approval prompts / normal scenario |
|---|---:|---:|---:|---:|---:|---:|
| S0 — no_defense | 100.0% (94.9%–100.0%; n=72) | 72/72 (100.0% (94.9%–100.0%; n=72)) | 100.0% (89.8%–100.0%; n=34) | 0 | 0 | 0.000 |
| S1 — hard_rules_only | 70.8% (59.5%–80.1%; n=72) | 51/72 (70.8% (59.5%–80.1%; n=72)) | 79.4% (63.2%–89.7%; n=34) | 7 | 0 | 0.000 |
| S2 — hard_rules_plus_linking | 40.3% (29.7%–51.8%; n=72) | 29/72 (40.3% (29.7%–51.8%; n=72)) | 79.4% (63.2%–89.7%; n=34) | 7 | 0 | 0.000 |
| S3 — full_deny | 31.9% (22.3%–43.4%; n=72) | 23/72 (31.9% (22.3%–43.4%; n=72)) | 79.4% (63.2%–89.7%; n=34) | 7 | 0 | 0.206 |
| S4 — full_approve_all | 79.2% (68.4%–86.9%; n=72) | 57/72 (79.2% (68.4%–86.9%; n=72)) | 100.0% (89.8%–100.0%; n=34) | 7 | 0 | 0.206 |
| S5 — full_careful_reviewer | 31.9% (22.3%–43.4%; n=72) | 23/72 (31.9% (22.3%–43.4%; n=72)) | 100.0% (89.8%–100.0%; n=34) | 7 | 0 | 0.206 |

## Known gaps

S3 and S5 each had 23 harmful steps execute: 9 paraphrase cases, 6 rewritten-value cases, 6 unflagged-source cases, and 2 medium-risk possible-link cases allowed with logging. The full trace list and reasons remain in [`data/results/layer2_eval/known_gaps.md`](data/results/layer2_eval/known_gaps.md). The policy gap is that a possible link on a medium-risk tool is only logged by default.

## Reproduce

Run these commands from a clean checkout. The full evaluation writes outputs, so back up `data/results/layer2_eval/` or use a separate worktree before running it.

```powershell
python -m harness.eval_layer2 --validate-only
python -m harness.eval_layer2 --allow-changed
python -m pytest
python scripts/verify_release.py
```

## Non-claims

These results do not establish general detection accuracy, performance on real LLM agents, resistance to adaptive attacks, or generalization to other policies/tools. The careful reviewer is a scripted function, not a human study. Output hold/masking was exercised in deterministic traces; those traces cannot show how a live model would adapt after a held or masked result.

