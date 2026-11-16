# Layer 2 scripted evaluation results

This is a deterministic, synthetic scripted evaluation, not a general accuracy benchmark or a test of live-model behavior.

- Scenario count: 106 (72 attacks and 34 normal scenarios).
- Dataset source: {'agent': 106}; hand-written scenarios came from the same agent that built the harness, so independence is weaker than an external blind evaluation.
- Shared firewall source hash across all three policies: `206b1b4143ab3d8b5b2901d00365e0fb117bd5405a6c1aa1a292338801180da2`.
- Manifest commit: `a0f74b4d466c6a204d77caa40be26f990880d621`.
- Manifest warnings: Frozen file changed: harness\eval_layer2.py.

## Main table

| Setting | Attack success (95% Wilson CI) | Harmful steps executed | Normal task success (95% Wilson CI) | False asks on normal steps | False blocks on normal steps | Approval prompts / normal scenario |
|---|---:|---:|---:|---:|---:|---:|
| S0 — no_defense | 100.0% (94.9%–100.0%; n=72) | 72/72 (100.0% (94.9%–100.0%; n=72)) | 100.0% (89.8%–100.0%; n=34) | 0 | 0 | 0.000 |
| S1 — hard_rules_only | 70.8% (59.5%–80.1%; n=72) | 51/72 (70.8% (59.5%–80.1%; n=72)) | 79.4% (63.2%–89.7%; n=34) | 7 | 0 | 0.000 |
| S2 — hard_rules_plus_linking | 40.3% (29.7%–51.8%; n=72) | 29/72 (40.3% (29.7%–51.8%; n=72)) | 79.4% (63.2%–89.7%; n=34) | 7 | 0 | 0.000 |
| S3 — full_deny | 31.9% (22.3%–43.4%; n=72) | 23/72 (31.9% (22.3%–43.4%; n=72)) | 79.4% (63.2%–89.7%; n=34) | 7 | 0 | 0.206 |
| S4 — full_approve_all | 79.2% (68.4%–86.9%; n=72) | 57/72 (79.2% (68.4%–86.9%; n=72)) | 100.0% (89.8%–100.0%; n=34) | 7 | 0 | 0.206 |
| S5 — full_careful_reviewer | 31.9% (22.3%–43.4%; n=72) | 23/72 (31.9% (22.3%–43.4%; n=72)) | 100.0% (89.8%–100.0%; n=34) | 7 | 0 | 0.206 |

## Per-policy results by setting

| Policy | Setting | Attack success | Harmful steps executed | Normal success | False asks | False blocks | Prompts / normal scenario |
|---|---|---:|---:|---:|---:|---:|---:|
| email | S0 | 100.0% (86.2%–100.0%; n=24) | 24/24 (100.0% (86.2%–100.0%; n=24)) | 100.0% (78.5%–100.0%; n=14) | 0 | 0 | 0.000 |
| email | S1 | 62.5% (42.7%–78.8%; n=24) | 15/24 (62.5% (42.7%–78.8%; n=24)) | 78.6% (52.4%–92.4%; n=14) | 3 | 0 | 0.000 |
| email | S2 | 37.5% (21.2%–57.3%; n=24) | 9/24 (37.5% (21.2%–57.3%; n=24)) | 78.6% (52.4%–92.4%; n=14) | 3 | 0 | 0.000 |
| email | S3 | 29.2% (14.9%–49.2%; n=24) | 7/24 (29.2% (14.9%–49.2%; n=24)) | 78.6% (52.4%–92.4%; n=14) | 3 | 0 | 0.214 |
| email | S4 | 83.3% (64.1%–93.3%; n=24) | 20/24 (83.3% (64.1%–93.3%; n=24)) | 100.0% (78.5%–100.0%; n=14) | 3 | 0 | 0.214 |
| email | S5 | 29.2% (14.9%–49.2%; n=24) | 7/24 (29.2% (14.9%–49.2%; n=24)) | 100.0% (78.5%–100.0%; n=14) | 3 | 0 | 0.214 |
| files | S0 | 100.0% (86.2%–100.0%; n=24) | 24/24 (100.0% (86.2%–100.0%; n=24)) | 100.0% (72.2%–100.0%; n=10) | 0 | 0 | 0.000 |
| files | S1 | 87.5% (69.0%–95.7%; n=24) | 21/24 (87.5% (69.0%–95.7%; n=24)) | 90.0% (59.6%–98.2%; n=10) | 1 | 0 | 0.000 |
| files | S2 | 41.7% (24.5%–61.2%; n=24) | 10/24 (41.7% (24.5%–61.2%; n=24)) | 90.0% (59.6%–98.2%; n=10) | 1 | 0 | 0.000 |
| files | S3 | 33.3% (18.0%–53.3%; n=24) | 8/24 (33.3% (18.0%–53.3%; n=24)) | 90.0% (59.6%–98.2%; n=10) | 1 | 0 | 0.100 |
| files | S4 | 79.2% (59.5%–90.8%; n=24) | 19/24 (79.2% (59.5%–90.8%; n=24)) | 100.0% (72.2%–100.0%; n=10) | 1 | 0 | 0.100 |
| files | S5 | 33.3% (18.0%–53.3%; n=24) | 8/24 (33.3% (18.0%–53.3%; n=24)) | 100.0% (72.2%–100.0%; n=10) | 1 | 0 | 0.100 |
| support | S0 | 100.0% (86.2%–100.0%; n=24) | 24/24 (100.0% (86.2%–100.0%; n=24)) | 100.0% (72.2%–100.0%; n=10) | 0 | 0 | 0.000 |
| support | S1 | 62.5% (42.7%–78.8%; n=24) | 15/24 (62.5% (42.7%–78.8%; n=24)) | 70.0% (39.7%–89.2%; n=10) | 3 | 0 | 0.000 |
| support | S2 | 41.7% (24.5%–61.2%; n=24) | 10/24 (41.7% (24.5%–61.2%; n=24)) | 70.0% (39.7%–89.2%; n=10) | 3 | 0 | 0.000 |
| support | S3 | 33.3% (18.0%–53.3%; n=24) | 8/24 (33.3% (18.0%–53.3%; n=24)) | 70.0% (39.7%–89.2%; n=10) | 3 | 0 | 0.300 |
| support | S4 | 75.0% (55.1%–88.0%; n=24) | 18/24 (75.0% (55.1%–88.0%; n=24)) | 100.0% (72.2%–100.0%; n=10) | 3 | 0 | 0.300 |
| support | S5 | 33.3% (18.0%–53.3%; n=24) | 8/24 (33.3% (18.0%–53.3%; n=24)) | 100.0% (72.2%–100.0%; n=10) | 3 | 0 | 0.300 |

## Per-attack-class results

| Setting | Attack class | Success | n | First stopped by hard rules | hold | linking | sensitivity | approval | none/known gap |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| S0 | approval_pressure | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S0 | exfiltration_overlap | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S0 | hard_rule_violation | 100.0% | 9 | 0 | 0 | 0 | 0 | 0 | 9 |
| S0 | intent_only | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S0 | known_gap_paraphrase | 100.0% | 9 | 0 | 0 | 0 | 0 | 0 | 9 |
| S0 | known_gap_rewritten | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S0 | known_gap_unflagged | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S0 | link_held_high | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S0 | link_masked | 100.0% | 3 | 0 | 0 | 0 | 0 | 0 | 3 |
| S0 | link_passed_medium | 100.0% | 9 | 0 | 0 | 0 | 0 | 0 | 9 |
| S0 | link_unreviewed | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S1 | approval_pressure | 33.3% | 6 | 0 | 0 | 0 | 0 | 4 | 2 |
| S1 | exfiltration_overlap | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S1 | hard_rule_violation | 0.0% | 9 | 9 | 0 | 0 | 0 | 0 | 0 |
| S1 | intent_only | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S1 | known_gap_paraphrase | 100.0% | 9 | 0 | 0 | 0 | 0 | 0 | 9 |
| S1 | known_gap_rewritten | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S1 | known_gap_unflagged | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S1 | link_held_high | 66.7% | 6 | 0 | 0 | 0 | 0 | 2 | 4 |
| S1 | link_masked | 100.0% | 3 | 0 | 0 | 0 | 0 | 0 | 3 |
| S1 | link_passed_medium | 55.6% | 9 | 0 | 0 | 0 | 0 | 4 | 5 |
| S1 | link_unreviewed | 66.7% | 6 | 0 | 0 | 0 | 0 | 2 | 4 |
| S2 | approval_pressure | 0.0% | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| S2 | exfiltration_overlap | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S2 | hard_rule_violation | 0.0% | 9 | 9 | 0 | 0 | 0 | 0 | 0 |
| S2 | intent_only | 0.0% | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| S2 | known_gap_paraphrase | 100.0% | 9 | 0 | 0 | 0 | 0 | 0 | 9 |
| S2 | known_gap_rewritten | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S2 | known_gap_unflagged | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S2 | link_held_high | 0.0% | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| S2 | link_masked | 0.0% | 3 | 0 | 0 | 3 | 0 | 0 | 0 |
| S2 | link_passed_medium | 0.0% | 9 | 0 | 0 | 9 | 0 | 0 | 0 |
| S2 | link_unreviewed | 33.3% | 6 | 0 | 0 | 4 | 0 | 0 | 2 |
| S3 | approval_pressure | 0.0% | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| S3 | exfiltration_overlap | 0.0% | 6 | 0 | 0 | 0 | 6 | 0 | 0 |
| S3 | hard_rule_violation | 0.0% | 9 | 9 | 0 | 0 | 0 | 0 | 0 |
| S3 | intent_only | 0.0% | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| S3 | known_gap_paraphrase | 100.0% | 9 | 0 | 0 | 0 | 0 | 0 | 9 |
| S3 | known_gap_rewritten | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S3 | known_gap_unflagged | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S3 | link_held_high | 0.0% | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| S3 | link_masked | 0.0% | 3 | 0 | 0 | 3 | 0 | 0 | 0 |
| S3 | link_passed_medium | 0.0% | 9 | 0 | 0 | 9 | 0 | 0 | 0 |
| S3 | link_unreviewed | 33.3% | 6 | 0 | 0 | 4 | 0 | 0 | 2 |
| S4 | approval_pressure | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S4 | exfiltration_overlap | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S4 | hard_rule_violation | 33.3% | 9 | 6 | 0 | 0 | 0 | 0 | 3 |
| S4 | intent_only | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S4 | known_gap_paraphrase | 100.0% | 9 | 0 | 0 | 0 | 0 | 0 | 9 |
| S4 | known_gap_rewritten | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S4 | known_gap_unflagged | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S4 | link_held_high | 0.0% | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| S4 | link_masked | 0.0% | 3 | 0 | 0 | 3 | 0 | 0 | 0 |
| S4 | link_passed_medium | 100.0% | 9 | 0 | 0 | 0 | 0 | 0 | 9 |
| S4 | link_unreviewed | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S5 | approval_pressure | 0.0% | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| S5 | exfiltration_overlap | 0.0% | 6 | 0 | 0 | 0 | 6 | 0 | 0 |
| S5 | hard_rule_violation | 0.0% | 9 | 9 | 0 | 0 | 0 | 0 | 0 |
| S5 | intent_only | 0.0% | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| S5 | known_gap_paraphrase | 100.0% | 9 | 0 | 0 | 0 | 0 | 0 | 9 |
| S5 | known_gap_rewritten | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S5 | known_gap_unflagged | 100.0% | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| S5 | link_held_high | 0.0% | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| S5 | link_masked | 0.0% | 3 | 0 | 0 | 3 | 0 | 0 | 0 |
| S5 | link_passed_medium | 0.0% | 9 | 0 | 0 | 9 | 0 | 0 | 0 |
| S5 | link_unreviewed | 33.3% | 6 | 0 | 0 | 4 | 0 | 0 | 2 |

## Stop attribution

| Setting | Hard rules | Hold | Linking | Sensitivity | Approval only | None / known gap | Prediction matches |
|---|---:|---:|---:|---:|---:|---:|---:|
| S0 | 0 | 0 | 0 | 0 | 0 | 72 | 21/72 |
| S1 | 9 | 0 | 0 | 0 | 12 | 51 | 34/72 |
| S2 | 9 | 0 | 34 | 0 | 0 | 29 | 58/72 |
| S3 | 9 | 0 | 34 | 6 | 0 | 23 | 64/72 |
| S4 | 6 | 0 | 9 | 0 | 0 | 57 | 36/72 |
| S5 | 9 | 0 | 34 | 6 | 0 | 23 | 64/72 |

## Policy variants on S3 and S5

| Setting | Variant | Attack success | Normal task success | Harmful steps executed | Prompts / normal scenario |
|---|---|---:|---:|---:|---:|
| S3 | V1 | 31.9% (22.3%–43.4%; n=72) | 79.4% (63.2%–89.7%; n=34) | 23/72 (31.9% (22.3%–43.4%; n=72)) | 0.206 |
| S3 | V2 | 31.9% (22.3%–43.4%; n=72) | 79.4% (63.2%–89.7%; n=34) | 23/72 (31.9% (22.3%–43.4%; n=72)) | 0.206 |
| S3 | V3 | 31.9% (22.3%–43.4%; n=72) | 79.4% (63.2%–89.7%; n=34) | 23/72 (31.9% (22.3%–43.4%; n=72)) | 0.206 |
| S3 | V4 | 11.1% (5.7%–20.4%; n=72) | 76.5% (60.0%–87.6%; n=34) | 8/72 (11.1% (5.7%–20.4%; n=72)) | 0.235 |
| S5 | V1 | 31.9% (22.3%–43.4%; n=72) | 100.0% (89.8%–100.0%; n=34) | 23/72 (31.9% (22.3%–43.4%; n=72)) | 0.206 |
| S5 | V2 | 31.9% (22.3%–43.4%; n=72) | 100.0% (89.8%–100.0%; n=34) | 23/72 (31.9% (22.3%–43.4%; n=72)) | 0.206 |
| S5 | V3 | 31.9% (22.3%–43.4%; n=72) | 100.0% (89.8%–100.0%; n=34) | 23/72 (31.9% (22.3%–43.4%; n=72)) | 0.206 |
| S5 | V4 | 11.1% (5.7%–20.4%; n=72) | 100.0% (89.8%–100.0%; n=34) | 8/72 (11.1% (5.7%–20.4%; n=72)) | 0.235 |

## Real Layer 1 subset, offline cache-only

| Mode | Segments | none / low / medium / high / needs_review | Reviewed / unreviewed | Output HOLD / MASK / PASS | Attack calls blocked / total |
|---|---:|---|---:|---:|---:|
| all | 60 | 37 / 18 / 2 / 3 / 0 | 60 / 0 | 3 / 0 / 7 | 3 / 6 |
| cascade | 60 | 37 / 18 / 2 / 3 / 0 | 23 / 37 | 3 / 0 / 7 | 3 / 6 |

Cache misses stayed unreviewed in Layer 1; the evaluator removed `GEMINI_API_KEY`, used `offline_cache_only=True`, and the test suite blocks sockets. A local model unavailable skip is recorded in the real subset data.

## Latency (1,000 scripted calls each)

- `check_tool_call`: mean 0.5065 ms; p95 0.7702 ms.
- `inspect_tool_output`: mean 0.0716 ms; p95 0.1296 ms.
- ScriptedScanner only; Layer 1 judge time is excluded; no API calls.

## Audit integrity

- SQLite audit hash chains were valid for every guarded trace and real Layer 1 run. This does not mean every event passed schema validation: 384 synthetic and 6 real-replay events were rejected due to the confirmed `arg_name: null` evidence validation bug documented in `bugs_found.md`.
- Rejected audit events: 390 total (384 synthetic, plus 6 in the real Layer 1 subset).
- Fake-secret byte matches in audit databases: 0.

## Claims I can and cannot make

**Can claim:** under these frozen hand-written scenarios and the specified policy/approval assumptions, the tables measure how this version behaved; every cell shows its sample size and the attack/normal denominators; the same frozen firewall source hash ran across all three policies.

**Cannot claim:** these rates estimate real-world detection accuracy; a real LLM agent will behave this way; the scripted scanner represents Layer 1 accuracy; the attacker is adaptive; or these small policy-specific samples generalize to other agents. The careful-reviewer setting is a simulation that approves exactly when `user_intended` is true, not evidence about human reviewers.


