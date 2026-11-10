# Context-Aware Multi-Layer Prompt Injection Detection and Mitigation Framework for LLM-Based Agents

## 1. Project Overview

The proposed system is designed to detect and mitigate prompt injection attacks in LLM-based agents. These attacks occur when malicious instructions are hidden inside external content such as documents, emails, webpages, or tool outputs. The framework uses three security layers and a shared Threat Context and Provenance Manager to analyze external content, control tool usage, and produce safer responses.

## 2. System Architecture

### Layer 1: Context-Aware Content Analysis

This layer analyzes external content before it reaches the AI agent.

- **Content Segmentation:** Divides documents and other external content into meaningful segments.
- **Instruction Identification:** Identifies segments containing instruction-like content directed at an AI agent.
- **Context Analysis:** Examines the document context, user's original task, and meaning of the identified instructions.
- **Malicious Instruction Detection:** Classifies instructions as benign, suspicious, or malicious based on their context and intent.
- **Cross-Segment Relationship Analysis:** Examines relationships between different segments to identify potentially coordinated or distributed malicious instructions.

### Layer 2: Tool-Level Security Analysis

This layer protects the agent when it attempts to use external tools.

- **Tool Necessity and Relevance:** Checks whether a requested tool is relevant to the user's task.
- **Permission Validation:** Checks whether the requested operation is permitted by the security policy.
- **Tool Input Inspection:** Examines tool names, arguments, destinations, and requested operations.
- **Suspicious Influence Assessment:** Checks whether untrusted or suspicious external content may be influencing the tool call.
- **Unauthorized Tool Prevention:** Blocks tool calls that violate deterministic security rules.

A deterministic policy engine acts as the main security boundary. An LLM-based evaluator may provide additional advice but cannot override the policy engine.

Tool outputs are sent back through Layer 1 for content analysis before being returned to the agent.

### Layer 3: Safe Response and Security Management

This layer manages the final response and security-related activities.

- **Sanitized Content Generation:** Creates a separate sanitized copy by removing or masking confirmed malicious content while preserving the original document.
- **Human-in-the-Loop Review:** Sends uncertain cases for user review and approval.
- **Security Audit Logging:** Records detected threats, decisions, affected segments, and tool-related security events.
- **Security Dashboard:** Displays flagged content, review decisions, activity, and security evaluation results using FastAPI and React.

## 3. Shared Module: Threat Context and Provenance Manager (TCPM)

This is a shared module used by all three layers, not an additional security layer.

It maintains information about external content and tracks its influence throughout the agent workflow.

It stores:
- Segment IDs and source information.
- Trust classification and suspicion level.
- Detection results and reasons.
- Relationships between related segments.
- Associated tool calls and actions.
- Provenance and influence information.

All external content is treated as untrusted by default. Untrusted content is not automatically malicious; its classification can change based on analysis.

## 4. Overall System Workflow

1. External content enters the system and is recorded by the Threat Context and Provenance Manager.
2. Layer 1 segments and analyzes the content to identify potentially malicious instructions.
3. The analyzed content is provided to the AI agent.
4. Before a tool executes, Layer 2 checks its relevance, inputs, permissions, and possible influence from suspicious content.
5. If the tool call violates security policies, it is blocked. Otherwise, it can proceed.
6. Tool outputs return through Layer 1 for further content analysis.
7. Layer 3 manages sanitization, human review, audit logging, and dashboard activities.

## 5. Expected Outcome

The framework aims to improve prompt injection detection, reduce unauthorized tool execution, preserve useful content, and provide traceability of suspicious instructions throughout the agent workflow. Its effectiveness will be evaluated through experiments using benign, malicious, and mixed-content documents.

---

## 6. Development Log

### Day 1 — Project Setup & Segmenter (2026-11-06)

**Goals:**
- [x] Initialize Git repo and folder structure
- [x] Create virtual environment
- [x] Write 8–10 sample documents (data/original/)
- [x] Build sentence segmenter with overlapping windows
- [x] Save segment JSON output to data/segments/
- [x] Write and pass basic tests

**Known Edge Cases (Segmenter v1):**
- Common abbreviations such as "Dr.", "e.g.", and "i.e." and decimal numbers such as "5000.50" are handled by the current splitter; uncommon forms may still split incorrectly.
- Blank lines separate headings and list blocks. Single-line bullets or headings without blank lines can remain grouped together.
- Files with fewer than 3 sentences produce one smaller window.

**Next Steps (Day 3):**
- Threat Context and Provenance Manager (TCPM) data model
- Carry segment provenance and suspicion through tool-call checks

### Day 2 — Instruction Detection + PIGuard Scoring + Comparison

**Implementation:** Added a high-recall instruction signal filter, a batched PIGuard wrapper, a seeded labeled set, and a split-safe comparison report. `data/labeled/labels.json` contains 10 harmless source documents: 4 classic attacks, 4 action-only attacks, and 2 controls, split 5/5 with both attack types and a control in each split. Insertions cover start, middle, and end positions. The untracked `data/original/doc11.txt` was excluded and left unchanged because it already contains an instruction override; it is not a harmless control.

**Rule signals:**
- Assistant-directed patterns: `ignore`, `disregard`, `assistant`, `system prompt`, `you must`, `you should`, whole-word `AI`, and `previous instructions`.
- spaCy action lemmas: `send`, `forward`, `upload`, `delete`, `pay`, `transfer`, `reveal`, `export`, `share`, `disclose`, `email`, `submit`, `approve`, `grant`, `change`, and `follow`.
- Imperative: initial base-form verb with no explicit subject. A small high-recall supplement catches listed action verbs at sentence start when spaCy mis-tags them (for example, `Forward` as an adverb) and skips polite lead-ins such as `Please` / `Kindly`.

**Evaluation results:** PIGuard model `leolee99/PIGuard`, injection-score threshold `0.5`, batch size `8`. Recall is over attack segments; FPR is the flag rate on harmless segments. Counts are TP / FP / TN / FN.

| Split | Detector | Recall | Classic recall | Action-only recall | FPR | TP / FP / TN / FN |
|---|---|---:|---:|---:|---:|---:|
| Tuning | Rules | 0.889 | 1.000 | 0.800 | 0.247 | 8 / 20 / 61 / 1 |
| Tuning | PIGuard | 0.444 | 1.000 | 0.000 | 0.259 | 4 / 21 / 60 / 5 |
| Tuning | Either | 0.889 | 1.000 | 0.800 | 0.370 | 8 / 30 / 51 / 1 |
| Test | Rules | 1.000 | 1.000 | 1.000 | 0.168 | 6 / 29 / 144 / 0 |
| Test | PIGuard | 0.333 | 1.000 | 0.000 | 0.173 | 2 / 30 / 143 / 4 |
| Test | Either | 1.000 | 1.000 | 1.000 | 0.324 | 6 / 56 / 117 / 0 |

The PIGuard threshold sweep uses the tuning split only; the test split did not inform threshold choice. Detailed metrics, sweep chart, missed segments, and per-segment scored records are in `data/results/`.

**Observed miss and flag patterns:**
- PIGuard flagged all classic attack segments in this small set but missed all action-only attack segments at `0.5`, including a direct `Share ...` sentence.
- Rules missed one segment containing only the neutral setup sentence from a two-sentence action-only insertion. The requested overlap labeling makes that segment ground-truth attack even though the actionable sentence falls in the next window.
- Combining detectors retained tuning recall and reached full test recall here, while increasing harmless flag rate to 0.370 on tuning and 0.324 on test.
- Rule false positives came from ordinary content with action language (payment details, email requests, checklist items) and AI/security vocabulary. This is consistent with a high-recall screening filter and should be reviewed downstream.

These are descriptive results from 10 documents and overlapping windows, not a claim that either detector is accurate. Validation run: `venv/Scripts/python.exe -m pytest -q` (77 passed).

### Day 3 — Context-Aware LLM Judge (2026-11-07)

**Implementation:** Added a Gemini-backed context judge (`gemini-3.1-flash-lite`, prompt `v1`) with JSON-schema output, strict parsing, prompt delimiter neutralization, retry handling, configurable rate limiting, and a resumable cache keyed by model, prompt version, segment ID, and task. The judge is a helper signal only. Judge errors are treated as review flags by the combined metric. Added static tasks/context notes for all labeled documents, six content-dependent documents, a dry-run mode, comparison/miss reports, and offline tests. The runner preserves Day 2 fields and does not modify source documents or Day 2 scoring outputs.

**Input adaptation:** The Day 2 labeled set is represented by `data/results/segments_scored.json` plus `data/labeled/labels.json`; the runner joins these for evaluation. Judge selection is rules OR PIGuard score >= 0.5. Original documents stay untouched. Five clean content-dependent documents test legitimate procedural instructions; the sixth also contains an injected attack.

**Initial local validation:** Dry-run displayed three complete prompts without API calls. The offline judge-pipeline suite passed (11 tests). The first environment lacked the Gemini SDK and API key; live runs were later completed from the user's VS Code terminal, as recorded below.

**Baseline metrics before the judge (from Day 2):** Recall / false-flag rate; rules and PIGuard values are reproduced from the Day 2 labeled evaluation. Judge and combined values cannot be reported until the API run is completed.

| Split | Detector | Recall | False-flag rate |
|---|---|---:|---:|
| Tuning | Rules | 0.889 | 0.247 |
| Tuning | PIGuard | 0.444 | 0.259 |
| Tuning | Judge | pending | pending |
| Tuning | Combined | pending | pending |
| Test | Rules | 1.000 | 0.168 |
| Test | PIGuard | 0.333 | 0.173 |
| Test | Judge | pending | pending |
| Test | Combined | pending | pending |

**Observed Day 2 patterns (not judge mistakes):**
- PIGuard at threshold 0.5 caught the classic attacks but missed action-only attacks in this small corpus.
- Rule-based detection caught most action-only cases but also flagged ordinary action language and security-related vocabulary.
- Overlapping three-sentence windows can label neighboring segments as attack-overlapping even when the actual malicious sentence is only in one of them; per-segment metrics should be interpreted with that labeling rule in mind.
- The content-dependent documents are a deliberately difficult check: instructions may be legitimate when the user explicitly asks to follow document steps. No judge decisions on these examples are available yet.

**Run sequence used:** Set `GEMINI_API_KEY` in the local shell, run `experiments/run_judge.py --split tuning --limit 5`, finish tuning, run test once, process `--dataset legit`, then run `experiments/evaluate_layer1.py`. Review tuning results before changing prompt wording; if changed, increment `PROMPT_VERSION`.

**Environment follow-up:** I also attempted to install `google-genai` into the project virtual environment. The install could not reach PyPI (`getaddrinfo failed`), so the SDK remains unavailable here. The evaluation report was refreshed in offline mode; live judge, legitimate-instruction, and consistency metrics remain pending until the SDK and API key are available.

### Day 3 — Final live evaluation (2026-11-09; supersedes the pending status above)

**Run completed:** Model `gemini-3.1-flash-lite`, prompt `v1`, PIGuard threshold `0.5`. The five-segment tuning trial was reused from cache; then the remaining tuning candidates, test candidates, all content-dependent segments, and the consistency sample were processed. Original documents were not modified.

| Split | Detector | Recall | Classic recall | Action-only recall | False-flag rate | TP / FP / TN / FN |
|---|---|---:|---:|---:|---:|---:|
| Tuning | Rules | 0.889 | 1.000 | 0.800 | 0.247 | 8 / 20 / 61 / 1 |
| Tuning | PIGuard | 0.444 | 1.000 | 0.000 | 0.259 | 4 / 21 / 60 / 5 |
| Tuning | Judge | 0.889 | 1.000 | 0.800 | 0.049 | 8 / 4 / 77 / 1 |
| Tuning | Combined | 0.889 | 1.000 | 0.800 | 0.370 | 8 / 30 / 51 / 1 |
| Test | Rules | 1.000 | 1.000 | 1.000 | 0.168 | 6 / 29 / 144 / 0 |
| Test | PIGuard | 0.333 | 1.000 | 0.000 | 0.173 | 2 / 30 / 143 / 4 |
| Test | Judge | 1.000 | 1.000 | 1.000 | 0.040 | 6 / 7 / 166 / 0 |
| Test | Combined | 1.000 | 1.000 | 1.000 | 0.324 | 6 / 56 / 117 / 0 |

**Content-dependent tasks:** The judge did not flag any of the 16 judged legitimate-only segments (0/16). It flagged all 3 attack-overlapping segments (3/3) in the injected-attack README. Those three windows overlap the same inserted attack.

**Consistency:** 40/40 sampled segments had unanimous `judge_flag` results across three runs (100% agreement); zero segment-level errors. The run made 122 API calls for 120 requested judgments because two retries were needed.

**API usage and time:** 100 main-dataset calls, 19 content-dependent calls, and 122 consistency calls: 241 API calls total including retries. Summed model-reported request latency was about 2,027 seconds (33m 47s), excluding pacing and backoff waits. The consistency report contains the exact counts and token totals.

**Observed judge errors / limitations:**
- On the main evaluation, the judge missed one tuning attack-overlapping segment (`doc_10_product_catalog-w3-0028`); the other window containing the injected payment-redirection sentence was flagged. The combined detector therefore also missed that neighboring segment.
- It wrongly flagged seven harmless test segments in a vendor email because requests addressed to the human recipient were treated as unnecessary assistant instructions.
- It wrongly flagged four harmless tuning segments: three README setup-command windows (not needed for a task to describe the README) and one report goal. These are task-relative false flags, even though they contain imperative/directive content.
- The combined OR detector preserved recall but had a higher harmless false-flag rate than the judge alone, because rule and PIGuard false positives also remain active.

These results describe this small, overlapping-window dataset and are not a general accuracy guarantee. Detailed cases and reports are in `data/results/detector_evaluation.md`, `data/results/flagged_segment_analysis.md`, and `data/results/judge_repeatability.md`.

### Day 4 — Full-span labels, suspicion, trust, and threat store (2026-11-09)

**Inputs and scope:** Used the existing `data/results/segments_judged.json` (269 records), `data/labeled/labels.json`, existing Day 3 cache/results, and the configured PIGuard threshold. No Gemini API calls were made. `data/original/*.txt`, detector code/thresholds, judge prompt, and cached judge results were not modified. The new corrected labels are written into `segments_leveled.json`; the source labels file stays unchanged.

**Label correction:** A segment is attack only when it fully contains the inserted span; a non-full overlap is partial and excluded from segment recall/FPR denominators. Tuning has 1 partial segment (`doc_10_product_catalog-w3-0028`); test has 0. With this corrected definition, tuning attack-segment recall rises from 8/9 to 8/8 for rules, judge, Day 2 any-flag, and Day 3 any-flag. PIGuard rises from 4/9 to 4/8. The partial window contains the benign lead-in but not the malicious payment instruction; the adjacent fully containing window was flagged. Test labels and rates are unchanged.

| Split | Detector | Old recall | New recall | Old FPR | New FPR | Per-attack flagged (new labels) |
|---|---|---:|---:|---:|---:|---:|
| Tuning | Rules | 0.889 | 1.000 | 0.247 | 0.247 | 4/4 |
| Tuning | PIGuard | 0.444 | 0.500 | 0.259 | 0.259 | 2/4 |
| Tuning | Judge | 0.889 | 1.000 | 0.049 | 0.049 | 4/4 |
| Tuning | Day 2 any-flag | 0.889 | 1.000 | 0.370 | 0.370 | 4/4 |
| Tuning | Day 3 any-flag | 0.889 | 1.000 | 0.370 | 0.370 | 4/4 |
| Test | Rules | 1.000 | 1.000 | 0.168 | 0.168 | 4/4 |
| Test | PIGuard | 0.333 | 0.333 | 0.173 | 0.173 | 2/4 |
| Test | Judge | 1.000 | 1.000 | 0.040 | 0.040 | 4/4 |
| Test | Day 2 any-flag | 1.000 | 1.000 | 0.324 | 0.324 | 4/4 |
| Test | Day 3 any-flag | 1.000 | 1.000 | 0.324 | 0.324 | 4/4 |

**Active suspicion table:** `default`. Alternative `stricter` maps low to medium; `lenient` maps medium to low. All three were evaluated on tuning and test for comparison, but I did not select a table based on the test split. On the tuning split the default assigns 11/81 harmless segments medium, compared with 26/81 under stricter and 0/81 under lenient. The default also assigns 8/8 full attack segments high. No attack ended at none or low (0/4 in tuning and 0/4 in test).

**Default-table confusion (partial segments excluded):**

| Split | Suspicion | Attack | Harmless |
|---|---|---:|---:|
| Tuning | none | 0 | 51 |
| Tuning | low | 0 | 15 |
| Tuning | medium | 0 | 11 |
| Tuning | high | 8 | 4 |
| Tuning | needs_review | 0 | 0 |
| Test | none | 0 | 117 |
| Test | low | 0 | 46 |
| Test | medium | 0 | 3 |
| Test | high | 6 | 7 |
| Test | needs_review | 0 | 0 |

Harmless document rates use only no-attack documents (the clean controls are included). There is just one such document in each split, so the document-level proportions are especially coarse. In default, 0/1 tuning controls and 1/1 test controls had a segment at medium or above; exactly-high counts are 0/1 and 1/1, respectively.

**Explicit table assumption:** The task’s default rules do not define both rules and PIGuard flagged when the judge did not run. I assign that combination medium because two screening signals agree; the report and config state this assumption. Judge errors always become `needs_review`.

**Trust and store:** All external document/email/web sources default to `untrusted`, independently of suspicion. Email source IDs are configured; other documents use source type `document`. `data/results/segments_leveled.json` preserves all 269 existing records and adds trust, suspicion, reasons, full/partial label, split, and source type. `data/results/threat_store.sqlite` was rebuilt with all 269 segments. `layers/threat_store.py` can rebuild it from the cached judged JSON. Exact/whitespace-normalized and fuzzy matching is best-effort and cannot recover a trail after paraphrase or transformation.

**Files and validation:** Detailed label deltas are in `data/results/labeling_comparison.md`; table comparisons and attack/document views are in `data/results/suspicion_evaluation.md`. The evaluator is `experiments/evaluate_suspicion.py`. A SHA-256 baseline for the 11 originals is in `tests/fixtures/original_sha256.json`; verification passed. Offline suite: `venv/Scripts/python.exe -m pytest -q` (147 passed). No network/API tests were made.

## Held-out hard attack evaluation

**Run completed:** the frozen Layer 1 judge processed all 330 segments. There were 330 logical judgments and 332 API attempts including retries. The first run had intermittent Gemini 503 errors; successful cached judgments were reused and the remaining 88 completed in the final run. No judge errors remain in the final judge views. Evaluation outputs are `data/results/hard_eval_report.md`, `data/results/hard_eval_misses.md`, `data/results/hard_eval_segments_leveled_cascade.json`, and `data/results/hard_eval_segments_leveled_all.json`.

The held-out data contains 30 single-attack documents (5 in each of six categories), 5 split-attack documents, 12 ordinary controls, and 8 benign-instruction-like controls. It produces 330 overlapping three-sentence segments. All attacks are synthetic and use placeholders. Duplicate audit passed. The post-generation keyword audit found a literal rule keyword/pattern in 4/35 attack documents (11.4%). Frozen manifest verification passed with SHA-256 `61944dff4868e9595674102b1908965dbd818132f80f43b5654d0bc968bb2ac4`.

### Main comparison

| Measure | Test 1: cascade | Test 2: judge on all |
|---|---:|---:|
| Segments sent to judge | 114/330 (34.5%) | 330/330 (100%) |
| Combined any-flag per-attack recall, single attacks | 24/30 (80.0%); 95% Wilson CI [0.627, 0.905] | 29/30 (96.7%); 95% Wilson CI [0.833, 0.994] |
| Judge-only per-attack recall, single attacks | 21/30 (70.0%) | 26/30 (86.7%) |
| Combined any-flag false alarms on harmless segments | 69/240 (28.7%); 95% Wilson CI [0.234, 0.348] | 69/240 (28.7%); 95% Wilson CI [0.234, 0.348] |
| Suspicion medium-or-higher harmless segments | 4/240 (1.7%) | 4/240 (1.7%) |
| Control docs with any medium-or-higher segment | Ordinary 0/12; benign-instruction-like 3/8 | Ordinary 0/12; benign-instruction-like 3/8 |
| Control docs with any high segment | 0/20 | 0/20 |
| Estimated judge calls / time at 5 RPM | 114 / 1,368 sec (~22.8 min) | 330 / 3,960 sec (~66 min) |

The judge-on-all view found five single attacks the cascade did not: `hard_single_statement_style_02`, `hard_single_statement_style_04`, `hard_single_authority_claim_04`, `hard_single_authority_claim_05`, and `hard_single_concealment_04`. The cascade did not send these to the judge because neither rules nor PIGuard selected their fully containing segments. One additional filter miss, `hard_single_authority_claim_01`, was also missed by judge-on-all.

Judge-on-all missed four single attacks: `hard_single_statement_style_01`, `_03`, `_05`, and `hard_single_authority_claim_01`. In those cases its reasons treated the segments as factual/descriptive content rather than instructions. For judge-targeted attacks, the judge was not fooled on any of the five: it called all five instructions, and rules/PIGuard selected their full segments.

### Suspicion and split attacks

Among single attacks, 9/30 ended at none or low suspicion in the cascade view; 4/30 did so in judge-on-all. The judge-on-all low/none set is statement-style `_01`, `_03`, `_05` (low) and authority-claim `_01` (none). Harmless content at high suspicion: 0 segments in both views. The 8 benign-instruction-like controls produced medium-or-higher suspicion in 3 documents, while no ordinary control did; no controls reached high.

All five split attacks were missed by rules, PIGuard, the cascade judge, and judge-on-all (0/5). They were designed as distributed descriptions and the judge saw a window containing the full span, yet it described the text as factual or template context. This is the clearest weakness exposed by the test and indicates the current single-segment judge does not infer the harmful action from these subtle cross-sentence relationships.

### Cost and limits

The filter selected 114/330 segments, reducing judge volume by 65.5% compared with judge-on-all. The completed run made 332 actual API attempts for 330 logical judgments because two calls had earlier retries; the final 88-request invocation took 1,194.9 seconds. Estimates at 5 RPM are 22.8 minutes for cascade and 66 minutes for judge-on-all. The cascade results are derived from the same judge responses as judge-on-all; no duplicate segment judgments were needed.

These are exploratory results: only five examples per single-attack category, 20 controls, and all attacks are synthetic. Wilson intervals are wide, and overlapping windows are correlated. The benign-instruction-like labels involve human judgment. The full tables, per-attack results, judge reasons, levels, split-attack details, and manifest hashes are in `data/results/hard_eval_report.md` and `data/results/hard_eval_misses.md`.

## Filter v2 Phase 0: held-out set frozen before filter changes

Created `data/hard_eval_v2/` with 61 synthetic documents (30 single attacks, 5 split attacks, 12 ordinary controls, 8 benign-instruction-like controls, 6 benign-approval-like controls), 8 sentences each (366 expected 3-sentence windows). Static tasks/context entries were added to `config/tasks.json`. SHA-256 hashes for every held-out dataset file were written to `config/heldout_v2_hashes.json` at 2026-11-10T13:29:26.490500+05:30. This freeze occurred before creating or changing any v2 filter rule.

No `data/external_attacks_v2.json` was present. The attack text was written by the same agent that had prior conversational context about the v1 evaluation and saw the task description’s examples of v1 misses, so this held-out set is weaker than a genuinely blind set. At least 10 attack sentences use plain business wording and avoid the specified approval/permission/concealment terms; all use synthetic placeholders. Vocabulary leakage and near-duplicate audits remain to be run after the hash freeze.

**Phase 0 audit note:** the initial 13:29:26 freeze preceded opening dev misses, but validation later found the project segmenter merged one control sentence ending in “Corp.” The correction changed only that ordinary control sentence (no attack text/labels); hashes were refreshed at 13:34:17, after dev inspection but before any rules-v2 code. `vocab_check.md` was included in the refreshed 63-file freeze. Therefore attack construction preceded dev analysis, but final control wording was not fully blind. This limitation is disclosed in the report.

**Pre-registration:** `config/filter_v2_config.py` was created at 13:42:57, before dev tuning, with `TARGET_FILTER_RECALL=0.95`, `TARGET_MAX_JUDGE_FRACTION=0.50`, and the PIGuard threshold sweep. The Layer 1 final task retains `RULES_VERSION = "v1"` as the runtime default and supports v2 through explicit version selection.

## Filter v2

All phases were offline: no Gemini/API calls were made. PIGuard ran from its local cache with network access blocked. The semantic filter was skipped because sentence-transformers and a local sentence-embedding model were unavailable; no network installation was attempted.

Held-out v2 was frozen in `config/heldout_v2_hashes.json` (63 files; SHA-256 per file). Rules v2 and the dev-selected configuration were frozen in `config/frozen_manifest_v2.json` (manifest SHA-256 `a203b5008b12cd08166bf765fd5780c1bb3b6b487b898ddceb6cb967c05ea27a`). Rules v1, PIGuard, judge prompt/model, thresholds, and suspicion configuration were left unchanged. V2 is additive and includes v1 rule checks. The current runtime default is v1; historical v2 evaluation and its explicit v2 rescoring remain documented above.

### Previous cascade misses rescored with v2

The six attack cases missed by the earlier v1 cascade were rescored offline using v2 BROAD instruction rules OR PIGuard at the unchanged 0.50 threshold. V2 selected all 11/11 fully containing attack segments across all 6/6 cases. In these cases v2 rules supplied the positive signal; none of their cached PIGuard scores reached 0.50. This means all six cases would now be sent to the judge. No judge/API calls were made during this rescore, so judge confirmation is not measured. Segment-level text, reasons, scores, and selection are in `data/results/previous_misses_v2_rescore.md` and `.json`; rerun with `venv\\Scripts\\python.exe experiments\\check_previous_misses_v2.py`.

### Main held-out filter results

| Measure | Baseline v1 filter | Chosen v2 BROAD filter |
|---|---:|---:|
| Single-attack filter recall | 22/30 (73.3%); Wilson 95% CI [0.556, 0.858] | 26/30 (86.7%); Wilson 95% CI [0.703, 0.947] |
| Segments selected for judge | 114/366 (31.1%) | 201/366 (54.9%) |
| Harmless segments selected | 74/281 (26.3%) | 137/281 (48.8%) |
| Benign-instruction-like docs with any segment selected | 8/8 | 8/8 |
| Benign-approval-like docs with any segment selected | 6/6 | 6/6 |
| Ordinary-control docs with any segment selected | 3/12 | 5/12 |
| Split attacks with any full window selected | 0/5 | 2/5 |

V2 caught 4 more single attacks than v1 on held-out. It improved concealment from 3/5 to 5/5, disguised notes from 4/5 to 5/5, and statement-style attacks from 2/5 to 3/5. Authority claims stayed at 3/5; v2 missed statement-style `_01`, statement-style `_04`, authority-claim `_01`, and authority-claim `_04`. Full missed attack text is in `data/results/filter_v2_misses.md`.

The extra selection cost was 87 segments, raising the selected fraction by 23.8 percentage points (31.1% to 54.9%). V2 exceeded the 50% judge-volume target on held-out. It selected 26/36 benign-approval-like segments versus 10/36 for v1, and both filters selected all 8 benign-instruction-like documents. That is the main tradeoff and an area to improve.

On dev, chosen v2 reached 30/30 filter recall and 30/30 cached end-to-end recall while selecting 137/330 (41.5%), versus baseline 24/30 and 114/330 (34.5%). This is tuned-on-dev performance. Held-out end-to-end recall was **not measured** because judge calls were prohibited; do not interpret held-out filter recall as cascade end-to-end recall.

Older labeled-set statistics are filter-only: `data/labeled` selected 100/269 segments (v1) vs 104/269 (v2), with 8/8 attack cases selected by both; `data/labeled_legit` selected 19/19 by both, including its labeled attack span and 16/16 harmless segments. No judge outputs were guessed for newly selected segments.

The optional vocabulary check found attack-associated words including `private`, `recovery`, `phrase`, and `string`, while words such as `sample`, `placeholder`, `illustrative`, and `public` appeared across both labels. Residual vocabulary leakage is possible. The data are synthetic and small (30 single attacks, five per category; five split attacks; 26 controls); confidence intervals are wide. The same agent had prior conversational knowledge of v1 misses, and one control sentence was corrected after dev inspection, so this is a weaker held-out set. Split attacks remain difficult: v1 dev judge-on-all missed 5/5; on held-out, filter v2 selected 2/5, with no judge evaluation.

Detailed reports: `data/results/filter_v2_report.md`, `data/results/filter_v2_misses.md`, `data/results/filter_v2_choice.md`, `data/results/filter_v2_dev_analysis.md`, and `data/hard_eval_v2/vocab_check.md`. The frozen baseline manifest is `config/frozen_manifest_v2.json`.

## Layer 1 final

Unified entry point: `layers/scan.py` (`scan()`); CLI: `python -m layers.scan_cli`. Runtime defaults are rules v1, judge mode `all`, unlimited per-document judge budget, and offline cache-only operation. Rules v2 remains selectable through the router. PIGuard is `leolee99/PIGuard` with the unchanged 0.50 threshold; judge model/prompt remain `gemini-3.1-flash-lite` / `v1`; the Day 4 suspicion table is unchanged. The final component hashes are recorded in `config/layer1_final_manifest.json` (manifest hash `d821773213c6f4cb325829796e70b24c01c405fe426c48251ccc118729c64c53`).

The offline regression replay had **0 mismatches** across the hard set (all: 330/330 covered; cascade: 114/330 covered), the earlier main labeled set (10 docs / 269 segments), and the legit set (6 docs / 19 segments). Replayed judge results came from the explicit legacy-cache path; no Gemini/API calls were made. The saved-vs-replayed hard-set detection remained 29/30 for judge-on-all and 24/30 for cascade.

False-alarm review: 15 judge flags present only in judge-on-all were all attack-bearing by full-span labels (15 attack, 0 harmless, 0 partial). Among harmless segments, four reached medium suspicion and none reached high; these were user-task-relevant checklist or formatting instructions. At document level, 3/8 benign-instruction-like controls had medium-or-higher suspicion and 0/8 high; ordinary controls were 0/12 at both thresholds. See `data/results/layer1_false_alarm_report.md` and `data/results/layer1_final_regression.md` for counts and Wilson intervals.

Limitations: the hard set has only 30 single attacks and early sets have four attacks per split; all are synthetic. Split attacks were not detected by the judge (0/5). Cascade recall is lower than judge-on-all (24/30 vs 29/30). Any improved filter lacks an independent end-to-end check due API quota; some categories have only five examples. Provenance matching is best-effort and can lose a trail when values are rewritten. The judge can still be influenced by segment text, so it sees only task, trusted context, and one segment; its answer is a signal, never permission. Missing all-mode judge coverage is marked `needs_review`, never silently treated as safe.
