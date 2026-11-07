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
- Imperative: initial base-form verb with no explicit subject. A small high-recall supplement catches listed action verbs at sentence start when spaCy mis-tags them (for example, `Forward` as an adverb).

**Evaluation results:** PIGuard model `leolee99/PIGuard`, injection-score threshold `0.5`, batch size `8`. Recall is over attack segments; FPR is the flag rate on harmless segments. Counts are TP / FP / TN / FN.

| Split | Detector | Recall | Classic recall | Action-only recall | FPR | TP / FP / TN / FN |
|---|---|---:|---:|---:|---:|---:|
| Tuning | Rules | 0.889 | 1.000 | 0.800 | 0.247 | 8 / 20 / 61 / 1 |
| Tuning | PIGuard | 0.444 | 1.000 | 0.000 | 0.259 | 4 / 21 / 60 / 5 |
| Tuning | Either | 0.889 | 1.000 | 0.800 | 0.370 | 8 / 30 / 51 / 1 |
| Test | Rules | 1.000 | 1.000 | 1.000 | 0.156 | 6 / 27 / 146 / 0 |
| Test | PIGuard | 0.333 | 1.000 | 0.000 | 0.173 | 2 / 30 / 143 / 4 |
| Test | Either | 1.000 | 1.000 | 1.000 | 0.312 | 6 / 54 / 119 / 0 |

The PIGuard threshold sweep uses the tuning split only; the test split did not inform threshold choice. Detailed metrics, sweep chart, missed segments, and per-segment scored records are in `data/results/`.

**Observed miss and flag patterns:**
- PIGuard flagged all classic attack segments in this small set but missed all action-only attack segments at `0.5`, including a direct `Share ...` sentence.
- Rules missed one segment containing only the neutral setup sentence from a two-sentence action-only insertion. The requested overlap labeling makes that segment ground-truth attack even though the actionable sentence falls in the next window.
- Combining detectors retained tuning recall and reached full test recall here, while increasing harmless flag rate to 0.370 on tuning and 0.312 on test.
- Rule false positives came from ordinary content with action language (payment details, email requests, checklist items) and AI/security vocabulary. This is consistent with a high-recall screening filter and should be reviewed downstream.

These are descriptive results from 10 documents and overlapping windows, not a claim that either detector is accurate. Validation run: `venv/Scripts/python.exe -m pytest -q` (77 passed).
