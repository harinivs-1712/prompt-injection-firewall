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
- Abbreviations like "Dr.", "e.g.", "i.e." may cause false sentence splits → noted as known limit
- Bullet lists / headings with no full stops → handled by `\n{2,}` split pattern
- Files with fewer than 3 sentences → handled by `max(1, len(sents) - window + 1)` guard
- Numbers like "5000.50" → may trigger false split on the dot → known limit

**Next Steps (Day 2):**
- Layer 1: Instruction identification (regex heuristics + LLM classifier)
- Threat Context and Provenance Manager (TCPM) data model
