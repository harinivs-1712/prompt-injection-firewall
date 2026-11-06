# prompt-injection-firewall

A research framework for detecting and mitigating prompt injection attacks in LLM-based agents.

## Overview

Prompt injection attacks embed malicious instructions inside external content (documents, emails, tool outputs) to hijack the behavior of AI agents. This project implements a three-layer detection and mitigation framework with a shared provenance tracking module.

## Project Structure

```
prompt-injection-firewall/
├── data/
│   ├── original/      # Read-only sample documents
│   └── segments/      # JSON output from the segmenter
├── layers/            # Security layer implementations
│   ├── layer1/        # Content analysis engine
│   ├── layer2/        # Tool security and policy engine
│   └── layer3/        # Sanitization, HITL, audit logging
├── shared/            # Threat Context and Provenance Manager
├── tests/             # Unit and integration tests
└── notes.md           # Architecture and development log
```

## Getting Started

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/harinivs-1712/prompt-injection-firewall.git
cd prompt-injection-firewall

# Create a virtual environment
python -m venv venv

# Activate the virtual environment (Windows)
venv\Scripts\activate

# Activate the virtual environment (macOS/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Segmenter

```bash
python layers/segmenter.py
```

Segments will be saved as JSON files in `data/segments/`.

### Running Tests

```bash
pytest tests/ -v
```

## Layers

### Layer 1: Context-Aware Content Analysis

Segments external content and classifies instructions as benign, suspicious, or malicious.

### Layer 2: Tool-Level Security Analysis

Validates tool calls against a deterministic policy engine before execution.

### Layer 3: Safe Response and Security Management

Handles sanitization, human-in-the-loop review, audit logging, and the security dashboard.

### Shared: Threat Context and Provenance Manager (TCPM)

Tracks the origin, trust level, and influence of every content segment across all layers.

## Status

- [x] Day 1: Project setup, sample documents, segmenter
- [ ] Day 2: Instruction identification, TCPM data model
- [ ] Day 3+: Layer 1 classifier, Layer 2 policy engine

## License

MIT
