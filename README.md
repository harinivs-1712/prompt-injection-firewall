# Prompt Injection Firewall

This repository is a student-built, agent-agnostic firewall prototype for reducing risks from prompt injection in external content and tool calls. It combines a deterministic, policy-driven Layer 2 tool gate with an optional Layer 1 content scanner; the scripted evaluation is synthetic and does not establish real-world accuracy or real-agent behavior.

## Architecture

```text
External content -> agent integration -> scan_content() -> Layer 1 analysis -> agent context
Agent tool request -> check_tool_call()/authorize_tool_call() -> Layer 2 policy gate
                                                              -> approval callback for ASK
Tool output -> inspect_tool_output() -> Layer 1 analysis -> agent receives agent_view only
All decisions and review events -> metadata-only append-only audit store
```

The host application has two required integration points: pass external content through `Firewall.scan_content()` before adding it to agent context, and execute a tool only after `check_tool_call()` returns ALLOW (or after resolving ASK through `authorize_tool_call()`). After tools run, inspect their outputs and give the agent only `OutputResult.agent_view`. A host that bypasses these points is outside the protection boundary.

## Quickstart

Python 3.10 or later is required. Install the core package and developer tools, run the offline walkthrough, then run the test suite:

```powershell
python -m pip install -e ".[dev]"
python examples/demo_offline.py
python -m pytest
```

The offline demo uses scripted scanners and approvals. It needs no model key or network access. Optional Layer 1 dependencies are installed with `python -m pip install -e ".[layer1]"`; local model weights and a judge API key are needed only for the corresponding live/model-backed paths.

## Layer 1 judge modes

`all` is the default and sends every segment to the judge when it is available. `cascade` is a budget option that sends only segments selected by the rules OR PIGuard. In the held-out hard test, cascade reviewed 114/330 segments and caught 24/30 single-attack documents; judge-on-all reviewed 330/330 and caught 29/30. Cascade saved 216 judge calls on this set and missed five attacks that judge-on-all caught. These are measured results on the frozen hand-written set, not a universal trade-off estimate. See [Layer 1 evaluation](data/results/hard_eval_report.md) and [Layer 1 use](docs/layer1.md).

## Configuration

- `policies/`: example policies for an email-like agent, a files agent, and a support agent.
- `config/`: strict policy-related settings, detector settings, and frozen evaluation manifests.
- `firewall/`: deterministic Layer 2 engine, with optional code in `firewall/layer1/`.
- `harness/`: source-checkout-only fake tools and scripted evaluation helpers; it is not installed as part of the core distribution.
- `data/results/layer2_eval/`: frozen Day 10 scripted evaluation outputs.

Run `python -m firewall.lint policies/example_agent.yaml` to receive advisory policy warnings. Warnings do not block policy loading.

## Status and limits

This is a prototype and integration library, not a standalone agent or a guarantee against prompt injection. Only content passed through `scan_content()` and tool calls passed through the firewall are checked. Tool-output inspection happens after the tool has run. Linking can miss paraphrased or transformed values, cascade mode may leave content unreviewed, and a human can approve an ASK request. Evaluation claims and limitations are documented in [docs/evaluation.md](docs/evaluation.md); policy setup is in [docs/writing_a_policy.md](docs/writing_a_policy.md).

## License

`LICENSE` is a placeholder: TODO: choose a license.
