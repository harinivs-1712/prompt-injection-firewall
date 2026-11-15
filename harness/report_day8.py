"""Generate Day 8 setting comparisons from deterministic scripted traces."""
from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from firewall import Firewall, SegmentRecord
from firewall.linking import find_links
from firewall.policy import policy_from_mapping
from harness.day8_runner import run_day8_trace
from harness.runner import load_traces

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "harness" / "scenarios" / "day8_traces.yaml"
POLICIES = ROOT / "policies"
OUTPUT = ROOT / "data" / "results" / "layer2_day8_results.md"
SETTINGS = ("no_defense", "hard_only", "linked_deny", "linked_approve")
LABELS = {"no_defense": "No defense", "hard_only": "Day 6 hard rules only",
          "linked_deny": "Hard rules + R-LINK (deny asks)",
          "linked_approve": "Hard rules + R-LINK (approve asks)"}


def _evidence(items):
    if not items:
        return "-"
    return "; ".join(f"{item['kind']}:{item['segment_level']}:{item['match_type']}" for item in items)


def _performance_sanity():
    raw = {"policy_version": "1", "agent_name": "performance_example",
           "tools": {"search": {"description": "Placeholder search", "risk": "low",
                                 "side_effects": False, "args": {"query": {"type": "free_text"}}}},
           "task_categories": {"search": {"allowed_tools": ["search"], "keywords": ["search"]}}}
    policy = policy_from_mapping(raw)
    session = Firewall(policy).start_session("search records")
    sample = "A repeated placeholder sentence with enough words for a shingle match. " * 15
    session.segments.extend({"record": SegmentRecord(f"perf-{index}", "perf-doc", "document", 0,
                                                       len(sample), sample, "none", True, "reviewed")}
                            for index in range(2000))
    started = perf_counter()
    find_links(session, policy, "search", {"query": sample})
    return perf_counter() - started


def main():
    traces = load_traces(SCENARIOS)
    performance_seconds = _performance_sanity()
    results = defaultdict(dict)
    with TemporaryDirectory(prefix="firewall-day8-") as temp:
        for trace_index, trace in enumerate(traces):
            for mode in SETTINGS:
                results[trace_index][mode] = run_day8_trace(
                    trace, POLICIES / f"{trace['policy']}.yaml",
                    Path(temp) / f"{trace_index}-{mode}", mode=mode)

    rows = []
    totals = {mode: {"harmful": 0, "harmful_run": 0, "normal": 0, "normal_run": 0,
                     "normal_asks": 0, "normal_blocks": 0} for mode in SETTINGS}
    caught = []
    known_gaps = []
    for trace_index, trace in enumerate(traces):
        for mode in SETTINGS:
            result = results[trace_index][mode]
            for step in result["steps"]:
                evidence = _evidence(step["evidence"])
                rows.append(f"| {trace['name']} | {LABELS[mode]} | {step['decision']} | {step['link_level']} | {evidence} | {str(step['executed']).lower()} | {str(step['harmful_executed']).lower()} |")
                stat = totals[mode]
                if step["harmful"]:
                    stat["harmful"] += 1
                    stat["harmful_run"] += int(step["harmful_executed"])
                else:
                    stat["normal"] += 1
                    stat["normal_run"] += int(step["executed"])
                    stat["normal_asks"] += int(step["decision"] == "ask")
                    stat["normal_blocks"] += int(step["decision"] == "block")
        hard_steps = results[trace_index]["hard_only"]["steps"]
        linked_steps = results[trace_index]["linked_deny"]["steps"]
        if any(s["harmful_executed"] for s in hard_steps) and not any(s["harmful_executed"] for s in linked_steps):
            caught.append(trace["name"])
        if trace.get("calls") and any(call.get("known_gap") for call in trace["calls"]):
            if any(s["harmful_executed"] for s in results[trace_index]["linked_deny"]["steps"]):
                known_gaps.append(trace["name"])

    text = "# Layer 2 Day 8: provenance and intent-linking results\n\n"
    text += "These are deterministic scripted traces, not a detection-accuracy benchmark. The fake tools only log tool and argument names in temporary directories. No network/API calls were made.\n\n"
    text += "| Trace | Setting | Decision | Link level | Evidence (metadata only) | Executed | Harmful executed |\n|---|---|---|---|---|---:|---:|\n" + "\n".join(rows) + "\n\n"
    text += "## Totals\n\n| Setting | Attack success | Task success | False asks / blocks on normal calls |\n|---|---:|---:|---:|\n"
    for mode in SETTINGS:
        s = totals[mode]
        attack = f"{s['harmful_run']}/{s['harmful']} ({100*s['harmful_run']/max(1,s['harmful']):.1f}%)"
        task = f"{s['normal_run']}/{s['normal']} ({100*s['normal_run']/max(1,s['normal']):.1f}%)"
        false = f"{s['normal_asks']} asks, {s['normal_blocks']} blocks / {s['normal']} normal calls"
        text += f"| {LABELS[mode]} | {attack} | {task} | {false} |\n"
    text += "\n## Attacks stopped by linking after passing hard rules\n\n"
    text += ("\n".join(f"- {name}" for name in caught) if caught else "- None in this trace set.")
    text += "\n\n## Known gaps\n\n"
    text += ("\n".join(f"- {name}: rewritten/paraphrased content did not link; the call passed the configured rules. This is a known limitation, not a success." for name in known_gaps)
                if known_gaps else "- No labeled known-gap trace executed in this run.")
    text += "\n\nMatching is best-effort: rewritten, paraphrased, or split values can lose their trail. Intent matching is limited to configured English verbs and simple forms. Session taint can increase approval prompts; unreviewed content can increase POSSIBLE links. A value found only in unflagged external content is informational and may pass. ASK can still be approved carelessly. Segment text remains in session memory for matching.\n"
    text += f"\nPerformance sanity check: matching one free-text argument against 2,000 scripted segments of about 1 KB each took {performance_seconds:.3f} seconds on this run (local environment; not a capacity guarantee).\n"
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
