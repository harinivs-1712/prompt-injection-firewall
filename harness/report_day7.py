"""Create the Day 7 scripted output-inspection report without network calls."""
from pathlib import Path
from tempfile import TemporaryDirectory

from harness.runner import load_traces, run_trace

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "harness" / "scenarios" / "day7_traces.yaml"
POLICIES = ROOT / "policies"
OUTPUT = ROOT / "data" / "results" / "layer2_day7_results.md"


def main():
    rows = []
    followup_seen = False
    with TemporaryDirectory(prefix="firewall-day7-") as temp:
        for index, trace in enumerate(load_traces(SCENARIOS)):
            path = POLICIES / f"{trace['policy']}.yaml"
            result = run_trace(trace, path, Path(temp) / f"trace-{index}", protect=True, approve=True)
            inspection = result.get("inspection")
            if inspection is None:
                levels, action, view, reasons = "not run", "not run", "original", "-"
            else:
                levels = ", ".join(f"{key}:{value}" for key, value in inspection.level_counts.items() if value) or inspection.max_level
                action, view = inspection.action, result["view_type"]
                reasons = ", ".join(inspection.reason_codes)
            follow = result.get("follow_up")
            if follow and follow.get("needs_day8_linking"):
                followup_seen = True
                reasons += f"; follow-up {follow['action']} (needs Day 8 linking; not counted as blocked)"
            rows.append(f"| {trace['name']} | {levels} | {action} | {view} | {reasons} |")
    text = "# Layer 2 Day 7: tool-output inspection results\n\n"
    text += "These traces use a deterministic scripted scanner with placeholder markers. They are functional checks, not measured detection accuracy. A masked or held output does not prove that an agent behaves safely; inspection happens after the tool already ran.\n\n"
    text += "| Trace | Levels | Output action | Agent view | Reasons / notes |\n|---|---|---|---|---|\n" + "\n".join(rows) + "\n\n"
    text += "The poisoned-output follow-up call passes the Day 6 rules because the firewall does not yet link inspected segments to later arguments. It is labeled as a Day 8 provenance task and is not counted as blocked. Tool outputs may already have caused side effects before inspection.\n\n"
    text += "Limits: the scripted scanner is not Layer 1; masking removes only flagged spans and remaining text can still influence the agent; holding may block useful work; judge calls consume the session budget; unreviewed content is passed with a mark by default; JSON keys and non-string values are not scanned; oversize and depth-limited content may remain unscanned; span matching is best-effort.\n"
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
