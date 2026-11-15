"""Generate a reproducible offline report from the hand-written scenarios."""
from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory

from harness.runner import load_traces, run_trace

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "harness" / "scenarios" / "day6_traces.yaml"
POLICIES = ROOT / "policies"
OUTPUT = ROOT / "data" / "results" / "layer2_day6_results.md"


def report_day7():
    from harness.report_day7 import main as day7_main
    day7_main()


def report_day6():
    traces = load_traces(SCENARIOS)
    groups = defaultdict(list)
    for trace in traces:
        groups[trace["policy"]].append(trace)
    rows = []
    with TemporaryDirectory(prefix="firewall-harness-") as temp:
        for policy, items in groups.items():
            stats = {mode: {"normal": [0, 0], "attack": [0, 0]} for mode in ("no defense", "deny asks", "approve asks")}
            for index, trace in enumerate(items):
                path = POLICIES / f"{policy}.yaml"
                for mode, protect, approve in (("no defense", False, False), ("deny asks", True, False), ("approve asks", True, True)):
                    result = run_trace(trace, path, Path(temp) / f"{policy}-{index}-{mode.replace(' ', '-')}", protect=protect, approve=approve)
                    counts = stats[mode][trace["label"]]
                    counts[0] += 1
                    counts[1] += int(result["executed"])
            for mode, values in stats.items():
                normal_total, normal_exec = values["normal"]
                attack_total, attack_exec = values["attack"]
                rows.append(f"| {policy} | {mode} | {normal_exec}/{normal_total} | {attack_exec}/{attack_total} |")
    body = "# Layer 2 hard-rule engine: offline harness results\n\n"
    body += "Each trace is a hand-written example, not a statistical benchmark. The fake tools only write tool and argument names in a temporary directory. ‘Approve asks’ executes every ASK result to show the effect of user approval.\n\n"
    body += "| Policy | Mode | Normal traces executed | Attack traces executed |\n|---|---|---:|---:|\n" + "\n".join(rows) + "\n\n"
    body += "The rules are deterministic and policy-driven. This harness does not use Layer 1 content analysis, a model judge, network access, or real side effects.\n"
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(body, encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "day6":
        report_day6()
    elif len(sys.argv) > 1 and sys.argv[1] == "day7":
        report_day7()
    elif len(sys.argv) > 1 and sys.argv[1] == "day8":
        from harness.report_day8 import main as report_day8
        report_day8()
    else:
        from harness.report_day9 import main as report_day9
        report_day9()
