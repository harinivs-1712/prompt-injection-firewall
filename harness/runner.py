"""Run offline traces through generic fake tools and a configured firewall."""
from pathlib import Path
from firewall import Action, Firewall, load_policy
from harness.fake_tools import build_tools
from harness.scanners import FailingScanner, ScriptedScanner


def run_trace(trace, policy_path, temp_dir, *, protect=True, approve=False):
    policy = load_policy(policy_path)
    tools = build_tools(policy, temp_dir)
    tool = tools.get(trace["tool"])
    if not protect:
        tool_result = tool(**trace["args"]) if tool else None
        return {"action": "executed" if tool else "unknown", "executed": bool(tool), "decision": None,
                "inspection": None, "view_type": "original", "tool_result": tool_result}
    scanner = FailingScanner() if trace.get("scanner_failure") else ScriptedScanner()
    firewall = Firewall(policy, scanner=scanner, linking_enabled=False)
    session = firewall.start_session(trace["task"])
    decision = firewall.check_tool_call(session, trace["tool"], trace["args"])
    executed = decision.action is Action.ALLOW or (decision.action is Action.ASK and approve)
    inspection = None
    tool_result = None
    if executed and tool:
        tool_result = tool(**trace["args"])
        if "output_kind" in trace and trace["output_kind"] == "bytes":
            tool_result = b"opaque placeholder bytes"
        elif "output_repeat" in trace:
            spec = trace["output_repeat"]
            tool_result = spec["text"] * int(spec["count"])
        elif "tool_output" in trace:
            tool_result = trace["tool_output"]
        inspection = firewall.inspect_tool_output(session, trace["tool"], tool_result)
    followup = None
    if executed and trace.get("follow_up") and (inspection is None or inspection.action != "HOLD"):
        follow = trace["follow_up"]
        follow_tool = tools.get(follow["tool"])
        follow_decision = firewall.check_tool_call(session, follow["tool"], follow["args"])
        follow_executed = bool(follow_tool and (follow_decision.action is Action.ALLOW or
                                                (follow_decision.action is Action.ASK and approve)))
        if follow_executed:
            follow_result = follow_tool(**follow["args"])
            firewall.inspect_tool_output(session, follow["tool"], follow_result)
        followup = {"action": follow_decision.action.value, "executed": follow_executed,
                    "needs_day8_linking": bool(inspection and inspection.segment_ids and follow_executed)}
    if inspection is None or inspection.agent_view == tool_result:
        view_type = "original"
    elif inspection.action == "MASK":
        view_type = "masked"
    elif inspection.action == "HOLD":
        view_type = "withheld"
    elif "OUTPUT_OVERSIZE" in inspection.reason_codes:
        view_type = "truncated/marked"
    else:
        view_type = "marked"
    return {"action": decision.action.value, "executed": bool(executed and tool), "decision": decision,
            "inspection": inspection, "view_type": view_type, "tool_result": tool_result,
            "follow_up": followup}


def load_traces(path):
    import yaml
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))["traces"]
