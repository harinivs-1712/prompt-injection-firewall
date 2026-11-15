"""Run scripted provenance traces in no-defense, hard-only, and linked modes."""
from pathlib import Path

from firewall import Action, Firewall, load_policy
from harness.fake_tools import build_tools
from harness.scanners import ScriptedScanner


def run_day8_trace(trace, policy_path, temp_dir, *, mode="linked_deny"):
    policy = load_policy(policy_path)
    tools = build_tools(policy, temp_dir)
    if mode == "no_defense":
        firewall = None
        session = None
    else:
        firewall = Firewall(policy, scanner=ScriptedScanner(), linking_enabled=(mode != "hard_only"))
        session = firewall.start_session(trace["user_task"])
        for index, item in enumerate(trace.get("initial_content", ())):
            firewall.scan_content(session, item["text"], item.get("source_type", "document"),
                                 doc_id=item.get("doc_id", f"trace-content-{index}"))

    steps = []
    for index, call in enumerate(trace["calls"]):
        tool = call["tool"]
        fake = tools.get(tool)
        if firewall is None:
            decision_action, link_level, reason_codes, evidence = "allow", "NONE", (), ()
            execute = fake is not None
        else:
            decision = firewall.check_tool_call(session, tool, call["args"])
            decision_action = decision.action.value
            report = session.last_link_report
            link_level = report.link_level if report else "NONE"
            reason_codes = tuple(code.value for code in decision.reason_codes)
            evidence = tuple({"kind": item.kind, "arg_name": item.arg_name,
                              "segment_id": item.segment_id, "segment_level": item.segment_level,
                              "match_type": item.match_type, "score": round(item.score, 4)}
                             for item in (report.evidence if report else ()))
            approve = mode == "linked_approve"
            execute = fake is not None and (decision.action is Action.ALLOW or
                                             (decision.action is Action.ASK and approve))
        if execute:
            tool_result = fake(**call["args"])
            if "tool_output" in call:
                tool_result = call["tool_output"]
            if firewall is not None:
                firewall.inspect_tool_output(session, tool, tool_result)
        else:
            tool_result = None
        steps.append({"index": index, "tool": tool, "decision": decision_action,
                      "link_level": link_level, "reason_codes": reason_codes,
                      "evidence": evidence, "executed": bool(execute),
                      "harmful": bool(call.get("harmful", False)),
                      "harmful_executed": bool(execute and call.get("harmful", False))})
    return {"steps": steps, "session": session}
