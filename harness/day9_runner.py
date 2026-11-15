"""Offline, deterministic Day 9 scenario execution."""
from copy import deepcopy
from pathlib import Path
import yaml
from firewall import Action, Firewall
from firewall.policy import load_policy
from firewall.audit import SQLiteAuditStore
from harness.approvers import ScriptedApprover
from harness.fake_tools import build_tools
from harness.scanners import ScriptedScanner

MODES=("no_defense","hard_link","full_deny","full_approve")
def run_day9_trace(trace, policy_path, temp_dir, *, mode):
    policy=load_policy(policy_path)
    raw=yaml.safe_load(Path(policy_path).read_text(encoding="utf-8"))
    if mode in {"hard_link","no_defense"}:
        raw["sensitivity"]={**raw.get("sensitivity",{}),"enabled":False}
    elif trace.get("mode")=="any_confidential_in_session":
        raw["sensitivity"]["taint_mode"]="any_confidential_in_session"
    tools=build_tools(policy,temp_dir)
    if mode=="no_defense":
        first=trace["output"]
        executed=trace["tool"] in tools
        if executed: tools[trace["tool"]](**trace["args"])
        return {"action":"allow","executed":executed,"harmful":bool(trace["attack"] and executed),"approvals":0,"reason_codes":(),"audit_chain_ok":None,"audit_rejections":0}
    approver=ScriptedApprover(approve=(mode=="full_approve")) if mode in {"full_deny","full_approve"} else None
    Path(temp_dir).mkdir(parents=True,exist_ok=True)
    sink=SQLiteAuditStore(Path(temp_dir)/"audit.sqlite")
    fw=Firewall(raw,scanner=ScriptedScanner(),approval_callback=approver,audit_sink=sink)
    session=fw.start_session(trace["task"])
    fw.inspect_tool_output(session,trace["output_tool"],trace["output"])
    if mode=="hard_link":
        decision=fw.check_tool_call(session,trace["tool"],trace["args"])
        action=decision.action.value
        execute=decision.action is Action.ALLOW
        codes=tuple(c.value for c in decision.reason_codes)
    else:
        final=fw.authorize_tool_call(session,trace["tool"],trace["args"])
        action=final.action.lower(); execute=final.action=="ALLOW"
        codes=tuple(c.value for c in final.reason_codes)
    if execute and trace["tool"] in tools:
        result=tools[trace["tool"]](**trace["args"])
        fw.inspect_tool_output(session,trace["tool"],result)
    return {"action":action,"executed":bool(execute),"harmful":bool(trace["attack"] and execute),
            "approvals":session.approval_count,"reason_codes":codes,"session":session,
            "audit_chain_ok":sink.verify_chain()[0],"audit_rejections":sink.rejected_events}

def load_day9_traces():
    path=Path(__file__).resolve().parent/"scenarios"/"day9_traces.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))["traces"]
