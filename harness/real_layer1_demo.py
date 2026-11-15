"""Offline-only adapter regression and tool-flow report using held-out cached documents."""
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DOC_IDS=(
    "hard_single_disguised_note_01",
    "hard_single_concealment_01",
    "hard_single_statement_style_01",
    "hard_single_unusual_verbs_01",
    "hard_control_ordinary_01",
    "hard_control_ordinary_02",
    "hard_control_benign_instruction_like_01",
    "hard_control_benign_instruction_like_02",
)

def _counts(session):
    result=Counter(item["record"].suspicion_level for item in session.segments)
    return {level:result[level] for level in ("none","low","medium","high","needs_review")}

def _load():
    tasks=json.loads((ROOT/"config"/"tasks.json").read_text(encoding="utf-8"))
    labels=json.loads((ROOT/"data"/"hard_eval"/"labels.json").read_text(encoding="utf-8"))
    docs={item["doc_id"]:item for item in labels["documents"]}
    saved_all=json.loads((ROOT/"data"/"results"/"hard_eval_segments_leveled_all.json").read_text(encoding="utf-8"))
    saved_cascade=json.loads((ROOT/"data"/"results"/"hard_eval_segments_leveled_cascade.json").read_text(encoding="utf-8"))
    return tasks,docs,saved_all,saved_cascade

def run():
    os.environ["HF_HUB_OFFLINE"]="1"
    os.environ["TRANSFORMERS_OFFLINE"]="1"
    os.environ.pop("GEMINI_API_KEY",None)
    from firewall import Action, Firewall
    from firewall.adapters.layer1 import Layer1Scanner

    tasks,labels,saved_all,saved_cascade=_load()
    saved={"all":saved_all,"cascade":saved_cascade}
    entries=[]; sessions={}
    for mode in ("all","cascade"):
        firewall=Firewall(ROOT/"policies"/"example_output_agent.yaml",
                          scanner=Layer1Scanner(mode=mode,offline_cache_only=True,legacy_cache=True))
        for doc_id in DOC_IDS:
            content=(ROOT/"data"/"hard_eval"/f"{doc_id}.txt").read_text(encoding="utf-8")
            metadata=tasks[doc_id]
            session=firewall.start_session(metadata["user_task"])
            output=firewall.inspect_tool_output(session,"inspect_text",content,doc_id=doc_id,
                                                context_note=metadata["context_note"])
            if "OUTPUT_SCAN_FAILED" in output.reason_codes:
                raise RuntimeError("Offline Layer 1 scan failed; check cached model availability.")
            records=[item["record"] for item in session.segments]
            saved_rows=[row for row in saved[mode] if row.get("doc_id")==doc_id]
            saved_levels={row["segment_id"]:row["suspicion_level"] for row in saved_rows}
            actual_levels={record.segment_id:record.suspicion_level for record in records}
            reviewed=sum(record.judge_ran for record in records)
            entries.append({"doc_id":doc_id,"category":labels[doc_id]["category"],"mode":mode,
                "segments":len(records),"levels":_counts(session),"reviewed":reviewed,
                "unreviewed":len(records)-reviewed,"action":output.action,
                "matches":actual_levels==saved_levels})
            sessions[(mode,doc_id)]=(firewall,session,output)

    attack_fw,attack_session,attack_output=sessions[("all","hard_single_disguised_note_01")]
    high=next((item["record"] for item in attack_session.segments if item["record"].suspicion_level=="high"),None)
    if high is None or attack_output.action!="HOLD" or high.text in str(attack_output.agent_view):
        raise RuntimeError("Attack integration precondition failed: no HIGH segment held from the agent view.")
    from firewall import load_policy
    attacker=Firewall(load_policy(ROOT/"policies"/"example_agent.yaml"),
                      scanner=Layer1Scanner(mode="all",offline_cache_only=True,legacy_cache=True))
    attack_session.allowed_tools=frozenset({"send_email"})
    blocked=attacker.authorize_tool_call(attack_session,"send_email",{
        "to":"billing@example.com","subject":"Review","body":high.text})
    attack_link=(blocked.action=="BLOCK" and any(code.value.startswith("ARG_MATCHES_HIGH") for code in blocked.reason_codes))
    if not attack_link:
        raise RuntimeError("The copied value was not blocked through R-LINK.")

    _,control_session,control_output=sessions[("all","hard_control_ordinary_01")]
    clean=Firewall(load_policy(ROOT/"policies"/"example_agent.yaml"),
                   scanner=Layer1Scanner(mode="all",offline_cache_only=True,legacy_cache=True))
    control_session.allowed_tools=frozenset({"read_email"})
    normal=clean.authorize_tool_call(control_session,"read_email",{"email_id":"message-0001"})
    normal_allowed=normal.action=="ALLOW"
    if not normal_allowed:
        raise RuntimeError("Normal control trace was not permitted.")

    rows=[]
    for item in entries:
        lev=item["levels"]
        level_text=", ".join(f"{name}:{lev[name]}" for name in lev)
        rows.append(f"| {item['doc_id']} | {item['category']} | {item['mode']} | {item['segments']} | {level_text} | {item['reviewed']}/{item['segments']} ({item['unreviewed']} unreviewed) | {item['action']} | {'yes' if item['matches'] else 'no'} |")
    report="# Offline Layer 1 integration report\n\n"
    report+="Local-only cache regression through `Firewall.inspect_tool_output`; HF Hub and Transformers offline mode were enabled, Gemini key was removed from this process, and no API calls were made. The eight documents (four attack examples, four controls) were read-only.\n\n"
    report+="| Original doc_id | Dataset category | Mode | Segments | Suspicion levels | Judge coverage | Output action | Matches saved result |\n|---|---|---|---:|---|---|---|---|\n"+"\n".join(rows)+"\n\n"
    report+="## Flow checks\n\n"
    report+=f"- Attack document `hard_single_disguised_note_01`: output action `{attack_output.action}`; HIGH content was withheld from the agent view; a scripted call copied from that flagged segment was `{blocked.action}` through R-LINK (`{'PASS' if attack_link else 'FAIL'}`).\n"
    report+=f"- Control document `hard_control_ordinary_01`: output action `{control_output.action}`; low-risk scripted read call `{normal.action}` (`{'PASS' if normal_allowed else 'FAIL'}`).\n"
    report+="- Judge cache misses remain marked unreviewed by Layer 1 in offline mode; no judge calls are attempted without a cache hit.\n\n"
    report+="## All-mode versus cascade\n\n"
    for doc_id in DOC_IDS:
        all_row=next(row for row in entries if row["doc_id"]==doc_id and row["mode"]=="all")
        cascade_row=next(row for row in entries if row["doc_id"]==doc_id and row["mode"]=="cascade")
        report+=f"- `{doc_id}`: all {all_row['action']} with {all_row['unreviewed']} unreviewed; cascade {cascade_row['action']} with {cascade_row['unreviewed']} unreviewed; actions differ: {'yes' if all_row['action']!=cascade_row['action'] else 'no'}.\n"
    path=ROOT/"data"/"results"/"layer1_integration_report.md"
    path.write_text(report,encoding="utf-8")
    print(f"Wrote {path}")
    print(f"Layer 1 flow checks passed; all-level matches: {sum(x['matches'] for x in entries if x['mode']=='all')}/8; cascade-level matches: {sum(x['matches'] for x in entries if x['mode']=='cascade')}/8")

def main(): run()
if __name__=="__main__": main()
