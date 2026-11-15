"""Generate offline Day 9 metrics from scripted placeholder traces."""
from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory
from harness.day9_runner import MODES, load_day9_traces, run_day9_trace

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/"data"/"results"/"layer2_day9_results.md"
LABELS={"no_defense":"No defense","hard_link":"Hard rules + linking (R-SENS off)","full_deny":"Full firewall + deny asks","full_approve":"Full firewall + approve asks"}
def main():
    traces=load_day9_traces(); stats=defaultdict(lambda:{"attack_n":0,"attack_run":0,"normal_n":0,"normal_run":0,"asks":0,"blocks":0,"halts":0,"normal_prompts":0,"all_prompts":0,"audit_ok":0,"audit_runs":0,"audit_rejections":0})
    rows=[]; gaps=[]
    with TemporaryDirectory(prefix="layer2-day9-") as temp:
        for i,t in enumerate(traces):
            for mode in MODES:
                result=run_day9_trace(t,ROOT/"policies"/(t["policy"]+".yaml"),Path(temp)/f"{i}-{mode}",mode=mode)
                s=stats[mode]; attack=t["attack"]
                if attack: s["attack_n"]+=1; s["attack_run"]+=int(result["harmful"])
                else:
                    s["normal_n"]+=1; s["normal_run"]+=int(result["executed"])
                    s["asks"]+=int(result["action"] in {"ask","denied"}); s["blocks"]+=int(result["action"]=="block")
                s["all_prompts"]+=result["approvals"]
                if not attack: s["normal_prompts"]+=result["approvals"]
                s["halts"]+=int(any(x=="RETRY_LIMIT_REACHED" for x in result["reason_codes"]))
                if result["audit_chain_ok"] is not None:
                    s["audit_runs"]+=1; s["audit_ok"]+=int(result["audit_chain_ok"]); s["audit_rejections"]+=result["audit_rejections"]
                rows.append(f"| {t['name']} | {LABELS[mode]} | {result['action']} | {str(result['executed']).lower()} | {', '.join(result['reason_codes']) or '-'} | {result['approvals']} |")
                if t.get("known_gap") and mode=="full_deny" and result["executed"]: gaps.append(t["name"])
    text="# Layer 2 Day 9: egress, approval, audit, and loop guard results\n\n"
    text+="Offline scripted placeholder traces only; fake tools have no real side effects. No network or API calls were made.\n\n"
    text+="| Trace | Setting | Decision | Executed | Reason codes | Approval prompts |\n|---|---|---|---:|---|---:|\n"+"\n".join(rows)+"\n\n"
    text+="## Summary metrics\n\n| Setting | Attack success | Normal tasks completed | False asks/blocks | Approval prompts on normal calls | Halts | Audit chains valid | Rejected audit events |\n|---|---:|---:|---:|---:|---:|---:|---:|\n"
    for mode in MODES:
        s=stats[mode]; false=f"{s['asks']} asks, {s['blocks']} blocks / {s['normal_n']} normal traces"
        text+=f"| {LABELS[mode]} | {s['attack_run']}/{s['attack_n']} | {s['normal_run']}/{s['normal_n']} | {false} | {s['normal_prompts']} / {s['normal_n']} normal traces ({s['all_prompts']} total) | {s['halts']} | {s['audit_ok']}/{s['audit_runs']} | {s['audit_rejections']} |\n"
    text+="\n## Known gaps\n\n"
    text+="- Overlap matching does not recognize paraphrases. The any-confidential-in-session mode catches a call after confidential output even without matching words, but may ask about unrelated external sends.\n"
    text+="- Missed attack examples under the full firewall with deny asks: "+(", ".join(gaps) if gaps else "none in these scripted traces")+". These are scenario-specific gaps, not a general miss-rate estimate.\n"
    text+="- Sensitivity coverage depends on policy authors marking the right tool outputs confidential and declaring all egress arguments.\n"
    text+="- An approve-everything reviewer defeats ASK protections. The preview intentionally contains values in memory; the approval UI must be trusted and must not log it.\n"
    text+="- Timeouts and callback failures deny. Audit hashes detect row edits but not deletion of the entire database. Investigations still need evidence outside this metadata-only log. A halted session blocks all calls until reviewer resume.\n"
    OUTPUT.parent.mkdir(parents=True,exist_ok=True); OUTPUT.write_text(text,encoding="utf-8"); print(f"Wrote {OUTPUT}")
if __name__=="__main__": main()
