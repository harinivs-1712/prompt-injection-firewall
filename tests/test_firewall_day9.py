from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
import socket
import threading
from contextlib import closing

import pytest

from firewall import Action, Firewall, ReasonCode
from firewall.approval import ReviewPacket
from firewall.audit import SQLiteAuditStore
from firewall.policy import PolicyError, policy_from_mapping
from firewall.protocols import InMemoryAuditSink
from harness.scanners import ScriptedScanner
from firewall.taskfit import MockTaskFitChecker
from harness.approvers import HangingApprover, RaisingApprover, ScriptedApprover
from harness.scanners import ScriptedScanner

@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs): raise AssertionError("network disabled")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)

def raw_policy(**extra):
    raw={"policy_version":"1","agent_name":"placeholder_agent","tools":{
        "read":{"description":"Read placeholder material.","risk":"low","side_effects":False,"output_sensitivity":"confidential","args":{"path":{"type":"path"}}},
        "send":{"description":"Send placeholder material.","risk":"high","side_effects":True,"args":{"destination":{"type":"recipient"},"body":{"type":"free_text"}},"egress":{"args":["body"],"destination_args":["destination"]}}},
        "limits":{"allowed_recipient_domains":["example.com","internal.example.com"],"internal_domains":["internal.example.com"],"allowed_recipients":["billing@example.com","inside@internal.example.com"]},
        "task_categories":{"work":{"allowed_tools":["send","read"],"keywords":["send","read"]}},
        "sensitivity":{"enabled":True,"action":"ask"}}
    raw.update(extra); return raw

@pytest.fixture
def hanging_approver(request):
    release=threading.Event()
    approver=HangingApprover(release)
    request.addfinalizer(release.set)
    return approver

def test_sensitivity_overlap_external_internal_and_any_taint():
    fw=Firewall(raw_policy(),scanner=ScriptedScanner(),linking_enabled=False)
    s=fw.start_session("read and send the notes")
    fw.inspect_tool_output(s,"read","Placeholder source phrase ACCT-000111 has enough useful words")
    ext=fw.check_tool_call(s,"send",{"destination":"billing@example.com","body":"Placeholder source phrase ACCT-000111 has enough useful words"})
    assert ext.action is Action.ASK and ReasonCode.CONFIDENTIAL_DATA_EXTERNAL in ext.reason_codes
    internal=fw.check_tool_call(s,"send",{"destination":"inside@internal.example.com","body":"Placeholder source phrase ACCT-000111 has enough useful words"})
    assert ReasonCode.CONFIDENTIAL_DATA_EXTERNAL not in internal.reason_codes
    raw=raw_policy(sensitivity={"enabled":True,"taint_mode":"any_confidential_in_session"})
    stricter=Firewall(raw,scanner=ScriptedScanner(),linking_enabled=False); ss=stricter.start_session("read and send")
    stricter.inspect_tool_output(ss,"read","One confidential value")
    assert ReasonCode.CONFIDENTIAL_DATA_EXTERNAL in stricter.check_tool_call(ss,"send",{"destination":"billing@example.com","body":"Unrelated short message"}).reason_codes

def test_fingerprints_store_hashes_only_and_r_sens_never_loosens():
    fw=Firewall(raw_policy(sensitivity={"enabled":True,"action":"block"}),scanner=ScriptedScanner(),linking_enabled=False)
    s=fw.start_session("read and send")
    secret="SECRET-TOKEN-0000"
    fw.inspect_tool_output(s,"read",secret)
    assert secret not in repr(s.confidential)
    result=fw.check_tool_call(s,"send",{"destination":"billing@example.com","body":secret})
    assert result.action is Action.BLOCK

def test_approval_outcomes_packet_safety_exact_scope_and_timeout(hanging_approver):
    secret="SECRET-TOKEN-0000"
    seen=[]
    def approver(packet, timeout): seen.append(packet); return True
    fw=Firewall(raw_policy(),scanner=ScriptedScanner(),approval_callback=approver,linking_enabled=False)
    s=fw.start_session("read and send")
    fw.inspect_tool_output(s,"read",secret)
    final=fw.authorize_tool_call(s,"send",{"destination":"billing@example.com","body":secret})
    assert final.action=="ALLOW" and ReasonCode.USER_APPROVED in final.reason_codes
    assert secret not in repr(seen[0]) and secret not in str(seen[0])
    assert seen[0].values_preview["body"].startswith(secret)
    assert fw.authorize_tool_call(s,"send",{"destination":"billing@example.com","body":secret+" additional text"}).action=="ALLOW"
    assert len(seen)==2 # changed arguments require a separate approval decision
    timeout_policy=raw_policy(approval={"timeout_seconds":0.03})
    timed=Firewall(timeout_policy,scanner=ScriptedScanner(),approval_callback=hanging_approver,linking_enabled=False)
    ts=timed.start_session("read and send"); timed.inspect_tool_output(ts,"read",secret)
    denied=timed.authorize_tool_call(ts,"send",{"destination":"billing@example.com","body":secret})
    assert denied.action=="DENIED" and ReasonCode.APPROVAL_TIMEOUT in denied.reason_codes
    broken=Firewall(raw_policy(),scanner=ScriptedScanner(),approval_callback=RaisingApprover(),linking_enabled=False)
    bs=broken.start_session("read and send"); broken.inspect_tool_output(bs,"read",secret)
    assert ReasonCode.APPROVAL_CALLBACK_ERROR in broken.authorize_tool_call(bs,"send",{"destination":"billing@example.com","body":secret}).reason_codes

def test_no_approver_denies_block_never_calls_approver_and_preview_is_truncated():
    fw=Firewall(raw_policy(approval={"preview_max_chars":4}),scanner=ScriptedScanner(),linking_enabled=False)
    s=fw.start_session("read and send"); fw.inspect_tool_output(s,"read","Private phrase ACCT-000111 with enough words")
    denied=fw.authorize_tool_call(s,"send",{"destination":"billing@example.com","body":"Private phrase ACCT-000111 with enough words"})
    assert denied.action=="DENIED" and ReasonCode.NO_APPROVER in denied.reason_codes
    calls=[]
    blocked=Firewall(raw_policy(),scanner=ScriptedScanner(),approval_callback=lambda *a:calls.append(a) or True,linking_enabled=False)
    bs=blocked.start_session("send"); result=blocked.authorize_tool_call(bs,"send",{})
    assert result.action=="BLOCK" and not calls

def test_sqlite_audit_chain_redaction_whitelist_and_queries(tmp_path):
    db=tmp_path/"audit.sqlite"; store=SQLiteAuditStore(db)
    fw=Firewall(raw_policy(),scanner=ScriptedScanner(),audit_sink=store,linking_enabled=False)
    secret="SECRET-TOKEN-0000"; s=fw.start_session("send placeholder task")
    fw.inspect_tool_output(s,"read",secret)
    fw.authorize_tool_call(s,"send",{"destination":"billing@example.com","body":secret})
    assert store.verify_chain()==(True,None)
    assert store.list_events(session_id=s.session_id)
    assert store.session_summary(s.session_id)["session_id"]==s.session_id
    assert store.stats()["events"]>=1
    assert store.rejected_events==0
    store.record({"event_type":"tool_check","secret":secret})
    assert store.rejected_events==1
    assert store.verify_chain()==(True,None)
    content=b"".join(p.read_bytes() for p in tmp_path.glob("audit.sqlite*"))
    assert secret.encode() not in content
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda _:store.record({"event_type":"tool_check","session_id":s.session_id,"tool":"send","action":"allow","reason_codes":["ALL_RULES_PASSED"]}), range(12)))
    assert store.verify_chain()==(True,None)

def test_loop_guard_halts_resumes_and_requires_reviewer():
    raw=raw_policy(loop_guard={"max_denied_same_call":2,"max_blocked_per_tool":3,"max_blocked_per_session":8})
    fw=Firewall(raw,scanner=ScriptedScanner(),approval_callback=ScriptedApprover(approve=False),linking_enabled=False)
    s=fw.start_session("read and send"); fw.inspect_tool_output(s,"read","Private phrase ACCT-000111 with enough words")
    args={"destination":"billing@example.com","body":"Private phrase ACCT-000111 with enough words"}
    assert fw.authorize_tool_call(s,"send",args).action=="DENIED"
    second=fw.authorize_tool_call(s,"send",args)
    assert s.halted and ReasonCode.RETRY_LIMIT_REACHED in second.reason_codes
    assert ReasonCode.SESSION_HALTED in fw.authorize_tool_call(s,"send",args).reason_codes
    with pytest.raises(PermissionError): fw.resume_session(s,reviewer=False)
    fw.resume_session(s,reviewer=True); assert not s.halted

def test_task_fit_only_receives_trusted_metadata_and_only_tightens():
    checker=MockTaskFitChecker("does_not_fit")
    fw=Firewall(raw_policy(),task_fit_checker=checker,linking_enabled=False)
    s=fw.start_session("send this placeholder")
    decision=fw.check_tool_call(s,"send",{"destination":"billing@example.com","body":"SECRET-TOKEN-0000"})
    assert ReasonCode.TASK_FIT_DOUBTFUL in decision.reason_codes
    assert checker.calls[0][1:]==("send","Send placeholder material.",{"destination":"recipient","body":"free_text"})

def test_policy_egress_names_validate_and_same_policy_engine_runs_examples():
    raw=raw_policy(); raw["tools"]["send"]["egress"]["args"]=["unknown"]
    with pytest.raises(PolicyError,match=r"tools.send.egress.args"): policy_from_mapping(raw)
    for path in ("policies/example_agent.yaml","policies/example_files_agent.yaml","policies/example_support_agent.yaml"):
        assert policy_from_mapping(__import__("yaml").safe_load(Path(path).read_text(encoding="utf-8"))).tools

def test_inspect_output_passes_explicit_original_id_and_trusted_context_note():
    class SpyScanner:
        def __init__(self): self.calls=[]
        def scan(self, content, *, doc_id, source_type, user_task, context_note=None, max_judge_calls=None):
            self.calls.append((doc_id,user_task,context_note))
            return ScriptedScanner().scan(content,doc_id=doc_id,source_type=source_type,user_task=user_task,
                                           context_note=context_note,max_judge_calls=max_judge_calls)
    scanner=SpyScanner(); fw=Firewall("policies/example_output_agent.yaml",scanner=scanner)
    session=fw.start_session("trusted task")
    fw.inspect_tool_output(session,"inspect_text","A short placeholder output.",doc_id="original-doc",
                           context_note="trusted source context")
    assert scanner.calls==[("original-doc","trusted task","trusted source context")]

def test_sqlite_is_append_only_and_hash_chain_detects_edit_in_copy(tmp_path):
    import shutil, sqlite3
    source=tmp_path/"source.sqlite"; store=SQLiteAuditStore(source)
    store.record({"event_type":"tool_check","session_id":"session-01","tool":"send","action":"allow","reason_codes":["ALL_RULES_PASSED"]})
    assert store.verify_chain()==(True,None)
    assert not hasattr(store,"update_event") and not hasattr(store,"delete_event")
    with closing(sqlite3.connect(source)) as db:
        with db:
            with pytest.raises(sqlite3.DatabaseError): db.execute("UPDATE audit_events SET action='block' WHERE id=1")
    copy=tmp_path/"copy.sqlite"; shutil.copy2(source,copy)
    with closing(sqlite3.connect(copy)) as db:
        with db:
            db.execute("DROP TRIGGER audit_events_append_only_update")
            db.execute("UPDATE audit_events SET action='block' WHERE id=1")
    assert SQLiteAuditStore(copy).verify_chain()==(False,1)

def test_sqlite_store_closes_cleanly_under_path_with_spaces(tmp_path):
    import shutil
    folder=tmp_path/"folder with spaces"; folder.mkdir()
    db_path=folder/"audit log.sqlite"
    with SQLiteAuditStore(db_path) as store:
        store.record({"event_type":"tool_check","session_id":"session-02","tool":"send","action":"allow","reason_codes":["ALL_RULES_PASSED"]})
        assert store.verify_chain()==(True,None)
    assert store._closed
    shutil.rmtree(folder)
    assert not folder.exists()

def test_preview_is_control_sanitized_and_capped_and_bad_approval_denies():
    seen=[]
    def capture(packet, timeout): seen.append(packet); return "yes"
    raw=raw_policy(approval={"preview_max_chars":5})
    fw=Firewall(raw,scanner=ScriptedScanner(),approval_callback=capture,linking_enabled=False)
    s=fw.start_session("read and send"); fw.inspect_tool_output(s,"read","Source phrase ACCT-000111 with enough useful words")
    outcome=fw.authorize_tool_call(s,"send",{"destination":"billing@example.com","body":"Source phrase ACCT-000111 with enough useful words\nsecret"})
    assert outcome.action=="DENIED" and ReasonCode.APPROVAL_CALLBACK_ERROR in outcome.reason_codes
    assert len(seen[0].values_preview["body"])<=5 and "\n" not in seen[0].values_preview["body"]

def test_loop_guard_per_tool_and_halt_callback_once():
    calls=[]
    raw=raw_policy(loop_guard={"max_blocked_per_tool":3,"max_blocked_per_session":8,"max_denied_same_call":8})
    fw=Firewall(raw,approval_callback=ScriptedApprover(),on_halt=lambda *args:calls.append(args),linking_enabled=False)
    s=fw.start_session("send placeholder")
    for _ in range(3): result=fw.authorize_tool_call(s,"send",{"destination":"bad","body":"x"})
    assert s.halted and ReasonCode.RETRY_LIMIT_REACHED in result.reason_codes and len(calls)==1
    fw.authorize_tool_call(s,"send",{"destination":"bad","body":"x"})
    assert len(calls)==1

def test_sensitivity_thresholds_unicode_variants_unparseable_and_scope_external():
    source="amber cobalt silver violet orange purple yellow green"
    raw=raw_policy(sensitivity={"enabled":True,"min_overlap_shingles":2,"shingle_size":5})
    fw=Firewall(raw,scanner=ScriptedScanner(),linking_enabled=False); s=fw.start_session("read and send")
    fw.inspect_tool_output(s,"read",source)
    call={"destination":"billing@example.com","body":"amber cobalt silver violet orange"}
    assert ReasonCode.CONFIDENTIAL_DATA_EXTERNAL not in fw.check_tool_call(s,"send",call).reason_codes
    raw=raw_policy(sensitivity={"enabled":True,"min_overlap_shingles":1,"shingle_size":5})
    fw=Firewall(raw,scanner=ScriptedScanner(),linking_enabled=False); s=fw.start_session("read and send")
    fw.inspect_tool_output(s,"read",source)
    call["body"]="ＡＭＢＥＲ   cobalt silver violet orange"
    assert ReasonCode.CONFIDENTIAL_DATA_EXTERNAL in fw.check_tool_call(s,"send",call).reason_codes
    raw=raw_policy(); raw["tools"]["send"]["args"]["destination"]["type"]="free_text"
    fw=Firewall(raw,scanner=ScriptedScanner(),linking_enabled=False); s=fw.start_session("read and send")
    fw.inspect_tool_output(s,"read",source)
    assert ReasonCode.CONFIDENTIAL_DATA_EXTERNAL in fw.check_tool_call(s,"send",{"destination":"not a parseable destination","body":source}).reason_codes
    raw=raw_policy(); raw["tools"]["send"]["egress"]["scope"]="external"
    fw=Firewall(raw,scanner=ScriptedScanner(),linking_enabled=False); s=fw.start_session("read and send")
    fw.inspect_tool_output(s,"read",source)
    assert ReasonCode.CONFIDENTIAL_DATA_EXTERNAL in fw.check_tool_call(s,"send",{"destination":"inside@internal.example.com","body":source}).reason_codes

def test_sensitive_rule_does_not_weaken_other_block_and_unconfigured_tool_is_not_egress():
    raw=raw_policy(sensitivity={"enabled":True,"taint_mode":"any_confidential_in_session"})
    fw=Firewall(raw,scanner=ScriptedScanner(),linking_enabled=False); s=fw.start_session("read and send")
    fw.inspect_tool_output(s,"read","Confidential source words available here")
    blocked=fw.check_tool_call(s,"send",{"destination":"billing@example.com","body":"Confidential source words available here","unexpected":"x"})
    assert blocked.action is Action.BLOCK
    assert ReasonCode.CONFIDENTIAL_DATA_EXTERNAL not in fw.check_tool_call(s,"read",{"path":"/safe/path"}).reason_codes

def test_task_fit_unknown_exception_timeout_do_not_change_decision():
    import time
    class Checker:
        def __init__(self, result): self.result=result
        def check(self, *args):
            if self.result=="error": raise RuntimeError("private placeholder")
            if self.result=="slow": time.sleep(1.1)
            return self.result
    baseline=Firewall(raw_policy(),linking_enabled=False).check_tool_call(Firewall(raw_policy(),linking_enabled=False).start_session("send"),"send",{"destination":"billing@example.com","body":"ordinary note"})
    for result in ("unknown","error","slow"):
        fw=Firewall(raw_policy(),task_fit_checker=Checker(result),linking_enabled=False)
        s=fw.start_session("send")
        decision=fw.check_tool_call(s,"send",{"destination":"billing@example.com","body":"ordinary note"})
        assert decision.action==baseline.action and ReasonCode.TASK_FIT_DOUBTFUL not in decision.reason_codes

def test_audit_sink_failure_fails_closed():
    class FailingSink:
        def record(self,event):
            if event.get("event_type")!="session_started": raise OSError("audit down")
    fw=Firewall(raw_policy(),audit_sink=FailingSink(),linking_enabled=False)
    s=fw.start_session("send placeholder")
    decision=fw.check_tool_call(s,"send",{"destination":"billing@example.com","body":"ordinary note"})
    assert decision.action is Action.BLOCK and ReasonCode.AUDIT_UNAVAILABLE in decision.reason_codes

