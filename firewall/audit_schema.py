"""Strict metadata-only audit event validator shared by the sink implementations."""
import re

EVENT_TYPES={"session_started","tool_check","tool_authorized","approval_requested","approval_outcome","output_inspected","tool_output_inspection","loop_guard_triggered","session_halted","session_resumed","audit_event_rejected"}
FIELDS={"event","event_type","tool_name","tool","action","output_id","reason_codes","rule_ids","argument_names","user_provided_args","session_id","max_level","level_counts","segment_ids","unreviewed_segment_ids","unscanned_chars","judge_calls_made","link_level","evidence","approval_outcome","counts","request_id","task_length","user_task_sha256","policy_version","agent_name","sensitivity_flags"}
def _safe_name(x): return isinstance(x,str) and (x=="<invalid>" or bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}",x)))
def _safe_codes(v, pattern): return isinstance(v,(list,tuple)) and all(isinstance(x,str) and re.fullmatch(pattern,x) for x in v)
def validate_event(event):
    if not isinstance(event,dict) or set(event)-FIELDS: return False
    for value in event.values():
        if isinstance(value,str) and len(value)>200: return False
    et=event.get("event_type",event.get("event","tool_check"))
    if et not in EVENT_TYPES: return False
    for key in ("tool","tool_name","agent_name","policy_version","output_id","session_id","request_id"):
        if key in event and event[key] is not None and not _safe_name(event[key]): return False
    if "action" in event and event["action"] not in {"allow","ask","block","denied","pass","mask","hold","ALLOW","BLOCK","DENIED","PASS","MASK","HOLD"}: return False
    for key in ("reason_codes","sensitivity_flags"):
        if key in event and not _safe_codes(event[key],r"[A-Z][A-Z0-9_]{0,63}"): return False
    if "rule_ids" in event and not _safe_codes(event["rule_ids"],r"[A-Z][A-Z0-9_-]{0,63}"): return False
    for key in ("argument_names","user_provided_args"):
        if key in event and not _safe_codes(event[key],r"[A-Za-z][A-Za-z0-9_]{0,80}"): return False
    for key in ("segment_ids","unreviewed_segment_ids"):
        if key in event and not _safe_codes(event[key],r"[A-Za-z0-9_.:-]{1,160}"): return False
    if "link_level" in event and event["link_level"] not in {"NONE","POSSIBLE","LIKELY","CONFIRMED",None}: return False
    if "max_level" in event and event["max_level"] not in {"none","low","medium","high","needs_review",None}: return False
    for key in ("task_length","unscanned_chars","judge_calls_made"):
        if key in event and (type(event[key]) is not int or event[key]<0): return False
    for key in ("level_counts","counts"):
        if key in event and (not isinstance(event[key],dict) or any(not _safe_name(k) or type(v) is not int or v<0 for k,v in event[key].items())): return False
    if "user_task_sha256" in event and not re.fullmatch(r"[0-9a-f]{64}",str(event["user_task_sha256"])): return False
    if "evidence" in event:
        if not isinstance(event["evidence"],(list,tuple)): return False
        for e in event["evidence"]:
            if not isinstance(e,dict) or set(e)-{"kind","arg_name","segment_id","segment_level","match_type","score","user_provided"}: return False
            for k in ("kind","arg_name","segment_id","segment_level","match_type"):
                if k in e and not _safe_name(e[k]): return False
            if "score" in e and (isinstance(e["score"],bool) or not isinstance(e["score"],(int,float))): return False
            if "user_provided" in e and type(e["user_provided"]) is not bool: return False
    return True
