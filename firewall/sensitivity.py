"""Value-free fingerprints and deterministic egress sensitivity checks."""
from __future__ import annotations
import hashlib
import re
import unicodedata
from firewall.cleaning import domain_of, is_domain_allowed, normalize_text
from firewall.decision import Action, Decision, ReasonCode

TOKEN_RE = re.compile(r"[A-Za-z0-9.+_-]+@[A-Za-z0-9.-]+|(?<!\w)[A-Z]{2,}[A-Z0-9_-]{4,}(?!\w)|(?<!\w)\d{4,}(?!\w)")

def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def fingerprints(text: str, *, shingle_size: int, min_token_len: int) -> dict[str, set[str]]:
    normalized = normalize_text(text) or ""
    words = re.findall(r"[^\W_]+", unicodedata.normalize("NFKC", normalized).casefold(), re.UNICODE)
    shingles = { _digest(" ".join(words[i:i+shingle_size])) for i in range(max(0, len(words)-shingle_size+1)) }
    tokens = set()
    for item in TOKEN_RE.findall(unicodedata.normalize("NFKC", text)):
        norm = normalize_text(item) or ""
        if len(norm) >= min_token_len:
            tokens.add(_digest(norm))
    return {"shingles": shingles, "tokens": tokens}

def add_confidential(session, text: str, config) -> None:
    if not isinstance(text, str) or not text:
        return
    session.confidential_output_seen = True
    fp = fingerprints(text, shingle_size=config.shingle_size, min_token_len=config.min_token_len)
    session.confidential["shingles"].update(fp["shingles"])
    session.confidential["tokens"].update(fp["tokens"])

def _external(firewall, tool, args) -> bool:
    egress = tool.egress
    if egress.get("scope", "by_destination") == "external":
        return True
    destinations = [args[n] for n in egress.get("destination_args", ()) if n in args]
    if not destinations:
        return True
    allowed = firewall.policy.limits.internal_domains
    for value in destinations:
        domain = domain_of(value)
        if domain is None or not is_domain_allowed(domain, allowed):
            return True
    return False

def check_sensitivity(firewall, session, tool_name, args):
    cfg = firewall.policy.sensitivity
    tool = firewall.policy.get_tool(tool_name)
    if not cfg.enabled or tool is None or not tool.egress or not _external(firewall, tool, args):
        return None
    egress_text = " ".join(str(args[name]) for name in tool.egress.get("args", ()) if name in args)
    candidate = fingerprints(egress_text, shingle_size=cfg.shingle_size, min_token_len=cfg.min_token_len)
    overlap = len(candidate["shingles"] & session.confidential["shingles"])
    token_match = bool(candidate["tokens"] & session.confidential["tokens"])
    triggered = session.confidential_output_seen if cfg.taint_mode == "any_confidential_in_session" else (overlap >= cfg.min_overlap_shingles or token_match)
    if not triggered:
        return None
    return Decision(Action(cfg.action), (ReasonCode.CONFIDENTIAL_DATA_EXTERNAL,),
                    "Confidential content may be leaving the system.", rule_id="R-SENS",
                    details={"sensitivity": "confidential_external", "shingle_overlap": min(overlap, 1000), "token_match": token_match})
