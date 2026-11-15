"""Human approval objects; sensitive previews are intentionally hidden in repr/str."""
from __future__ import annotations
from threading import Thread
from queue import Queue, Empty
from dataclasses import dataclass, field
from typing import Any, Protocol

@dataclass(frozen=True, repr=False)
class ReviewPacket:
    request_id: str
    session_id: str
    tool: str
    reason_codes: tuple[str, ...]
    explanation: str
    link_evidence: tuple[dict, ...] = ()
    sensitivity_flags: tuple[str, ...] = ()
    values_preview: dict[str, str] = field(default_factory=dict, repr=False)
    def __repr__(self):
        return (f"ReviewPacket(request_id={self.request_id!r}, session_id={self.session_id!r}, "
                f"tool={self.tool!r}, reason_codes={self.reason_codes!r}, explanation={self.explanation!r}, "
                f"link_evidence={self.link_evidence!r}, sensitivity_flags={self.sensitivity_flags!r}, values_preview=<redacted>)")
    __str__ = __repr__

class ApprovalCallback(Protocol):
    def __call__(self, packet: ReviewPacket, timeout_seconds: float) -> bool: ...

def run_with_timeout(function, timeout_seconds):
    result_queue=Queue(maxsize=1)
    def invoke():
        try: result_queue.put(("result",function()))
        except BaseException: result_queue.put(("error",None))
    Thread(target=invoke,name="firewall-approval",daemon=True).start()
    try: kind,result=result_queue.get(timeout=timeout_seconds)
    except Empty: return "timeout",None
    return kind,result

def ask_with_timeout(callback, packet, timeout_seconds):
    kind,result=run_with_timeout(lambda:callback(packet,timeout_seconds),timeout_seconds)
    if kind=="timeout": return "timeout",None
    if kind!="result" or type(result) is not bool: return "error",None
    return ("approved" if result else "denied"),result
