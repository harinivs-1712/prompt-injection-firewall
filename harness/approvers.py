"""Deterministic and interactive approval callbacks for the local harness."""
from threading import Event

class ScriptedApprover:
    def __init__(self, *, approve=False, by_reason=None):
        self.approve=bool(approve); self.by_reason=dict(by_reason or {}); self.packets=[]
    def __call__(self, packet, timeout_seconds):
        self.packets.append(packet)
        for reason in packet.reason_codes:
            if reason in self.by_reason: return bool(self.by_reason[reason])
        return self.approve

class HangingApprover:
    def __init__(self, release_event=None): self.release_event=release_event or Event()
    def __call__(self, packet, timeout_seconds):
        self.release_event.wait()
        return True

class RaisingApprover:
    def __call__(self, packet, timeout_seconds): raise RuntimeError("placeholder approval failure")
