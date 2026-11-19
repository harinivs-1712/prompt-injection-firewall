"""Convenience construction for a policy firewall with optional Layer 1 scanning."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from firewall.adapters.layer1 import Layer1Scanner
from firewall.api import Firewall
from firewall.protocols import AuditSink, ApprovalCallback, Scanner


def create_default_firewall(policy_path: str | Path, *, scanner: Scanner | None = None,
                            mode: str = "all", offline_cache_only: bool = True, judge: Any = None,
                            approval_callback: ApprovalCallback | None = None,
                            audit_sink: AuditSink | None = None, linking_enabled: bool = True,
                            task_fit_checker: Any = None, on_halt: Any = None, scan_recorder: Any = None) -> Firewall:
    selected_scanner = scanner if scanner is not None else Layer1Scanner(
        mode=mode, offline_cache_only=offline_cache_only, judge=judge)
    return Firewall(policy_path, scanner=selected_scanner,
                    approval_callback=approval_callback, audit_sink=audit_sink,
                    linking_enabled=linking_enabled, task_fit_checker=task_fit_checker, on_halt=on_halt,
                    scan_recorder=scan_recorder)
