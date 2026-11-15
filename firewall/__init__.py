"""Lightweight, agent-agnostic Layer 2 firewall package.

This module deliberately does not import Layer 1, model, agent, or SDK packages.
"""
from firewall.api import Firewall, NotConfigured
from firewall.decision import Action, Decision, ReasonCode
from firewall.policy import Policy, PolicyError, load_policy
from firewall.session import Session
from firewall.arg_types import register_type
from firewall.types import SegmentRecord, ScanOutcome, OutputResult
from firewall.approval import ReviewPacket
from firewall.audit import SQLiteAuditStore
from firewall.decision import FinalDecision

__all__ = [
    "Firewall", "Policy", "load_policy", "Decision", "Action", "ReasonCode",
    "Session", "PolicyError", "NotConfigured", "register_type",
    "SegmentRecord", "ScanOutcome", "OutputResult", "ReviewPacket", "FinalDecision", "SQLiteAuditStore",
]
