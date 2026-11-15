"""Public integration API for an agent-agnostic, fail-closed tool firewall."""
from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from copy import deepcopy
from typing import Any, Mapping
import re
import hashlib
import json
import uuid

from firewall.decision import Action, Decision, ReasonCode
from firewall.policy import Policy, PolicyError, policy_from_mapping, load_policy
from firewall.protocols import AuditSink, ApprovalCallback, NullAuditSink, Scanner
from firewall.approval import ReviewPacket, ask_with_timeout, run_with_timeout
from firewall.sensitivity import add_confidential
from firewall.taskfit import TaskFitChecker
from firewall.session import Session
from firewall.arg_types import accepts_value
from firewall.rules import CHECK_FUNCTIONS, combine_decisions
from firewall.types import OutputResult, ScanOutcome, SegmentRecord
from firewall.adapters.layer1 import ScannerUnavailable


class NotConfigured(RuntimeError):
    """An optional integration dependency has not been injected."""


_LEVEL_RANK = {"none": 0, "low": 1, "medium": 2, "needs_review": 3, "high": 4}


class Firewall:
    def __init__(self, policy: Policy | Mapping[str, Any] | str | Path, scanner: Scanner | None = None,
                 approval_callback: ApprovalCallback | None = None, audit_sink: AuditSink | None = None,
                 linking_enabled: bool = True, task_fit_checker: TaskFitChecker | None = None,
                 on_halt=None) -> None:
        if isinstance(policy, Policy):
            self.policy = policy
        elif isinstance(policy, (str, Path)):
            self.policy = load_policy(policy)
        else:
            self.policy = policy_from_mapping(policy)
        self.scanner = scanner
        self.approval_callback = approval_callback
        self.audit_sink = audit_sink or NullAuditSink()
        if type(linking_enabled) is not bool:
            raise TypeError("linking_enabled must be a boolean")
        self.linking_enabled = linking_enabled
        self.task_fit_checker = task_fit_checker
        self.on_halt = on_halt

    def start_session(self, user_task: str, allowed_tools=None) -> Session:
        if not isinstance(user_task, str):
            raise TypeError("user_task must be a string")
        if allowed_tools is not None:
            if not isinstance(allowed_tools, (list, tuple, set, frozenset)) or any(not isinstance(n, str) for n in allowed_tools):
                raise TypeError("allowed_tools must be a collection of tool names")
            allowed_tools = frozenset(allowed_tools)
        session = Session(user_task=user_task, allowed_tools=allowed_tools)
        try:
            record_session = getattr(self.audit_sink, "record_session", None)
            if callable(record_session): record_session(session.session_id, self.policy.policy_version, self.policy.agent_name, user_task)
            self.audit_sink.record({"event_type":"session_started", "session_id":session.session_id,
                "policy_version":self.policy.policy_version, "agent_name":self.policy.agent_name,
                "task_length":len(user_task), "user_task_sha256":hashlib.sha256(user_task.encode()).hexdigest()})
        except Exception:
            session.halted = True
        return session

    def scan_content(self, session: Session, content: str, source_type: str, *, doc_id: str | None = None,
                     context_note: str | None = None):
        if self.scanner is None:
            raise NotConfigured("No content scanner was injected; configure a Layer 1 scanner.")
        if not isinstance(session, Session):
            raise TypeError("session must be a Session")
        if not isinstance(content, str):
            raise TypeError("content must be a string")
        if doc_id is None:
            session.content_counter += 1
            doc_id = f"{session.session_id[:8]}-content{session.content_counter:04d}"
        remaining = self._remaining_budget(session)
        try:
            result = self.scanner.scan(content, doc_id=doc_id, source_type=source_type,
                                       user_task=session.user_task, context_note=context_note,
                                       max_judge_calls=remaining)
            if not isinstance(result, ScanOutcome):
                raise ValueError
            if remaining is not None and result.judge_calls_made > remaining:
                raise ValueError
            if any(record.end > len(content) or content[record.start:record.end] != record.text
                   for record in result.segments):
                raise ValueError
            self._store_segments(session, result, tool_name=None, output_id=None, unit_path=None)
            session.judge_calls_used += result.judge_calls_made
            return result
        except Exception:
            raise ScannerUnavailable("Content scan failed; the content was not cleared for the agent.") from None

    def _remaining_budget(self, session):
        budget = self.policy.output_inspection.session_judge_budget
        return None if budget is None else max(0, budget - session.judge_calls_used)

    @staticmethod
    def _store_segments(session, outcome: ScanOutcome, *, tool_name, output_id, unit_path):
        for record in outcome.segments:
            if not isinstance(record, SegmentRecord):
                raise ValueError("scanner returned a non-neutral segment")
            session.segments.append({"record": record, "tool_name": tool_name,
                                     "output_id": output_id, "unit_path": unit_path})
            session.level_counts[record.suspicion_level] = session.level_counts.get(record.suspicion_level, 0) + 1
            if not record.judge_ran or record.suspicion_level == "needs_review":
                if record.segment_id not in session.unreviewed_segment_ids:
                    session.unreviewed_segment_ids.append(record.segment_id)
            if _LEVEL_RANK[record.suspicion_level] > _LEVEL_RANK.get(session.max_level_seen, 0):
                session.max_level_seen = record.suspicion_level

    @staticmethod
    def _count_strings(value):
        if isinstance(value, str):
            return len(value)
        if isinstance(value, (list, tuple)):
            return sum(Firewall._count_strings(item) for item in value)
        if isinstance(value, dict):
            return sum(Firewall._count_strings(item) for item in value.values())
        return 0

    @staticmethod
    def _json_string_paths(value, max_depth):
        found = []
        def walk(node, path, depth):
            if isinstance(node, str):
                found.append((path, node))
            elif isinstance(node, dict) and depth < max_depth:
                for key, child in node.items():
                    walk(child, path + (key,), depth + 1)
            elif isinstance(node, (list, tuple)) and depth < max_depth:
                for index, child in enumerate(node):
                    walk(child, path + (index,), depth + 1)
        walk(value, (), 0)
        return found

    @staticmethod
    def _replace_json_string(root, path, new_value):
        if not path:
            return new_value
        parent = root
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = new_value
        return root

    @staticmethod
    def _marked_view(view, notice):
        if isinstance(view, str):
            return view + "\n" + notice
        # A wrapper makes the mark visible without relying on a reserved key in user data.
        return {"content": view, "_firewall_notice": notice}

    @staticmethod
    def _merge_spans(spans, limit):
        valid = sorted((max(0, int(a)), min(limit, int(b))) for a, b in spans if int(b) > int(a))
        merged = []
        for start, end in valid:
            if start >= end:
                continue
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    def _output_result(self, session, output_id, tool_name, action, view, codes, max_level,
                       level_counts, segment_ids, unreviewed_ids, unscanned, judge_calls, message):
        result = OutputResult(output_id, action, view, tuple(dict.fromkeys(codes)), max_level,
                              dict(level_counts), tuple(segment_ids), tuple(unreviewed_ids),
                              int(unscanned), int(judge_calls), message)
        event = {"event": "tool_output_inspection", "tool_name": tool_name,
                 **result.to_audit_dict()}
        session.events.append(dict(event))
        try:
            self.audit_sink.record(event)
        except Exception:
            # An audit failure can never authorize content that was not safely inspected.
            result = OutputResult(output_id, "HOLD", self.policy.output_inspection.hold_placeholder,
                                  tuple(dict.fromkeys((*result.reason_codes, ReasonCode.OUTPUT_SCAN_FAILED.value))),
                                  result.max_level, result.level_counts, result.segment_ids,
                                  result.unreviewed_segment_ids, result.unscanned_chars,
                                  result.judge_calls_made, "Output inspection could not be recorded.")
            if session.events:
                session.events[-1].update({"action": "HOLD", "reason_codes": result.reason_codes,
                                           "message": result.message})
        if result.action == "HOLD":
            session.held_outputs[output_id] = {"tool_name": tool_name, "reason_codes": result.reason_codes}
        return result

    def inspect_tool_output(self, session: Session, tool_name: str, output: Any, *, doc_id: str | None = None,
                            context_note: str | None = None) -> OutputResult:
        if not isinstance(session, Session):
            raise TypeError("session must be a Session")
        try:
            return self._inspect_tool_output_impl(session, tool_name, output, doc_id=doc_id, context_note=context_note)
        except Exception:
            # Covers failures before or outside the scanner call as well: never surface raw output.
            if session.output_counter == 0:
                session.output_counter += 1
            output_id = f"{session.session_id[:8]}-out{session.output_counter:04d}"
            try:
                self._output_result(session, output_id, tool_name if isinstance(tool_name, str) else "<invalid>",
                                    "HOLD", self.policy.output_inspection.hold_placeholder,
                                    [ReasonCode.OUTPUT_SCAN_FAILED.value], "needs_review", {}, (), (), 0, 0,
                                    "Output inspection failed; the output was withheld.")
            except Exception:
                pass
            return OutputResult(output_id, "HOLD", self.policy.output_inspection.hold_placeholder,
                                (ReasonCode.OUTPUT_SCAN_FAILED.value,), "needs_review", {}, (), (), 0, 0,
                                "Output inspection failed; the output was withheld.")

    def _inspect_tool_output_impl(self, session: Session, tool_name: str, output: Any, *, doc_id: str | None = None,
                                  context_note: str | None = None) -> OutputResult:
        if not isinstance(session, Session):
            raise TypeError("session must be a Session")
        if not isinstance(tool_name, str) or not tool_name:
            raise TypeError("tool_name must be a non-empty string")
        cfg = self.policy.output_inspection
        session.output_counter += 1
        output_id = f"{session.session_id[:8]}-out{session.output_counter:04d}"
        session.original_outputs[output_id] = deepcopy(output)
        tool = self.policy.get_tool(tool_name)
        if tool is not None and tool.output_sensitivity == "confidential" and self.policy.sensitivity.enabled:
            def collect_text(value):
                if isinstance(value, str): return [value]
                if isinstance(value, Mapping): return [part for child in value.values() for part in collect_text(child)]
                if isinstance(value, (list, tuple)): return [part for child in value for part in collect_text(child)]
                return []
            for secret_text in collect_text(output):
                add_confidential(session, secret_text, self.policy.sensitivity)
        scan_enabled = cfg.enabled and (tool.scan_output if tool is not None else True)
        if not scan_enabled:
            chars = self._count_strings(output)
            return self._output_result(session, output_id, tool_name, "PASS", output,
                                       [ReasonCode.OUTPUT_SCAN_DISABLED.value], "none", {}, (), (), chars, 0,
                                       "Output scanning is disabled by policy.")

        level_counts = {level: 0 for level in ("none", "low", "medium", "high", "needs_review")}
        ids, unreviewed_ids, high_spans, unit_specs = [], [], [], []
        total_unscanned = 0
        calls_this_output = 0
        original_is_text = isinstance(output, str)
        structured = isinstance(output, (dict, list, tuple))
        if original_is_text:
            allowed = min(len(output), cfg.max_total_chars)
            for start in range(0, allowed, cfg.max_chars_per_chunk):
                end = min(allowed, start + cfg.max_chars_per_chunk)
                unit_specs.append(((), output[start:end], start))
            total_unscanned = len(output) - allowed
        elif structured:
            working_count = 0
            paths = self._json_string_paths(output, cfg.json_max_depth)
            skipped_strings = 0
            accepted_strings = 0
            for path, value in paths:
                accepted_strings += 1
                if accepted_strings > cfg.json_max_strings or working_count >= cfg.max_total_chars:
                    skipped_strings += len(value)
                    continue
                take = min(len(value), cfg.max_total_chars - working_count)
                permitted = value[:take]
                for start in range(0, len(permitted), cfg.max_chars_per_chunk):
                    end = min(len(permitted), start + cfg.max_chars_per_chunk)
                    unit_specs.append((path, permitted[start:end], start))
                working_count += take
                skipped_strings += len(value) - take
            total_chars = self._count_strings(output)
            # Count values omitted by the depth limit as unscanned too.
            total_unscanned = max(skipped_strings, total_chars - working_count)
        else:
            marked = {"content": output, "_firewall_notice": "Non-text output was not scanned."}
            return self._output_result(session, output_id, tool_name, "PASS", marked,
                                       [ReasonCode.OUTPUT_NOT_TEXT.value, ReasonCode.OUTPUT_UNREVIEWED.value],
                                       "needs_review", {}, (), (), len(output) if isinstance(output, bytes) else 0,
                                       0, "Non-text output was not scanned.")

        oversize = total_unscanned > 0
        if oversize:
            code = ReasonCode.OUTPUT_OVERSIZE.value
        else:
            code = None
        try:
            description = tool.description if tool is not None else "Unlisted tool output."
            for unit_index, (path, unit_text, local_base) in enumerate(unit_specs):
                if self.scanner is None:
                    raise RuntimeError("scanner unavailable")
                safe_tool_id = tool_name if tool is not None else "unlisted"
                single_explicit_unit = doc_id is not None and len(unit_specs) == 1 and unit_index == 0
                effective_doc_id = (doc_id if single_explicit_unit else f"{doc_id}-{safe_tool_id}-u{unit_index}" if doc_id else
                                     f"{session.session_id[:8]}-out{session.output_counter}-{safe_tool_id}-{unit_index}")
                scan_context_note = context_note or (f"Output returned by the tool '{tool_name}': {description}"
                                                     if tool is not None else "Output returned by an unlisted tool.")
                outcome = self.scanner.scan(unit_text, doc_id=effective_doc_id, source_type="tool_output",
                                            user_task=session.user_task, context_note=scan_context_note,
                                            max_judge_calls=self._remaining_budget(session))
                if not isinstance(outcome, ScanOutcome):
                    raise ValueError("scanner returned invalid result")
                remaining = self._remaining_budget(session)
                if remaining is not None and outcome.judge_calls_made > remaining:
                    raise ValueError("scanner exceeded its call budget")
                calls_this_output += outcome.judge_calls_made
                session.judge_calls_used += outcome.judge_calls_made
                for record in outcome.segments:
                    if record.end > len(unit_text) or unit_text[record.start:record.end] != record.text:
                        raise ValueError("scanner offsets do not match input")
                absolute_records = tuple(SegmentRecord(
                    record.segment_id, record.doc_id, record.source_type,
                    record.start + local_base, record.end + local_base, record.text,
                    record.suspicion_level, record.judge_ran, record.coverage_reason,
                    record.rules_flag, record.piguard_flag,
                ) for record in outcome.segments)
                stored_outcome = ScanOutcome(absolute_records, outcome.judge_calls_made, outcome.coverage_fraction)
                self._store_segments(session, stored_outcome, tool_name=tool_name, output_id=output_id,
                                     unit_path=path)
                local_high = []
                for record in outcome.segments:
                    ids.append(record.segment_id)
                    level_counts[record.suspicion_level] += 1
                    if not record.judge_ran or record.suspicion_level == "needs_review":
                        unreviewed_ids.append(record.segment_id)
                    if record.suspicion_level == "high":
                        local_high.append((record.start, record.end))
                if local_high:
                    high_spans.append((path, local_base, local_high, len(unit_text)))
        except Exception:
            remainder_chars = total_unscanned
            return self._output_result(session, output_id, tool_name, "HOLD", cfg.hold_placeholder,
                                       [ReasonCode.OUTPUT_SCAN_FAILED.value], "needs_review", level_counts,
                                       ids, unreviewed_ids, remainder_chars, calls_this_output,
                                       "Output scanning failed; the output was withheld.")

        levels = [level for level, count in level_counts.items() if count]
        max_level = max(levels, key=lambda x: _LEVEL_RANK[x]) if levels else "none"
        codes = [code] if code else []
        if unreviewed_ids:
            codes.append(ReasonCode.OUTPUT_UNREVIEWED.value)
        action = "PASS"
        view = deepcopy(output)
        message = "Output passed inspection."
        if max_level == "high":
            high_action = cfg.actions["high"]
            if high_action == "hold":
                action, view, message = "HOLD", cfg.hold_placeholder, "Output was withheld for review."
                codes.append(ReasonCode.OUTPUT_HELD.value)
            else:
                action, codes, message = "MASK", codes + [ReasonCode.OUTPUT_MASKED.value], "Suspicious spans were masked in the agent copy."
                if original_is_text:
                    spans = [(base + a, base + b) for path, base, spans, _ in high_spans for a, b in spans]
                    for start, end in reversed(self._merge_spans(spans, len(output))):
                        view = view[:start] + cfg.mask_placeholder + view[end:]
                else:
                    by_path = {}
                    for path, base, spans, _ in high_spans:
                        by_path.setdefault(path, []).extend((base + a, base + b) for a, b in spans)
                    for path, spans in by_path.items():
                        text_value = output
                        for key in path:
                            text_value = text_value[key]
                        masked = text_value
                        for start, end in reversed(self._merge_spans(spans, len(text_value))):
                            masked = masked[:start] + cfg.mask_placeholder + masked[end:]
                        view = self._replace_json_string(view, path, masked)
        elif max_level == "needs_review":
            action_cfgs = [cfg.actions["needs_review"]]
            if unreviewed_ids:
                action_cfgs.append(cfg.actions["unreviewed"])
            codes.append(ReasonCode.OUTPUT_UNREVIEWED.value)
            if "hold" in action_cfgs:
                action, view, message = "HOLD", cfg.hold_placeholder, "Output requires review and was withheld."
                codes.append(ReasonCode.OUTPUT_HELD.value)
            else:
                action, message = "PASS", "Output passed with unreviewed segments marked."
                view = self._marked_view(view, "Some output segments were not reviewed.")
        elif unreviewed_ids:
            unreviewed_action = cfg.actions["unreviewed"]
            if unreviewed_action == "hold":
                action, view, message = "HOLD", cfg.hold_placeholder, "Output has unreviewed segments and was withheld."
                codes.append(ReasonCode.OUTPUT_HELD.value)
            else:
                view = self._marked_view(view, "Some output segments were not reviewed.")
                message = "Output passed with unreviewed segments marked."
        else:
            codes.append(ReasonCode.OUTPUT_PASSED.value)

        if oversize:
            if cfg.oversize_action == "hold":
                action, view, message = "HOLD", cfg.hold_placeholder, "Oversized output was withheld."
                codes.append(ReasonCode.OUTPUT_HELD.value)
            elif cfg.oversize_action == "truncate":
                notice = "\n[Output truncated; remainder was not scanned.]"
                if original_is_text:
                    scanned_end = len(output) - total_unscanned
                    if action != "HOLD":
                        prefix = output[:scanned_end]
                        if action == "MASK":
                            spans = [(base + a, min(scanned_end, base + b)) for path, base, spans, _ in high_spans
                                     if path == () for a, b in spans if base + a < scanned_end]
                            for start, end in reversed(self._merge_spans(spans, scanned_end)):
                                prefix = prefix[:start] + cfg.mask_placeholder + prefix[end:]
                        view = prefix + notice
                elif structured:
                    scanned_lengths = {}
                    for path, text_value, base in unit_specs:
                        scanned_lengths[path] = max(scanned_lengths.get(path, 0), base + len(text_value))
                    def truncate_node(node, path=()):
                        if isinstance(node, str):
                            end = min(len(node), scanned_lengths.get(path, 0))
                            return node[:end] + ("[unscanned remainder omitted]" if end < len(node) else "")
                        if isinstance(node, dict):
                            return {key: truncate_node(value, path + (key,)) for key, value in node.items()}
                        if isinstance(node, list):
                            return [truncate_node(value, path + (i,)) for i, value in enumerate(node)]
                        if isinstance(node, tuple):
                            return tuple(truncate_node(value, path + (i,)) for i, value in enumerate(node))
                        return node
                    if action != "HOLD":
                        view = truncate_node(deepcopy(output))
                        if action == "MASK":
                            spans_by_path = {}
                            for path, base, spans, _ in high_spans:
                                spans_by_path.setdefault(path, []).extend((base + a, base + b) for a, b in spans)
                            for path, spans in spans_by_path.items():
                                original_value = output
                                for key in path:
                                    original_value = original_value[key]
                                scanned_end = min(len(original_value), scanned_lengths.get(path, 0))
                                prefix = original_value[:scanned_end]
                                for start, end in reversed(self._merge_spans(spans, scanned_end)):
                                    prefix = prefix[:start] + cfg.mask_placeholder + prefix[end:]
                                if scanned_end < len(original_value):
                                    prefix += "[unscanned remainder omitted]"
                                view = self._replace_json_string(view, path, prefix)
                    codes.append(ReasonCode.OUTPUT_UNREVIEWED.value)
                message = "Only the permitted portion was scanned."
            else:
                view = self._marked_view(view, "Output remainder was not scanned.")
                action = "PASS"
            if cfg.oversize_action == "pass_marked":
                codes.append(ReasonCode.OUTPUT_UNREVIEWED.value)
        if not codes:
            codes.append(ReasonCode.OUTPUT_PASSED.value)
        return self._output_result(session, output_id, tool_name, action, view, codes, max_level,
                                   level_counts, ids, unreviewed_ids, total_unscanned,
                                   calls_this_output, message)

    def get_original_output(self, session: Session, output_id: str, *, reviewer: bool = False):
        if not isinstance(session, Session):
            raise TypeError("session must be a Session")
        if reviewer is not True:
            raise PermissionError("Original tool output is available to reviewers only.")
        if output_id not in session.original_outputs:
            raise KeyError("Unknown output identifier.")
        return deepcopy(session.original_outputs[output_id])

    def record_tool_result(self, session: Session, tool_name: str, output: Any, *, doc_id: str | None = None,
                           context_note: str | None = None) -> OutputResult:
        """Record confidential fingerprints and inspect a returned result through Day 7."""
        return self.inspect_tool_output(session, tool_name, output, doc_id=doc_id, context_note=context_note)

    @staticmethod
    def _argument_names(args: dict) -> tuple[str, ...]:
        names = []
        for key in dict.keys(args):
            if not isinstance(key, str) or not key:
                raise TypeError("argument names must be non-empty strings")
            names.append(key)
        return tuple(sorted(names))

    @staticmethod
    def _has_type(value: Any, declared: str) -> bool:
        return accepts_value(declared, value)

    def _record(self, session: Any, tool_name: str, argument_names: tuple[str, ...], decision: Decision, call_hash: str | None = None) -> Decision:
        if isinstance(session, Session) and decision.action is Action.BLOCK:
            key=tool_name if isinstance(tool_name,str) else "<invalid>"
            session.blocked_attempts[key]=session.blocked_attempts.get(key,0)+1
        session_id = session.session_id if isinstance(session, Session) else None
        link_report = session.last_link_report if isinstance(session, Session) else None
        evidence = []
        if link_report is not None:
            evidence = [{"kind": item.kind, "arg_name": item.arg_name, "segment_id": item.segment_id,
                         "segment_level": item.segment_level, "match_type": item.match_type,
                         "score": item.score, "user_provided": item.user_provided}
                        for item in link_report.evidence]
        event = {
            "event_type": "tool_check", "tool": tool_name if isinstance(tool_name, str) else "<invalid>",
            "tool_name": tool_name if isinstance(tool_name, str) else "<invalid>",
            "action": decision.action.value,
            "reason_codes": tuple(code.value for code in decision.reason_codes),
            "rule_ids": decision.rule_ids,
            "argument_names": argument_names,
            "session_id": session_id,
            "link_level": link_report.link_level if link_report is not None else "NONE",
            "evidence": evidence,
            "user_provided_args": link_report.user_provided_args if link_report is not None else (),
        }
        if isinstance(session, Session):
            session.events.append(dict(event))
        try:
            self.audit_sink.record(event)
        except Exception:
            # The audit adapter may fail; do not leak its error or turn failure into an allow.
            failed = Decision.block((ReasonCode.AUDIT_UNAVAILABLE,), "A security record could not be written.")
            if isinstance(session, Session) and session.events:
                session.events[-1].update({"action": Action.BLOCK.value,
                                           "reason_codes": (ReasonCode.AUDIT_UNAVAILABLE.value,)})
            return failed
        return decision

    @staticmethod
    def _safe_preview(value, limit):
        if isinstance(value, str): text=value
        else:
            try: text=json.dumps(value, ensure_ascii=False, sort_keys=True, default=lambda _: "[value]")
            except Exception: text="[unavailable]"
        text="".join(" " if ord(ch)<32 or ord(ch)==127 else ch for ch in text)
        return text[:limit]

    def authorize_tool_call(self, session: Session, tool_name: str, args: dict):
        """Check a call and resolve ASK through a bounded human approval callback."""
        from firewall.decision import FinalDecision
        if not isinstance(session, Session) or not isinstance(args, dict) or not isinstance(tool_name, str) or not tool_name:
            return FinalDecision("BLOCK", (ReasonCode.INTERNAL_ERROR,), "none", "This action was not permitted. Do not retry it; ask the user instead.", None)
        if session.halted:
            return FinalDecision("BLOCK", (ReasonCode.SESSION_HALTED,), "none", "This session is halted pending reviewer action.", None)
        decision=self.check_tool_call(session, tool_name, args)
        if decision.action is Action.ALLOW:
            if not self._audit_authorized(session, tool_name, "allow", decision.reason_codes, "none"):
                return FinalDecision("DENIED", (ReasonCode.AUDIT_UNAVAILABLE,), "error", "This action was not permitted. Do not retry it; ask the user instead.", decision)
            return FinalDecision("ALLOW", decision.reason_codes, "none", "The action was permitted.", decision)
        if decision.action is Action.BLOCK:
            self._register_block(session, tool_name, args)
            if session.halted:
                decision=Decision.block((ReasonCode.RETRY_LIMIT_REACHED,), "Repeated blocked calls halted this session.", rule_id="R-LOOP")
            self._audit_authorized(session, tool_name, "block", decision.reason_codes, "none")
            return FinalDecision("BLOCK", decision.reason_codes, "none", "This action was not permitted. Do not retry it; ask the user instead.", decision)
        callback=self.approval_callback
        if callback is None:
            outcome="no_approver"; code=ReasonCode.NO_APPROVER; result=False
        else:
            report=session.last_link_report
            evidence=tuple({"segment_id":e.segment_id,"level":e.segment_level,"match_type":e.match_type} for e in (report.evidence if report else ()))
            flags=("CONFIDENTIAL_DATA_EXTERNAL",) if ReasonCode.CONFIDENTIAL_DATA_EXTERNAL in decision.reason_codes else ()
            preview={name:self._safe_preview(value,self.policy.approval.preview_max_chars) for name,value in args.items()}
            packet=ReviewPacket(uuid.uuid4().hex,session.session_id,tool_name,tuple(c.value for c in decision.reason_codes),self.explain(decision),evidence,flags,preview)
            audit_evidence=tuple({"segment_id":e.segment_id,"segment_level":e.segment_level,"match_type":e.match_type} for e in (report.evidence if report else ()))
            try: self.audit_sink.record({"event_type":"approval_requested","session_id":session.session_id,"tool":tool_name,"action":"ask","reason_codes":[c.value for c in decision.reason_codes],"request_id":packet.request_id,"link_level":report.link_level if report else "NONE","evidence":list(audit_evidence)})
            except Exception:
                return FinalDecision("DENIED", tuple(dict.fromkeys((*decision.reason_codes,ReasonCode.AUDIT_UNAVAILABLE))), "error", "This action was not permitted. Do not retry it; ask the user instead.", decision)
            outcome,result=ask_with_timeout(callback,packet,self.policy.approval.timeout_seconds)
            code={"approved":ReasonCode.USER_APPROVED,"denied":ReasonCode.USER_DENIED,"timeout":ReasonCode.APPROVAL_TIMEOUT,"error":ReasonCode.APPROVAL_CALLBACK_ERROR}[outcome]
        session.approval_count += 1
        call_hash=hashlib.sha256(json.dumps({"tool":tool_name,"args":args},sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()
        session.authorized_calls[call_hash]=outcome
        if outcome != "approved":
            session.denied_call_counts[call_hash]=session.denied_call_counts.get(call_hash,0)+1
            session.blocked_session_count += 1
            session.blocked_attempts[tool_name]=session.blocked_attempts.get(tool_name,0)+1
            tool_count=session.blocked_attempts.get(tool_name,0)
            guard=self.policy.loop_guard
            if (session.denied_call_counts[call_hash] >= guard.max_denied_same_call or
                session.blocked_session_count >= guard.max_blocked_per_session or
                tool_count >= guard.max_blocked_per_tool):
                session.halted=True
                code=ReasonCode.RETRY_LIMIT_REACHED
                try:
                    self.audit_sink.record({"event_type":"loop_guard_triggered","session_id":session.session_id,"tool":tool_name,"action":"denied","reason_codes":[code.value]})
                    self.audit_sink.record({"event_type":"session_halted","session_id":session.session_id,"action":"denied","reason_codes":[ReasonCode.SESSION_HALTED.value]})
                    if self.on_halt: self.on_halt(session.session_id,(code.value,))
                except Exception: code=ReasonCode.AUDIT_UNAVAILABLE
        final_codes=tuple(dict.fromkeys((*decision.reason_codes,code)))
        final_action="ALLOW" if outcome=="approved" else "DENIED"
        try:
            self.audit_sink.record({"event_type":"approval_outcome","session_id":session.session_id,"tool":tool_name,"action":final_action.casefold(),"reason_codes":[code.value for code in final_codes],"approval_outcome":outcome})
        except Exception:
            session.halted=True
            return FinalDecision("DENIED", tuple(dict.fromkeys((*final_codes,ReasonCode.AUDIT_UNAVAILABLE))), "error", "This action was not permitted. Do not retry it; ask the user instead.", decision)
        if not self._audit_authorized(session,tool_name,final_action.casefold(),final_codes,outcome):
            return FinalDecision("DENIED", tuple(dict.fromkeys((*final_codes,ReasonCode.AUDIT_UNAVAILABLE))), "error", "This action was not permitted. Do not retry it; ask the user instead.", decision)
        message="The approved action may proceed." if final_action=="ALLOW" else "This action was not permitted. Do not retry it; ask the user instead."
        return FinalDecision(final_action,final_codes,outcome,message,decision)

    def _register_block(self, session, tool_name, args):
        keyhash=hashlib.sha256(json.dumps({"tool":tool_name,"args":args},sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()
        # check_tool_call has already counted an immediate BLOCK.
        session.blocked_session_count+=1
        session.denied_call_counts[keyhash]=session.denied_call_counts.get(keyhash,0)+1
        guard=self.policy.loop_guard
        if (session.blocked_attempts[tool_name] >= guard.max_blocked_per_tool or
            session.blocked_session_count >= guard.max_blocked_per_session or
            session.denied_call_counts[keyhash] >= guard.max_denied_same_call):
            session.halted=True
            try:
                self.audit_sink.record({"event_type":"loop_guard_triggered","session_id":session.session_id,"tool":tool_name,"action":"block","reason_codes":[ReasonCode.RETRY_LIMIT_REACHED.value]})
                self.audit_sink.record({"event_type":"session_halted","session_id":session.session_id,"action":"block","reason_codes":[ReasonCode.SESSION_HALTED.value]})
                if self.on_halt: self.on_halt(session.session_id,(ReasonCode.RETRY_LIMIT_REACHED.value,))
            except Exception:
                session.halted=True

    def _audit_authorized(self,session,tool_name,action,codes,outcome):
        try:
            self.audit_sink.record({"event_type":"tool_authorized","session_id":session.session_id,"tool":tool_name,"action":action,"reason_codes":[c.value for c in codes],"approval_outcome":outcome})
            return True
        except Exception: session.halted=True; return False

    def resume_session(self, session: Session, *, reviewer: bool = False):
        if reviewer is not True: raise PermissionError("A reviewer must authorize session resumption.")
        session.halted=False; session.blocked_attempts.clear(); session.blocked_session_count=0; session.denied_call_counts.clear()
        try: self.audit_sink.record({"event_type":"session_resumed","session_id":session.session_id,"action":"allow","reason_codes":[]})
        except Exception: session.halted=True

    def check_tool_call(self, session: Session, tool_name: str, args: dict) -> Decision:
        names: tuple[str, ...] = ()
        if isinstance(session, Session):
            session.last_link_report = None
        try:
            if not isinstance(args, dict):
                raise TypeError("tool arguments must be a dictionary")
            names = self._argument_names(args)
            if not isinstance(session, Session):
                raise TypeError("session must be a Session")
            if not isinstance(tool_name, str) or not tool_name:
                raise TypeError("tool_name must be a non-empty string")
            if session.halted:
                return self._record(session, tool_name, names, Decision.block((ReasonCode.SESSION_HALTED,), "This session is halted pending reviewer action.", rule_id="R-LOOP"))
            call_hash = hashlib.sha256(json.dumps({"tool":tool_name,"args":args}, sort_keys=True, separators=(",",":"), default=str).encode()).hexdigest()

            tool = self.policy.get_tool(tool_name)
            if tool is None:
                action = Action(self.policy.defaults.unknown_tool_action)
                decision = Decision(action, (ReasonCode.UNKNOWN_TOOL,), "The requested tool is not in policy.",
                                    details={"tool_name": tool_name, "argument_names": names}, rule_id="R-STRUCTURE")
                return self._record(session, tool_name, names, decision, call_hash)

            missing = tuple(sorted(name for name, spec in tool.args.items() if spec.required and name not in args))
            if missing:
                decision = Decision.block((ReasonCode.MISSING_ARGUMENT,), "A required argument is missing.",
                                          details={"argument_names": missing}, rule_id="R-STRUCTURE")
                return self._record(session, tool_name, names, decision, call_hash)

            unexpected = tuple(sorted(name for name in names if name not in tool.args))
            if unexpected and self.policy.defaults.strict_args:
                decision = Decision.block((ReasonCode.UNEXPECTED_ARGUMENT,), "The call has an unexpected argument.",
                                          details={"argument_names": unexpected}, rule_id="R-STRUCTURE")
                return self._record(session, tool_name, names, decision, call_hash)

            wrong = tuple(sorted(name for name in names if name in tool.args and
                                 not self._has_type(args[name], tool.args[name].type)))
            if wrong:
                decision = Decision.block((ReasonCode.WRONG_ARGUMENT_TYPE,), "An argument has the wrong type.",
                                          details={"argument_names": wrong}, rule_id="R-STRUCTURE")
                return self._record(session, tool_name, names, decision, call_hash)

            checks = CHECK_FUNCTIONS if self.linking_enabled else (*CHECK_FUNCTIONS[:-2], CHECK_FUNCTIONS[-1])
            results = [check(self, session, tool_name, args) for check in checks]
            check_ids = ("R-TASK", "R-ARGVALUES", "R-ALWAYSASK", "R-LINK", "R-SENS") if self.linking_enabled else ("R-TASK", "R-ARGVALUES", "R-ALWAYSASK", "R-SENS")
            tool_policy = self.policy.get_tool(tool_name)
            if self.task_fit_checker and tool_policy and (tool_policy.risk == "high" or tool_policy.side_effects):
                try:
                    status, verdict=run_with_timeout(lambda:self.task_fit_checker.check(session.user_task, tool_name, tool_policy.description, dict(self.policy.arg_types(tool_name))),1.0)
                    if status != "result": verdict="unknown"
                    if verdict == "does_not_fit":
                        results.append(Decision.ask((ReasonCode.TASK_FIT_DOUBTFUL,), "The tool may not fit the task.", rule_id="R-TASKFIT")); check_ids += ("R-TASKFIT",)
                except Exception:
                    pass
            decision = combine_decisions(results, checks_run=check_ids)
            decision = Decision(decision.action, decision.reason_codes, decision.message,
                                rule_id=decision.rule_id, matched_segment_ids=decision.matched_segment_ids,
                                details={"argument_names": names, "task_permission_source": session.task_permission_source,
                                         "matched_task_categories": session.matched_task_categories,
                                         "link_level": session.last_link_report.link_level if session.last_link_report else "NONE",
                                         "user_provided_args": session.last_link_report.user_provided_args if session.last_link_report else (),
                                         "evidence": tuple({"kind": item.kind, "arg_name": item.arg_name,
                                                            "segment_id": item.segment_id, "segment_level": item.segment_level,
                                                            "match_type": item.match_type, "score": item.score,
                                                            "user_provided": item.user_provided}
                                                           for item in session.last_link_report.evidence)
                                         if session.last_link_report else ()},
                                rule_ids=decision.rule_ids)
            return self._record(session, tool_name, names, decision, call_hash)
        except Exception:
            safe_names = names if all(isinstance(n, str) for n in names) else ()
            decision = Decision.ask((ReasonCode.INTERNAL_ERROR,), "A security check could not be completed.",
                                    details={"argument_names": safe_names})
            try:
                return self._record(session, tool_name, safe_names, decision)
            except Exception:
                return decision

    @staticmethod
    def explain(decision_or_audit_event) -> str:
        """Build a short summary using only decision codes and provenance metadata."""
        if isinstance(decision_or_audit_event, Decision):
            action = decision_or_audit_event.action.value.upper()
            codes = [code.value for code in decision_or_audit_event.reason_codes]
            details = decision_or_audit_event.details
            link_level = details.get("link_level", "NONE")
            evidence = details.get("evidence", ())
        elif isinstance(decision_or_audit_event, Mapping):
            action = str(decision_or_audit_event.get("action", "UNKNOWN")).upper()
            codes = [str(code) for code in decision_or_audit_event.get("reason_codes", ())]
            link_level = str(decision_or_audit_event.get("link_level", "NONE"))
            evidence = decision_or_audit_event.get("evidence", ())
        else:
            return "Decision details are unavailable."
        codes = [code for code in codes if re.fullmatch(r"[A-Z][A-Z0-9_]*", code)]
        safe_codes = ", ".join(codes) if codes else "no reason codes"
        segments = sorted({str(item.get("segment_id", "")) for item in evidence if isinstance(item, Mapping)
                           and re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", str(item.get("segment_id", "")))})
        valid_levels = {"none", "low", "medium", "high", "needs_review"}
        levels = sorted({str(item.get("segment_level", "")) for item in evidence if isinstance(item, Mapping)
                         and item.get("segment_level") in valid_levels})
        evidence_summary = ""
        if segments:
            evidence_summary = f" Linked segments: {', '.join(segments)} ({', '.join(levels)})."
        link_level = link_level if str(link_level).upper() in {"NONE", "POSSIBLE", "LIKELY", "CONFIRMED"} else "NONE"
        return f"{safe_codes}; link level {link_level}.{evidence_summary}"
