"""Strict JSON/YAML policy loading with immutable validated policy objects."""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from firewall.arg_types import get_validator, registered_types


class PolicyError(ValueError):
    """A policy is malformed or contains an unsupported field/value."""


ARG_TYPES = registered_types()
RISK_LEVELS = frozenset({"low", "medium", "high"})
SENSITIVITY_LEVELS = frozenset({"none", "confidential"})


@dataclass(frozen=True)
class ArgPolicy:
    type: str
    required: bool = True
    constraints: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True)
class ToolPolicy:
    description: str
    risk: str
    side_effects: bool
    always_ask: bool
    args: Mapping[str, ArgPolicy]
    output_sensitivity: str = "none"
    scan_output: bool = True
    egress: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True)
class OutputInspection:
    enabled: bool = True
    max_chars_per_chunk: int = 20000
    max_total_chars: int = 200000
    oversize_action: str = "truncate"
    json_max_depth: int = 10
    json_max_strings: int = 500
    actions: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    mask_placeholder: str = "[removed: suspicious content]"
    hold_placeholder: str = "[Tool output withheld: suspicious content detected. Waiting for user review.]"
    session_judge_budget: int | None = None


_LINK_DEFAULTS = {
    "low": {"none": "allow", "possible": "allow", "likely": "allow_log", "confirmed": "ask"},
    "medium": {"none": "allow", "possible": "allow_log", "likely": "ask", "confirmed": "block"},
    "high": {"none": "allow", "possible": "ask", "likely": "ask", "confirmed": "block"},
}
_LINK_MATCHING_DEFAULTS = {
    "fuzzy_threshold": 0.92, "min_account_len": 6, "min_amount_digits": 3,
    "min_identifier_len": 4, "shingle_size": 5, "min_shingles": 3,
    "shingle_containment_threshold": 0.6, "max_segments": 5000,
    "max_chars_per_segment": 20000,
}


@dataclass(frozen=True)
class TaskCategory:
    allowed_tools: tuple[str, ...]
    keywords: tuple[str, ...]


@dataclass(frozen=True)
class Limits:
    allowed_recipient_domains: tuple[str, ...] = ()
    allow_subdomains: bool = False
    allowed_recipients: tuple[str, ...] = ()
    max_amount: float | None = None
    allowed_path_prefixes: tuple[str, ...] = ()
    blocked_path_patterns: tuple[str, ...] = ()
    allowed_accounts: tuple[str, ...] = ()
    allowed_url_domains: tuple[str, ...] = ()
    internal_domains: tuple[str, ...] = ()


@dataclass(frozen=True)
class Sensitivity:
    enabled: bool = False
    action: str = "ask"
    taint_mode: str = "overlap_only"
    shingle_size: int = 5
    min_overlap_shingles: int = 3
    min_token_len: int = 6


@dataclass(frozen=True)
class Approval:
    timeout_seconds: float = 120
    preview_max_chars: int = 200
    block_overridable: bool = False


@dataclass(frozen=True)
class LoopGuard:
    max_blocked_per_tool: int = 3
    max_blocked_per_session: int = 8
    max_denied_same_call: int = 2
    on_limit: str = "halt"


@dataclass(frozen=True)
class TaskFit:
    enabled: bool = False


@dataclass(frozen=True)
class Defaults:
    unknown_tool_action: str = "ask"
    strict_args: bool = True
    error_action: str = "ask"
    approval_timeout_action: str = "deny"
    violation_actions: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))


def _mapping(value: Any, path: str) -> dict:
    if not isinstance(value, dict):
        raise PolicyError(f"{path}: expected a mapping")
    if any(not isinstance(k, str) for k in value):
        raise PolicyError(f"{path}: mapping keys must be strings")
    return value


def _keys(value: dict, allowed: set[str], path: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        key = unknown[0]
        raise PolicyError(f"{path}.{key}: unknown key")


def _required(value: dict, names: tuple[str, ...], path: str) -> None:
    for name in names:
        if name not in value:
            raise PolicyError(f"{path}.{name}: required field is missing")


def _string(value: Any, path: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        raise PolicyError(f"{path}: expected a string")
    if nonempty and not value.strip():
        raise PolicyError(f"{path}: must not be empty")
    return value


def _bool(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise PolicyError(f"{path}: expected a boolean")
    return value


def _string_list(value: Any, path: str, *, allow_empty_strings: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyError(f"{path}: expected a list of strings")
    output = tuple(_string(item, f"{path}[{i}]", nonempty=not allow_empty_strings) for i, item in enumerate(value))
    if len(set(output)) != len(output):
        raise PolicyError(f"{path}: duplicate names are not allowed")
    return output


def _yaml_to_obj(node: Any, loader: Any, path: str, ancestors: frozenset[int] = frozenset()) -> Any:
    """Construct YAML nodes manually so duplicate mapping keys are rejected."""
    from yaml.nodes import MappingNode, ScalarNode, SequenceNode

    if id(node) in ancestors:
        raise PolicyError(f"{path}: cyclic YAML aliases are not supported")
    nested = ancestors | {id(node)}
    if isinstance(node, MappingNode):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=True)
            if not isinstance(key, str):
                raise PolicyError(f"{path}: mapping keys must be strings")
            child_path = f"{path}.{key}"
            if key in result:
                raise PolicyError(f"{child_path}: duplicate name")
            result[key] = _yaml_to_obj(value_node, loader, child_path, nested)
        return result
    if isinstance(node, SequenceNode):
        return [_yaml_to_obj(child, loader, f"{path}[{i}]", nested) for i, child in enumerate(node.value)]
    if isinstance(node, ScalarNode):
        return loader.construct_object(node, deep=True)
    raise PolicyError(f"{path}: unsupported YAML value")


def _parse_file(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"policy: cannot read {path}") from exc
    if not text.strip():
        raise PolicyError("policy: file is empty")
    try:
        raw = json.loads(text, object_pairs_hook=_json_pairs(path))
    except PolicyError:
        raise
    except json.JSONDecodeError:
        try:
            import yaml
            loader = yaml.SafeLoader(text)
            try:
                root_node = loader.get_single_node()
                if root_node is None:
                    raise PolicyError("policy: file is empty")
                raw = _yaml_to_obj(root_node, loader, "policy")
            finally:
                loader.dispose()
        except ImportError as exc:
            raise PolicyError(f"policy: {path} is not JSON and PyYAML is unavailable") from exc
        except PolicyError:
            raise
        except Exception as exc:
            raise PolicyError(f"policy: invalid YAML in {path}") from exc
    return _mapping(raw, "policy")


def _json_pairs(path: Path):
    def hook(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PolicyError(f"policy.{key}: duplicate name in {path}")
            result[key] = value
        return result
    return hook


def _validate(raw: dict) -> "Policy":
    _keys(raw, {"policy_version", "agent_name", "tools", "limits", "task_categories", "verb_to_tool", "defaults", "output_inspection", "link_policy", "session_taint", "link_matching", "verb_forms", "sensitivity", "approval", "loop_guard"}, "policy")
    _required(raw, ("policy_version", "agent_name", "tools"), "policy")
    policy_version = _string(raw["policy_version"], "policy.policy_version")
    agent_name = _string(raw["agent_name"], "policy.agent_name")

    raw_tools = _mapping(raw["tools"], "policy.tools")
    if not raw_tools:
        raise PolicyError("policy.tools: must contain at least one tool")
    tools: dict[str, ToolPolicy] = {}
    for name, raw_tool in raw_tools.items():
        tool_path = f"policy.tools.{name}"
        if not name.strip():
            raise PolicyError(f"{tool_path}: tool name must not be empty")
        tool = _mapping(raw_tool, tool_path)
        _keys(tool, {"description", "risk", "side_effects", "always_ask", "args", "output_sensitivity", "scan_output", "egress"}, tool_path)
        _required(tool, ("description", "risk", "side_effects", "args"), tool_path)
        description = _string(tool["description"], f"{tool_path}.description", nonempty=False)
        risk = _string(tool["risk"], f"{tool_path}.risk")
        if risk not in RISK_LEVELS:
            raise PolicyError(f"{tool_path}.risk: unknown risk {risk!r}")
        side_effects = _bool(tool["side_effects"], f"{tool_path}.side_effects")
        always_ask = _bool(tool.get("always_ask", False), f"{tool_path}.always_ask")
        sensitivity = _string(tool.get("output_sensitivity", "none"), f"{tool_path}.output_sensitivity")
        scan_output = _bool(tool.get("scan_output", True), f"{tool_path}.scan_output")
        if sensitivity not in SENSITIVITY_LEVELS:
            raise PolicyError(f"{tool_path}.output_sensitivity: unknown sensitivity {sensitivity!r}")
        raw_args = _mapping(tool["args"], f"{tool_path}.args")
        args = {}
        for arg_name, raw_arg in raw_args.items():
            arg_path = f"{tool_path}.args.{arg_name}"
            if not arg_name.strip():
                raise PolicyError(f"{arg_path}: argument name must not be empty")
            arg = _mapping(raw_arg, arg_path)
            _keys(arg, {"type", "required", "constraints"}, arg_path)
            _required(arg, ("type",), arg_path)
            arg_type = _string(arg["type"], f"{arg_path}.type")
            validator = get_validator(arg_type)
            if validator is None:
                raise PolicyError(f"{arg_path}.type: unknown type {arg_type!r}")
            constraints_raw = _mapping(arg.get("constraints", {}), f"{arg_path}.constraints")
            allowed_constraints = set(getattr(validator, "constraint_keys", ()))
            _keys(constraints_raw, allowed_constraints, f"{arg_path}.constraints")
            if constraints_raw and not allowed_constraints:
                raise PolicyError(f"{arg_path}.constraints: constraints are unsupported for type {arg_type!r}")
            constraints = dict(constraints_raw)
            for bound in ("min", "max"):
                if bound in constraints and (isinstance(constraints[bound], bool) or not isinstance(constraints[bound], (int, float)) or not math.isfinite(float(constraints[bound]))):
                    raise PolicyError(f"{arg_path}.constraints.{bound}: expected a finite number")
            if "min" in constraints and "max" in constraints and constraints["min"] > constraints["max"]:
                raise PolicyError(f"{arg_path}.constraints.max: must be greater than or equal to min")
            if "allowed_values" in constraints:
                constraints["allowed_values"] = _string_list(constraints["allowed_values"], f"{arg_path}.constraints.allowed_values")
                if not constraints["allowed_values"]:
                    raise PolicyError(f"{arg_path}.constraints.allowed_values: must not be empty")
            if "allowed_pattern" in constraints:
                pattern = _string(constraints["allowed_pattern"], f"{arg_path}.constraints.allowed_pattern")
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise PolicyError(f"{arg_path}.constraints.allowed_pattern: invalid regular expression") from exc
            if "max_length" in constraints and (type(constraints["max_length"]) is not int or constraints["max_length"] < 0):
                raise PolicyError(f"{arg_path}.constraints.max_length: expected a non-negative integer")
            if arg_type == "text_pattern" and "allowed_pattern" not in constraints:
                raise PolicyError(f"{arg_path}.constraints.allowed_pattern: required field is missing")
            if arg_type == "enum" and "allowed_values" not in constraints:
                raise PolicyError(f"{arg_path}.constraints.allowed_values: required field is missing")
            args[arg_name] = ArgPolicy(arg_type, _bool(arg.get("required", True), f"{arg_path}.required"), MappingProxyType(constraints))
        egress_raw = _mapping(tool.get("egress", {}), f"{tool_path}.egress")
        _keys(egress_raw, {"args", "destination_args", "scope"}, f"{tool_path}.egress")
        egress = {}
        for field_name in ("args", "destination_args"):
            vals = _string_list(egress_raw.get(field_name, []), f"{tool_path}.egress.{field_name}")
            for arg in vals:
                if arg not in args:
                    raise PolicyError(f"{tool_path}.egress.{field_name}: unknown argument {arg!r}")
            egress[field_name] = vals
        scope = _string(egress_raw.get("scope", "by_destination"), f"{tool_path}.egress.scope")
        if scope not in {"external", "by_destination"}:
            raise PolicyError(f"{tool_path}.egress.scope: expected external or by_destination")
        egress["scope"] = scope
        if bool(egress_raw) and not egress["args"]:
            raise PolicyError(f"{tool_path}.egress.args: at least one argument is required")
        egress_policy = MappingProxyType(egress) if egress_raw else MappingProxyType({})
        tools[name] = ToolPolicy(description, risk, side_effects, always_ask, MappingProxyType(args), sensitivity, scan_output, egress_policy)

    limits_raw = _mapping(raw.get("limits", {}), "policy.limits")
    _keys(limits_raw, {"allowed_recipient_domains", "allow_subdomains", "allowed_recipients", "max_amount", "allowed_path_prefixes", "blocked_path_patterns", "allowed_accounts", "allowed_url_domains", "internal_domains"}, "policy.limits")
    domains = _string_list(limits_raw.get("allowed_recipient_domains", []), "policy.limits.allowed_recipient_domains")
    recipients = _string_list(limits_raw.get("allowed_recipients", []), "policy.limits.allowed_recipients")
    prefixes = _string_list(limits_raw.get("allowed_path_prefixes", []), "policy.limits.allowed_path_prefixes")
    blocked = _string_list(limits_raw.get("blocked_path_patterns", []), "policy.limits.blocked_path_patterns")
    allow_subdomains = _bool(limits_raw.get("allow_subdomains", False), "policy.limits.allow_subdomains")
    max_amount = limits_raw.get("max_amount")
    if max_amount is not None:
        try:
            valid_amount = (not isinstance(max_amount, bool) and isinstance(max_amount, (int, float))
                            and math.isfinite(float(max_amount)) and max_amount >= 0)
        except (OverflowError, TypeError, ValueError):
            valid_amount = False
        if not valid_amount:
            raise PolicyError("policy.limits.max_amount: expected a finite number greater than or equal to zero")
    accounts = _string_list(limits_raw.get("allowed_accounts", []), "policy.limits.allowed_accounts")
    url_domains = _string_list(limits_raw.get("allowed_url_domains", []), "policy.limits.allowed_url_domains")
    internal_domains = domains if "internal_domains" not in limits_raw else _string_list(limits_raw["internal_domains"], "policy.limits.internal_domains")
    limits = Limits(domains, allow_subdomains, recipients, float(max_amount) if max_amount is not None else None, prefixes, blocked, accounts, url_domains, internal_domains)

    sensitivity_raw = _mapping(raw.get("sensitivity", {}), "policy.sensitivity")
    _keys(sensitivity_raw, {"enabled", "action", "taint_mode", "shingle_size", "min_overlap_shingles", "min_token_len"}, "policy.sensitivity")
    sensitivity = Sensitivity(_bool(sensitivity_raw.get("enabled", False), "policy.sensitivity.enabled"),
        _string(sensitivity_raw.get("action", "ask"), "policy.sensitivity.action"),
        _string(sensitivity_raw.get("taint_mode", "overlap_only"), "policy.sensitivity.taint_mode"),
        sensitivity_raw.get("shingle_size", 5), sensitivity_raw.get("min_overlap_shingles", 3), sensitivity_raw.get("min_token_len", 6))
    if sensitivity.action not in {"ask", "block"}: raise PolicyError("policy.sensitivity.action: expected ask or block")
    if sensitivity.taint_mode not in {"overlap_only", "any_confidential_in_session"}: raise PolicyError("policy.sensitivity.taint_mode: invalid value")
    for field_name in ("shingle_size", "min_overlap_shingles", "min_token_len"):
        if type(getattr(sensitivity, field_name)) is not int or getattr(sensitivity, field_name) < 1: raise PolicyError(f"policy.sensitivity.{field_name}: expected positive integer")
    approval_raw = _mapping(raw.get("approval", {}), "policy.approval")
    _keys(approval_raw, {"timeout_seconds", "preview_max_chars", "block_overridable"}, "policy.approval")
    approval = Approval(approval_raw.get("timeout_seconds", 120), approval_raw.get("preview_max_chars", 200), _bool(approval_raw.get("block_overridable", False), "policy.approval.block_overridable"))
    if isinstance(approval.timeout_seconds, bool) or not isinstance(approval.timeout_seconds, (int,float)) or not math.isfinite(float(approval.timeout_seconds)) or approval.timeout_seconds <= 0: raise PolicyError("policy.approval.timeout_seconds: expected positive number")
    if type(approval.preview_max_chars) is not int or approval.preview_max_chars < 0: raise PolicyError("policy.approval.preview_max_chars: expected non-negative integer")
    if approval.block_overridable: raise PolicyError("policy.approval.block_overridable: only false is allowed")
    loop_raw = _mapping(raw.get("loop_guard", {}), "policy.loop_guard")
    _keys(loop_raw, {"max_blocked_per_tool", "max_blocked_per_session", "max_denied_same_call", "on_limit"}, "policy.loop_guard")
    loop_guard = LoopGuard(loop_raw.get("max_blocked_per_tool", 3), loop_raw.get("max_blocked_per_session", 8), loop_raw.get("max_denied_same_call", 2), _string(loop_raw.get("on_limit", "halt"), "policy.loop_guard.on_limit"))
    for field_name in ("max_blocked_per_tool", "max_blocked_per_session", "max_denied_same_call"):
        if type(getattr(loop_guard, field_name)) is not int or getattr(loop_guard, field_name) < 1: raise PolicyError(f"policy.loop_guard.{field_name}: expected positive integer")
    if loop_guard.on_limit != "halt": raise PolicyError("policy.loop_guard.on_limit: only halt is allowed")

    category_raw = _mapping(raw.get("task_categories", {}), "policy.task_categories")
    categories = {}
    for name, raw_category in category_raw.items():
        path = f"policy.task_categories.{name}"
        if not name.strip():
            raise PolicyError(f"{path}: category name must not be empty")
        category = _mapping(raw_category, path)
        _keys(category, {"allowed_tools", "keywords"}, path)
        _required(category, ("allowed_tools", "keywords"), path)
        allowed = _string_list(category["allowed_tools"], f"{path}.allowed_tools")
        for tool_name in allowed:
            if tool_name not in tools:
                raise PolicyError(f"{path}.allowed_tools: unknown tool {tool_name!r}")
        keywords = _string_list(category["keywords"], f"{path}.keywords")
        categories[name] = TaskCategory(allowed, keywords)

    verb_raw = _mapping(raw.get("verb_to_tool", {}), "policy.verb_to_tool")
    verb_to_tool = {}
    for verb, names in verb_raw.items():
        path = f"policy.verb_to_tool.{verb}"
        if not verb.strip():
            raise PolicyError(f"{path}: verb must not be empty")
        referenced = _string_list(names, path)
        for name in referenced:
            if name not in tools:
                raise PolicyError(f"{path}: unknown tool {name!r}")
        verb_to_tool[verb] = referenced

    defaults_raw = _mapping(raw.get("defaults", {}), "policy.defaults")
    _keys(defaults_raw, {"unknown_tool_action", "strict_args", "error_action", "approval_timeout_action", "violation_actions"}, "policy.defaults")
    unknown_action = _string(defaults_raw.get("unknown_tool_action", "ask"), "policy.defaults.unknown_tool_action")
    if unknown_action not in {"ask", "block"}:
        raise PolicyError("policy.defaults.unknown_tool_action: expected 'ask' or 'block'")
    strict_args = _bool(defaults_raw.get("strict_args", True), "policy.defaults.strict_args")
    error_action = _string(defaults_raw.get("error_action", "ask"), "policy.defaults.error_action")
    if error_action != "ask":
        raise PolicyError("policy.defaults.error_action: only 'ask' is allowed")
    timeout_action = _string(defaults_raw.get("approval_timeout_action", "deny"), "policy.defaults.approval_timeout_action")
    if timeout_action != "deny":
        raise PolicyError("policy.defaults.approval_timeout_action: only 'deny' is allowed")
    action_defaults = {"task": "ask", "recipient": "ask", "account": "ask", "amount": "block", "path": "block", "url": "ask", "value": "block"}
    action_raw = _mapping(defaults_raw.get("violation_actions", {}), "policy.defaults.violation_actions")
    _keys(action_raw, set(action_defaults), "policy.defaults.violation_actions")
    for key, value in action_raw.items():
        action = _string(value, f"policy.defaults.violation_actions.{key}")
        if action not in {"ask", "block"}:
            raise PolicyError(f"policy.defaults.violation_actions.{key}: expected 'ask' or 'block'")
        action_defaults[key] = action
    defaults = Defaults(unknown_action, strict_args, error_action, timeout_action, MappingProxyType(action_defaults))

    output_raw = _mapping(raw.get("output_inspection", {}), "policy.output_inspection")
    _keys(output_raw, {"enabled", "max_chars_per_chunk", "max_total_chars", "oversize_action", "json_max_depth", "json_max_strings", "actions", "mask_placeholder", "hold_placeholder", "session_judge_budget"}, "policy.output_inspection")
    enabled = _bool(output_raw.get("enabled", True), "policy.output_inspection.enabled")
    limits_out = {}
    for key, default in (("max_chars_per_chunk", 20000), ("max_total_chars", 200000), ("json_max_depth", 10), ("json_max_strings", 500)):
        value = output_raw.get(key, default)
        if type(value) is not int or value < (0 if key in {"json_max_depth", "json_max_strings"} else 1):
            raise PolicyError(f"policy.output_inspection.{key}: expected a valid non-negative integer")
        limits_out[key] = value
    oversize_action = _string(output_raw.get("oversize_action", "truncate"), "policy.output_inspection.oversize_action")
    if oversize_action not in {"truncate", "hold", "pass_marked"}:
        raise PolicyError("policy.output_inspection.oversize_action: expected truncate, hold, or pass_marked")
    action_defaults_out = {"none": "pass", "low": "pass", "medium": "pass", "high": "hold", "needs_review": "pass_marked", "unreviewed": "pass_marked", "scan_error": "hold"}
    actions_raw = _mapping(output_raw.get("actions", {}), "policy.output_inspection.actions")
    _keys(actions_raw, set(action_defaults_out), "policy.output_inspection.actions")
    valid_out_actions = {"none": {"pass"}, "low": {"pass"}, "medium": {"pass"}, "high": {"hold", "mask"}, "needs_review": {"pass_marked", "hold"}, "unreviewed": {"pass_marked", "hold"}, "scan_error": {"hold"}}
    for key, value in actions_raw.items():
        action = _string(value, f"policy.output_inspection.actions.{key}")
        if action not in valid_out_actions[key]:
            choices = ", ".join(sorted(valid_out_actions[key]))
            raise PolicyError(f"policy.output_inspection.actions.{key}: expected one of {choices}")
        action_defaults_out[key] = action
    mask_placeholder = _string(output_raw.get("mask_placeholder", "[removed: suspicious content]"), "policy.output_inspection.mask_placeholder", nonempty=False)
    hold_placeholder = _string(output_raw.get("hold_placeholder", "[Tool output withheld: suspicious content detected. Waiting for user review.]"), "policy.output_inspection.hold_placeholder", nonempty=False)
    budget = output_raw.get("session_judge_budget")
    if budget is not None and (type(budget) is not int or budget < 0):
        raise PolicyError("policy.output_inspection.session_judge_budget: expected a non-negative integer or null")
    output_inspection = OutputInspection(enabled, limits_out["max_chars_per_chunk"], limits_out["max_total_chars"], oversize_action,
                                         limits_out["json_max_depth"], limits_out["json_max_strings"],
                                         MappingProxyType(action_defaults_out), mask_placeholder, hold_placeholder, budget)

    link_raw = _mapping(raw.get("link_policy", {}), "policy.link_policy")
    link_policy = {risk: dict(cells) for risk, cells in _LINK_DEFAULTS.items()}
    _keys(link_raw, set(link_policy), "policy.link_policy")
    for risk, row_value in link_raw.items():
        path = f"policy.link_policy.{risk}"
        row = _mapping(row_value, path)
        _keys(row, {"none", "possible", "likely", "confirmed"}, path)
        for level, action in row.items():
            action = _string(action, f"{path}.{level}")
            if action not in {"allow", "allow_log", "ask", "block"}:
                raise PolicyError(f"{path}.{level}: expected allow, allow_log, ask, or block")
            if level == "none" and action == "block":
                raise PolicyError(f"{path}.none: block is not allowed")
            link_policy[risk][level] = action
    session_taint = _bool(raw.get("session_taint", True), "policy.session_taint")

    matching_raw = _mapping(raw.get("link_matching", {}), "policy.link_matching")
    _keys(matching_raw, set(_LINK_MATCHING_DEFAULTS), "policy.link_matching")
    matching = dict(_LINK_MATCHING_DEFAULTS)
    for name, value in matching_raw.items():
        path = f"policy.link_matching.{name}"
        if name in {"fuzzy_threshold", "shingle_containment_threshold"}:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or not 0 <= value <= 1:
                raise PolicyError(f"{path}: expected a number between 0 and 1")
            matching[name] = float(value)
        else:
            if type(value) is not int or value < 1:
                raise PolicyError(f"{path}: expected a positive integer")
            matching[name] = value
    if matching["min_shingles"] > 1000 or matching["shingle_size"] > 1000:
        raise PolicyError("policy.link_matching: shingle values must be at most 1000")

    verb_forms_raw = _mapping(raw.get("verb_forms", {}), "policy.verb_forms")
    verb_forms = {}
    for verb, forms in verb_forms_raw.items():
        if not verb.strip():
            raise PolicyError("policy.verb_forms: verb keys must not be empty")
        verb_forms[verb.casefold()] = tuple(value.casefold() for value in _string_list(forms, f"policy.verb_forms.{verb}"))

    return Policy(policy_version, agent_name, MappingProxyType(tools), limits,
                  MappingProxyType(categories), MappingProxyType(verb_to_tool), defaults, output_inspection,
                  MappingProxyType({risk: MappingProxyType(cells) for risk, cells in link_policy.items()}),
                  session_taint, MappingProxyType(matching), MappingProxyType(verb_forms), sensitivity, approval, loop_guard)


@dataclass(frozen=True)
class Policy:
    policy_version: str
    agent_name: str
    tools: Mapping[str, ToolPolicy]
    limits: Limits
    task_categories: Mapping[str, TaskCategory]
    verb_to_tool: Mapping[str, tuple[str, ...]]
    defaults: Defaults
    output_inspection: OutputInspection = field(default_factory=OutputInspection)
    link_policy: Mapping[str, Mapping[str, str]] = field(default_factory=lambda: MappingProxyType({risk: MappingProxyType(cells) for risk, cells in _LINK_DEFAULTS.items()}))
    session_taint: bool = True
    link_matching: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType(dict(_LINK_MATCHING_DEFAULTS)))
    verb_forms: Mapping[str, tuple[str, ...]] = field(default_factory=lambda: MappingProxyType({}))
    sensitivity: Sensitivity = field(default_factory=Sensitivity)
    approval: Approval = field(default_factory=Approval)
    loop_guard: LoopGuard = field(default_factory=LoopGuard)

    def get_tool(self, name: str) -> ToolPolicy | None:
        return self.tools.get(name)

    def has_tool(self, name: str) -> bool:
        return name in self.tools

    def arg_types(self, tool: str) -> Mapping[str, str]:
        spec = self.get_tool(tool)
        if spec is None:
            return MappingProxyType({})
        return MappingProxyType({name: arg.type for name, arg in spec.args.items()})


def load_policy(path: str | Path) -> Policy:
    """Load, strictly validate, and freeze a JSON or YAML policy file."""
    return _validate(_parse_file(Path(path)))


def policy_from_mapping(value: Mapping[str, Any]) -> Policy:
    """Validate a caller-provided mapping using the same schema as load_policy."""
    if not isinstance(value, Mapping):
        raise PolicyError("policy: expected a mapping")
    return _validate(dict(value))
