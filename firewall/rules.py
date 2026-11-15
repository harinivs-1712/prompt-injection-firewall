"""Composable deterministic checks; all details are safe metadata only."""
from __future__ import annotations

import fnmatch
import re

from firewall.arg_types import accepts_value, get_validator
from firewall.cleaning import domain_of, is_domain_allowed, normalize_account, normalize_amount, normalize_path, normalize_recipient, normalize_url, path_is_under
from firewall.decision import Action, Decision, ReasonCode
from firewall.linking import find_links
from firewall.sensitivity import check_sensitivity


def _decision(action, reason, message, rule):
    return Decision(action, (reason,), message, rule_id=rule)


def check_task_permission(firewall, session, tool_name, args):
    if session.allowed_tools is not None:
        allowed = tool_name in session.allowed_tools
        session.task_permission_source = "host"
        if allowed:
            return None
        return _decision(Action(firewall.policy.defaults.violation_actions["task"]), ReasonCode.TOOL_NOT_ALLOWED_FOR_TASK,
                         "The tool is outside the host-provided task permissions.", "R-TASK")
    task = session.user_task.casefold()
    categories = []
    permitted = set()
    for name, category in firewall.policy.task_categories.items():
        if any(re.search(r"(?<!\w)" + re.escape(keyword.casefold()) + r"(?!\w)", task) for keyword in category.keywords):
            categories.append(name)
            permitted.update(category.allowed_tools)
    if categories:
        session.task_permission_source = "policy_keywords"
        session.matched_task_categories = tuple(categories)
        if tool_name in permitted:
            return None
        return _decision(Action(firewall.policy.defaults.violation_actions["task"]), ReasonCode.TOOL_NOT_ALLOWED_FOR_TASK,
                           "The requested tool does not match the task categories.", "R-TASK")
    session.task_permission_source = "fallback"
    tool = firewall.policy.get_tool(tool_name)
    if tool and tool.risk == "low" and not tool.side_effects:
        return None
    return _decision(Action(firewall.policy.defaults.violation_actions["task"]), ReasonCode.TOOL_NOT_ALLOWED_FOR_TASK,
                     "The task did not authorize this tool.", "R-TASK")


def check_argument_values(firewall, session, tool_name, args):
    tool = firewall.policy.get_tool(tool_name)
    for name, spec in tool.args.items():
        if name not in args:
            continue
        value = args[name]
        validator = get_validator(spec.type)
        normalized, violation = validator.validate(value, spec, firewall.policy.limits)
        if violation:
            code = ReasonCode(violation)
            return _decision(Action(firewall.policy.defaults.violation_actions["value"]), code,
                             "An argument value violates its declared constraints.", "R-ARGVALUES")
        if spec.type == "recipient":
            values = normalized if isinstance(normalized, list) else [normalized]
            for recipient in values:
                domain = domain_of(recipient)
                exact = bool(firewall.policy.limits.allowed_recipients and recipient not in firewall.policy.limits.allowed_recipients)
                allowed = (not exact or recipient in firewall.policy.limits.allowed_recipients) and (
                    not firewall.policy.limits.allowed_recipient_domains or is_domain_allowed(
                        domain, firewall.policy.limits.allowed_recipient_domains, firewall.policy.limits.allow_subdomains))
                if not allowed:
                    code = ReasonCode.RECIPIENT_NOT_ALLOWED if exact else ReasonCode.DOMAIN_NOT_ALLOWED
                    return _decision(Action(firewall.policy.defaults.violation_actions["recipient"]), code,
                                     "The recipient is outside policy limits.", "R-ARGVALUES")
        elif spec.type == "account" and firewall.policy.limits.allowed_accounts:
            if normalized not in firewall.policy.limits.allowed_accounts:
                return _decision(Action(firewall.policy.defaults.violation_actions["account"]), ReasonCode.ACCOUNT_NOT_ALLOWED,
                                 "The account is outside policy limits.", "R-ARGVALUES")
        elif spec.type == "amount":
            if normalized <= 0:
                return _decision(Action.BLOCK, ReasonCode.INVALID_ARGUMENT_VALUE, "The amount must be greater than zero.", "R-ARGVALUES")
            maximum = firewall.policy.limits.max_amount
            if maximum is not None and normalized > maximum:
                return _decision(Action(firewall.policy.defaults.violation_actions["amount"]), ReasonCode.AMOUNT_OVER_LIMIT,
                                 "The amount exceeds the policy limit.", "R-ARGVALUES")
        elif spec.type == "path":
            if any(fnmatch.fnmatchcase(normalized, pattern) for pattern in firewall.policy.limits.blocked_path_patterns):
                return _decision(Action.BLOCK, ReasonCode.PATH_NOT_ALLOWED, "The path matches a blocked policy pattern.", "R-ARGVALUES")
            if firewall.policy.limits.allowed_path_prefixes and not path_is_under(normalized, firewall.policy.limits.allowed_path_prefixes):
                return _decision(Action(firewall.policy.defaults.violation_actions["path"]), ReasonCode.PATH_NOT_ALLOWED,
                                 "The path is outside policy limits.", "R-ARGVALUES")
        elif spec.type == "url" and firewall.policy.limits.allowed_url_domains:
            if not is_domain_allowed(domain_of(normalized), firewall.policy.limits.allowed_url_domains):
                return _decision(Action(firewall.policy.defaults.violation_actions["url"]), ReasonCode.URL_NOT_ALLOWED,
                                 "The URL domain is outside policy limits.", "R-ARGVALUES")
    return None


def check_always_ask(firewall, session, tool_name, args):
    tool = firewall.policy.get_tool(tool_name)
    if tool.always_ask:
        return Decision.ask((ReasonCode.ALWAYS_ASK_TOOL,), "This tool requires user approval.", rule_id="R-ALWAYSASK")
    return None


def check_link(firewall, session, tool_name, args):
    try:
        report = find_links(session, firewall.policy, tool_name, args)
        session.last_link_report = report
        tool = firewall.policy.get_tool(tool_name)
        risk = tool.risk if tool is not None else "high"
        action = firewall.policy.link_policy[risk][report.link_level.casefold()]
        if "LINK_SCAN_LIMIT" in report.reason_codes and action in {"allow", "allow_log"}:
            action = "ask"
        codes = tuple(ReasonCode(code) for code in report.reason_codes)
        if action == "allow_log":
            codes = tuple(dict.fromkeys((*codes, ReasonCode.LINK_LOGGED)))
            return Decision.allow(codes, "Linked content was recorded for audit.", rule_id="R-LINK")
        if action == "allow":
            return Decision.allow(codes, "No linking rule requires a stronger action.", rule_id="R-LINK")
        if not codes:
            codes = (ReasonCode.SESSION_TAINTED_HIGH_RISK,)
        return Decision(Action.ASK if action == "ask" else Action.BLOCK, codes,
                        "The tool call is linked to suspicious or unreviewed content.", rule_id="R-LINK")
    except Exception:
        session.last_link_report = None
        return Decision.ask((ReasonCode.INTERNAL_ERROR,), "A security check could not be completed.", rule_id="R-LINK")


def check_sensitive_egress(firewall, session, tool_name, args):
    try:
        return check_sensitivity(firewall, session, tool_name, args)
    except Exception:
        return Decision.block((ReasonCode.INTERNAL_ERROR,), "A security check could not be completed.", rule_id="R-SENS")

CHECK_FUNCTIONS = (check_task_permission, check_argument_values, check_always_ask, check_link, check_sensitive_egress)


def combine_decisions(results, *, checks_run=None):
    objections = [item for item in results if item is not None]
    checks_run = tuple(checks_run or ("R-TASK", "R-ARGVALUES", "R-ALWAYSASK", "R-LINK"))
    if not objections:
        return Decision.allow((ReasonCode.ALL_RULES_PASSED,), "All deterministic checks passed.",
                              rule_ids=checks_run)
    rank = {Action.ALLOW: 0, Action.ASK: 1, Action.BLOCK: 2}
    action = max((item.action for item in objections), key=rank.get)
    codes = tuple(dict.fromkeys(code for item in objections for code in item.reason_codes))
    if action is Action.ALLOW:
        codes = tuple(dict.fromkeys((*codes, ReasonCode.ALL_RULES_PASSED)))
    ids = tuple(dict.fromkeys((*checks_run, *(rule for item in objections for rule in item.rule_ids))))
    return Decision(action, codes, "; ".join(dict.fromkeys(item.message for item in objections if item.action is action)),
                    rule_id=ids[0] if len(ids) == 1 else None, rule_ids=ids)
