"""Advisory policy checks. Warnings never prevent policy loading."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from firewall.policy import Policy, load_policy


@dataclass(frozen=True)
class Warning:
    code: str
    tool: str | None
    message: str


def lint_policy(policy: Policy) -> list[Warning]:
    warnings: list[Warning] = []
    egress_tools = []
    for name, tool in policy.tools.items():
        has_destination = any(arg.type in {"recipient", "url", "account"} for arg in tool.args.values())
        is_egress = bool(tool.egress)
        if (tool.side_effects or has_destination) and not is_egress:
            warnings.append(Warning("W_NO_EGRESS_DECLARED", name,
                                    "Side effects or destination arguments are present without an egress declaration."))
        if is_egress:
            egress_tools.append(name)
        if tool.output_sensitivity == "none":
            warnings.append(Warning("W_UNLABELED_OUTPUT", name,
                                    "Tool outputs default to no sensitivity; explicitly label confidential outputs."))
        strict_link_cell = policy.link_policy.get(tool.risk, {}).get("possible") in {"ask", "block"}
        if tool.risk == "high" and tool.side_effects and not tool.always_ask and not strict_link_cell:
            warnings.append(Warning("W_HIGH_RISK_NO_ALWAYS_ASK", name,
                                    "High-risk side effects have neither always_ask nor a stricter possible-link rule."))
        if tool.risk == "medium" and policy.link_policy.get("medium", {}).get("possible") == "allow_log":
            warnings.append(Warning("W_LINK_MEDIUM_POSSIBLE_LOGGED", name,
                                    "Possible links on medium-risk tools are allowed with logging."))
    if egress_tools and not (policy.limits.internal_domains or policy.limits.allowed_recipient_domains):
        warnings.append(Warning("W_NO_INTERNAL_DOMAINS", None,
                                "Egress tools exist but no internal or allowed-recipient domains are configured."))
    if not policy.sensitivity.enabled:
        warnings.append(Warning("W_SENSITIVITY_DISABLED", None, "Confidential-data sensitivity checks are disabled."))
    if policy.loop_guard is None or policy.loop_guard.max_blocked_per_session <= 0:
        warnings.append(Warning("W_NO_LOOP_GUARD", None, "No effective session loop guard is configured."))
    if not policy.task_categories:
        warnings.append(Warning("W_TASK_CATEGORIES_MISSING", None,
                                "No task categories exist; fallback permits only low-risk, no-side-effect tools."))
    if policy.defaults.unknown_tool_action not in {"ask", "block"}:
        warnings.append(Warning("W_UNKNOWN_TOOL_ALLOWED", None,
                                "Unknown tools are not configured to ask or block."))
    return warnings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
    except Exception as exc:
        print(f"Could not load policy: {type(exc).__name__}")
        return 1
    findings = lint_policy(policy)
    if args.json:
        print(json.dumps([asdict(item) for item in findings], indent=2))
    elif findings:
        for item in findings:
            suffix = f" ({item.tool})" if item.tool else ""
            print(f"{item.code}{suffix}: {item.message}")
    else:
        print("No policy warnings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
