from types import SimpleNamespace

from firewall.lint import lint_policy
from firewall.policy import load_policy


class _Attr(SimpleNamespace):
    pass


def _policy(*, clean=False):
    if clean:
        tools = {"safe_action": _Attr(side_effects=True, args={}, egress={"args": ("destination",)},
            output_sensitivity="confidential", risk="high", always_ask=True)}
        link_policy = {"high": {"possible": "ask"}, "medium": {"possible": "ask"}}
        return _Attr(tools=tools, limits=_Attr(internal_domains=("internal.example.com",),
                    allowed_recipient_domains=()), sensitivity=_Attr(enabled=True),
                    loop_guard=_Attr(max_blocked_per_session=4), task_categories={"tasks": object()},
                    defaults=_Attr(unknown_tool_action="block"), link_policy=link_policy)
    tool_high = _Attr(side_effects=True, args={"to": _Attr(type="recipient")}, egress={},
                      output_sensitivity="none", risk="high", always_ask=False)
    tool_medium = _Attr(side_effects=True, args={}, egress={"args": ("payload",)}, output_sensitivity="none",
                        risk="medium", always_ask=False)
    return _Attr(tools={"high_action": tool_high, "medium_action": tool_medium},
                 limits=_Attr(internal_domains=(), allowed_recipient_domains=()),
                 sensitivity=_Attr(enabled=False), loop_guard=None, task_categories={},
                 defaults=_Attr(unknown_tool_action="allow"),
                 link_policy={"high": {"possible": "allow"}, "medium": {"possible": "allow_log"}})


def test_each_policy_linter_warning_code_is_represented():
    codes = {warning.code for warning in lint_policy(_policy())}
    assert codes == {
        "W_NO_EGRESS_DECLARED", "W_UNLABELED_OUTPUT", "W_HIGH_RISK_NO_ALWAYS_ASK",
        "W_LINK_MEDIUM_POSSIBLE_LOGGED", "W_NO_INTERNAL_DOMAINS", "W_SENSITIVITY_DISABLED",
        "W_NO_LOOP_GUARD", "W_TASK_CATEGORIES_MISSING", "W_UNKNOWN_TOOL_ALLOWED",
    }


def test_clean_policy_has_no_warnings():
    assert lint_policy(_policy(clean=True)) == []


def test_linter_does_not_raise_for_valid_loaded_policy():
    policy = load_policy("policies/example_agent.yaml")
    assert isinstance(lint_policy(policy), list)


def test_warning_messages_do_not_contain_argument_values():
    sample_value = "sensitive-placeholder-9281"
    policy = _policy()
    policy.tools["high_action"].args["to"] = _Attr(type="recipient", value=sample_value)
    assert all(sample_value not in warning.message for warning in lint_policy(policy))
