# Writing a policy for a new agent

Policies define the agent's tool surface and limits. The engine code should remain agent-agnostic.

1. **List tools.** Name every operation the host can execute and describe it in plain language.
2. **Assign risk and side effects.** Choose low, medium, or high. Mark whether the operation changes or sends data. Set `always_ask` when every call needs review.
3. **Type each argument.** Use a registered type such as `recipient`, `amount`, `path`, `url`, `identifier`, `free_text`, `integer`, `number`, `enum`, or `text_pattern`. A host can register a custom validator.
4. **Set limits and constraints.** Configure allowed recipients/domains, path prefixes, blocked path patterns, amount limits, numeric bounds, allowed enum values, regex patterns, and maximum text lengths. Keep values in the trusted policy file.
5. **Define egress and confidential output handling.** Mark which arguments leave the system and which arguments identify destinations. Label confidential tool outputs, configure sensitivity mode, and set internal domains.
6. **Define task categories.** Map task keywords to allowed tools. Set `verb_to_tool` for action-intent matching.
7. **Set `link_policy`.** Choose what possible, likely, and confirmed links to untrusted segments mean at each tool risk level. Defaults allow a possible link on a medium-risk tool with a log entry; consider whether that suits the agent.
8. **Configure approval and loop guard.** Choose timeout, preview length, deny behavior, and bounded retry limits.
9. **Write traces.** Add at least five normal and five attack traces to the harness, run the offline evaluation, and inspect decisions and fake-tool logs before connecting real tools.

Start with the commented [policy template](../policies/policy_template.yaml) and validate it with:

```powershell
python -c "from firewall.policy import load_policy; load_policy('policies/policy_template.yaml'); print('valid')"
python -m firewall.lint policies/policy_template.yaml
```

The linter reports advisory gaps only. It does not change, reject, or rewrite a policy.
The checked-in [example lint report](lint_report.md) records its warnings for all three example policies and this template.
