# Layer 2 hard-rule engine: offline harness results

Each trace is a hand-written example, not a statistical benchmark. The fake tools only write tool and argument names in a temporary directory. ‘Approve asks’ executes every ASK result to show the effect of user approval.

| Policy | Mode | Normal traces executed | Attack traces executed |
|---|---|---:|---:|
| example_agent | no defense | 4/4 | 4/4 |
| example_agent | deny asks | 3/4 | 0/4 |
| example_agent | approve asks | 4/4 | 2/4 |
| example_files_agent | no defense | 4/4 | 4/4 |
| example_files_agent | deny asks | 2/4 | 0/4 |
| example_files_agent | approve asks | 4/4 | 2/4 |
| example_support_agent | no defense | 4/4 | 4/4 |
| example_support_agent | deny asks | 3/4 | 0/4 |
| example_support_agent | approve asks | 4/4 | 0/4 |

The rules are deterministic and policy-driven. This harness does not use Layer 1 content analysis, a model judge, network access, or real side effects.
