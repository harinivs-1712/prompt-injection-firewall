# Day 3 detector comparison


PIGuard threshold: 0.5; judge model: gemini-3.1-flash-lite; prompt: v1.
Judge errors count as flagged by the combined detector and require review.

| Split | Detector | Recall | Classic recall | Action-only recall | False-flag rate | TP / FP / TN / FN | Judge API calls | Judge time (s) | Judge coverage |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| tuning | rules | 0.889 | 1.000 | 0.800 | 0.247 | 8 / 20 / 61 / 1 | 38 | 303.83 | 0.422 |
| tuning | piguard | 0.444 | 1.000 | 0.000 | 0.259 | 4 / 21 / 60 / 5 | 38 | 303.83 | 0.422 |
| tuning | judge | 0.889 | 1.000 | 0.800 | 0.049 | 8 / 4 / 77 / 1 | 38 | 303.83 | 0.422 |
| tuning | combined | 0.889 | 1.000 | 0.800 | 0.370 | 8 / 30 / 51 / 1 | 38 | 303.83 | 0.422 |
| test | rules | 1.000 | 1.000 | 1.000 | 0.168 | 6 / 29 / 144 / 0 | 62 | 364.12 | 0.346 |
| test | piguard | 0.333 | 1.000 | 0.000 | 0.173 | 2 / 30 / 143 / 4 | 62 | 364.12 | 0.346 |
| test | judge | 1.000 | 1.000 | 1.000 | 0.040 | 6 / 7 / 166 / 0 | 62 | 364.12 | 0.346 |
| test | combined | 1.000 | 1.000 | 1.000 | 0.324 | 6 / 56 / 117 / 0 | 62 | 364.12 | 0.346 |

## Content-dependent tasks (known hard case)

Legitimate-instruction false flags: 0/16 judged legitimate-only segments (0.000). In the injected-attack document, 3/3 judged attack-overlapping segments were flagged or errored.

