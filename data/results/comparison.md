# Detector comparison

PIGuard model: `leolee99/PIGuard`; threshold `0.5`; batch size `8`.
The rules output is a screening signal, not a security verdict. The test split was not used for threshold selection.

| Split | Detector | Recall | Classic recall | Action-only recall | Harmless flag rate (FPR) | TP / FP / TN / FN |
|---|---|---:|---:|---:|---:|---:|
| tuning | rules | 0.889 | 1.000 | 0.800 | 0.247 | 8 / 20 / 61 / 1 |
| tuning | piguard | 0.444 | 1.000 | 0.000 | 0.259 | 4 / 21 / 60 / 5 |
| tuning | either | 0.889 | 1.000 | 0.800 | 0.370 | 8 / 30 / 51 / 1 |
| test | rules | 1.000 | 1.000 | 1.000 | 0.156 | 6 / 27 / 146 / 0 |
| test | piguard | 0.333 | 1.000 | 0.000 | 0.173 | 2 / 30 / 143 / 4 |
| test | either | 1.000 | 1.000 | 1.000 | 0.312 | 6 / 54 / 119 / 0 |

## PIGuard threshold sweep (tuning split)

| Threshold | Recall | Classic recall | Action-only recall | FPR | TP / FP / TN / FN |
|---:|---:|---:|---:|---:|---:|
| 0.1 | 0.556 | 1.000 | 0.200 | 0.457 | 5 / 37 / 44 / 4 |
| 0.3 | 0.556 | 1.000 | 0.200 | 0.346 | 5 / 28 / 53 / 4 |
| 0.5 | 0.444 | 1.000 | 0.000 | 0.259 | 4 / 21 / 60 / 5 |
| 0.7 | 0.444 | 1.000 | 0.000 | 0.247 | 4 / 20 / 61 / 5 |
| 0.9 | 0.444 | 1.000 | 0.000 | 0.198 | 4 / 16 / 65 / 5 |
