# Ground-truth label correction: old vs full containment

Old labels counted any overlap with an inserted span as attack. New labels count a segment as attack only when it fully contains the inserted span; partial overlaps are excluded from recall/FPR denominators. Per-attack recall counts each inserted attack once if any fully containing segment is flagged.

| Split | Labeling | Detector | Attack segments | Harmless segments | Partial segments | Segment recall | False-flag rate | Per-attack flagged | TP / FP / TN / FN |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| tuning | old overlap | rules | 9 | 81 | 0 | 0.889 | 0.247 | 4/4 | 8 / 20 / 61 / 1 |
| tuning | old overlap | piguard | 9 | 81 | 0 | 0.444 | 0.259 | 2/4 | 4 / 21 / 60 / 5 |
| tuning | old overlap | judge | 9 | 81 | 0 | 0.889 | 0.049 | 4/4 | 8 / 4 / 77 / 1 |
| tuning | old overlap | day2_any | 9 | 81 | 0 | 0.889 | 0.370 | 4/4 | 8 / 30 / 51 / 1 |
| tuning | old overlap | day3_any | 9 | 81 | 0 | 0.889 | 0.370 | 4/4 | 8 / 30 / 51 / 1 |
| tuning | new full | rules | 8 | 81 | 1 | 1.000 | 0.247 | 4/4 | 8 / 20 / 61 / 0 |
| tuning | new full | piguard | 8 | 81 | 1 | 0.500 | 0.259 | 2/4 | 4 / 21 / 60 / 4 |
| tuning | new full | judge | 8 | 81 | 1 | 1.000 | 0.049 | 4/4 | 8 / 4 / 77 / 0 |
| tuning | new full | day2_any | 8 | 81 | 1 | 1.000 | 0.370 | 4/4 | 8 / 30 / 51 / 0 |
| tuning | new full | day3_any | 8 | 81 | 1 | 1.000 | 0.370 | 4/4 | 8 / 30 / 51 / 0 |
| test | old overlap | rules | 6 | 173 | 0 | 1.000 | 0.168 | 4/4 | 6 / 29 / 144 / 0 |
| test | old overlap | piguard | 6 | 173 | 0 | 0.333 | 0.173 | 2/4 | 2 / 30 / 143 / 4 |
| test | old overlap | judge | 6 | 173 | 0 | 1.000 | 0.040 | 4/4 | 6 / 7 / 166 / 0 |
| test | old overlap | day2_any | 6 | 173 | 0 | 1.000 | 0.324 | 4/4 | 6 / 56 / 117 / 0 |
| test | old overlap | day3_any | 6 | 173 | 0 | 1.000 | 0.324 | 4/4 | 6 / 56 / 117 / 0 |
| test | new full | rules | 6 | 173 | 0 | 1.000 | 0.168 | 4/4 | 6 / 29 / 144 / 0 |
| test | new full | piguard | 6 | 173 | 0 | 0.333 | 0.173 | 2/4 | 2 / 30 / 143 / 4 |
| test | new full | judge | 6 | 173 | 0 | 1.000 | 0.040 | 4/4 | 6 / 7 / 166 / 0 |
| test | new full | day2_any | 6 | 173 | 0 | 1.000 | 0.324 | 4/4 | 6 / 56 / 117 / 0 |
| test | new full | day3_any | 6 | 173 | 0 | 1.000 | 0.324 | 4/4 | 6 / 56 / 117 / 0 |

## Partial segments excluded by the new labels

- **tuning:** 1 partial segment(s): doc_10_product_catalog-w3-0028 (doc_10_product_catalog).
- **test:** 0 partial segment(s): none.

Attack-level scores count each inserted attack once. Segment-level denominators differ because sentence windows overlap. The corpus is small; counts are shown with every rate.
