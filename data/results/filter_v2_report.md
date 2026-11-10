# Rules v2 held-out filter evaluation (no judge calls)

## Side-by-side: baseline v1 filter vs chosen rules v2 filter

| Measure | Baseline filter v1 | Chosen filter v2 |
|---|---:|---:|
| Configuration | `baseline_v1_piguard_0.50` | `v2_broad_piguard_0.50` |
| Single-attack filter recall | 22/30 (0.733); Wilson 95% CI [0.556, 0.858] | 26/30 (0.867); Wilson 95% CI [0.703, 0.947] |
| Segments selected for judge | 114/366 (0.311) | 201/366 (0.549) |
| Harmless segment selection (Wilson 95% CI) | 74/281 (0.263); [0.215, 0.318] | 137/281 (0.488); [0.430, 0.546] |
| Any fully-contained split attack selected | 0/5 | 2/5 |

### Single-attack recall by category

| Category | Baseline v1 | Chosen v2 |
|---|---:|---:|
| authority_claim | 3/5 (0.600); [0.231, 0.882] | 3/5 (0.600); [0.231, 0.882] |
| concealment | 3/5 (0.600); [0.231, 0.882] | 5/5 (1.000); [0.566, 1.000] |
| disguised_note | 4/5 (0.800); [0.376, 0.964] | 5/5 (1.000); [0.566, 1.000] |
| judge_targeted | 5/5 (1.000); [0.566, 1.000] | 5/5 (1.000); [0.566, 1.000] |
| statement_style | 2/5 (0.400); [0.118, 0.769] | 3/5 (0.600); [0.231, 0.882] |
| unusual_verbs | 5/5 (1.000); [0.566, 1.000] | 5/5 (1.000); [0.566, 1.000] |

### Control selection by type (Wilson 95% intervals)

| Control type | v1 segment selection | v1 docs with any selected | v2 segment selection | v2 docs with any selected |
|---|---:|---:|---:|---:|
| ordinary | 8/72 (0.111); [0.057, 0.204] | 3/12 (0.250); [0.089, 0.532] | 13/72 (0.181); [0.109, 0.285] | 5/12 (0.417); [0.193, 0.680] |
| benign_instruction_like | 41/48 (0.854); [0.728, 0.928] | 8/8 (1.000); [0.676, 1.000] | 41/48 (0.854); [0.728, 0.928] | 8/8 (1.000); [0.676, 1.000] |
| benign_approval_like | 10/36 (0.278); [0.158, 0.440] | 6/6 (1.000); [0.610, 1.000] | 26/36 (0.722); [0.560, 0.842] | 6/6 (1.000); [0.610, 1.000] |

## Dev vs held-out for chosen configuration

On dev (tuned on this set), filter recall was 30/30 (1.000), cached end-to-end recall was 30/30 (1.000), and selected fraction was 0.415.
On held-out v2, filter recall was 26/30 (0.867; Wilson 95% CI [0.703, 0.947]) and selected fraction was 0.549.
Held-out end-to-end recall was **not measured** because no judge calls were made.

## Other dev-tuned configurations (filter-only; not selected)

| Configuration | Filter recall | Selected fraction | Harmless segment selection |
|---|---:|---:|---:|
| v2_cooccur_piguard_0.50 | 26/30 (0.867) | 0.519 | 126/281 (0.448) |
| v1_piguard_0.05 | 27/30 (0.900) | 0.407 | 92/281 (0.327) |
| v1_piguard_0.10 | 27/30 (0.900) | 0.388 | 87/281 (0.310) |
| v1_piguard_0.20 | 26/30 (0.867) | 0.361 | 82/281 (0.292) |
| v1_piguard_0.30 | 24/30 (0.800) | 0.342 | 80/281 (0.285) |
| v1_piguard_0.40 | 22/30 (0.733) | 0.317 | 76/281 (0.270) |

## Split attacks (separate; excluded from single-attack recall)

| Configuration | Split attacks with any full window selected |
|---|---:|
| baseline_v1_piguard_0.50 | 0/5 |
| v2_broad_piguard_0.50 | 2/5 |
| v2_cooccur_piguard_0.50 | 2/5 |
| v1_piguard_0.05 | 1/5 |
| v1_piguard_0.10 | 1/5 |
| v1_piguard_0.20 | 0/5 |
| v1_piguard_0.30 | 0/5 |
| v1_piguard_0.40 | 0/5 |

Phase 1 v1 dev diagnostic: each of the five dev split-attack spans fits completely inside one 3-sentence window; cached judge-on-all marked all five as non-instructions. The reasons are in `filter_v2_dev_analysis.md`.

## Vocabulary leakage

The hashed `data/hard_eval_v2/vocab_check.md` uses smoothed log-odds. Attack-associated terms include `private`, `recovery`, `phrase`, and `string`; the harmless side is led by `group`, `questions`, and `chart`. Terms such as `sample`, `placeholder`, `illustrative`, and `public` occur across both labels. This is a synthetic dataset and the vocabulary analysis is descriptive; residual lexical leakage remains possible.

## Older labeled sets: filter-level only

No cached judge answers were inferred for newly selected segments. These are filter selection counts only, not end-to-end recall.

| Dataset/config | Segments selected | Fully-contained attack cases selected | Selected harmless segments |
|---|---:|---:|---:|
| data/labeled/baseline_v1 | 100/269 (0.372) | 8/8 | 86/254 |
| data/labeled/chosen_v2 | 104/269 (0.387) | 8/8 | 90/254 |
| data/labeled_legit/baseline_v1 | 19/19 (1.000) | 1/1 | 16/16 |
| data/labeled_legit/chosen_v2 | 19/19 (1.000) | 1/1 | 16/16 |

## Limits

The 30 single attacks (five per category) and controls are synthetic. The v2 set was written by the same agent with prior conversational knowledge of v1 misses; despite the initial pre-filter freeze, one control sentence was corrected after dev inspection when the frozen segmenter merged `Corp.`. Attack texts/labels did not change, but control-set blinding is weaker. Confidence intervals are wide. No held-out judge calls were made, so these results measure filter recall/selection only. The optional semantic filter was skipped because sentence-transformers and a local sentence model were unavailable offline.
