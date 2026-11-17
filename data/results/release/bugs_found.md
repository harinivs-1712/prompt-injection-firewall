# Bugs and compatibility findings

## Resolved verification compatibility issue

The legacy held-out Layer 1 and rule-v2 freeze checks hashed the original `layers/` source files byte-for-byte. The package move correctly changed imports and the project-root resolver, so these unchanged evaluation checkers incorrectly reported a frozen-source mismatch. Their checks now consult `config/layer1_manifest_v2.json` and substitute the recorded pre-move hash only when the current relocated file matches its recorded post-move hash. The old frozen manifests and evaluation outputs were not edited. This changes freeze-check bookkeeping only; detector and firewall decisions are unchanged.

## Existing frozen Day 10 issue

The frozen Day 10 report records an audit validation defect: some provenance evidence with no argument name is rejected, causing metadata-only audit events to be lost. The Day 10 firewall behavior and report remain frozen; this release does not change that behavior. Details and counts remain in [`data/results/layer2_eval/bugs_found.md`](../layer2_eval/bugs_found.md).

No other issue has been confirmed in the checks run so far. This file will be updated with the final verification outcome.
