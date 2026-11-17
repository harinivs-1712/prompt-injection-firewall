# Layer 1 package move equivalence report

The original `layers/` package was moved with `git mv` to `firewall/layer1/`. No push, reset, rebase, merge, or deletion was performed.

## Equivalence checks

| Check | Result | Evidence |
|---|---|---|
| moved-file content | PASS | 12 files normalize to tagged originals; import/path/manifest-only differences. |
| Layer 1 constants and defaults | PASS | judge prompts/models, rule lists, suspicion levels, scan/segment defaults compare to baseline. |
| full pytest run 1/3 | FAIL | ================== 1 failed, 6 passed, 2 warnings in 25.62s =================== |

## Moved-file mapping

| Old path | New path | Change |
|---|---|---|
| `layers/__init__.py` | `firewall/layer1/__init__.py` | identical |
| `layers/instruction_rule_router.py` | `firewall/layer1/instruction_rule_router.py` | import-only changed |
| `layers/instruction_rules.py` | `firewall/layer1/instruction_rules.py` | identical |
| `layers/instruction_rules_v2.py` | `firewall/layer1/instruction_rules_v2.py` | import-only changed |
| `layers/judge.py` | `firewall/layer1/judge.py` | identical |
| `layers/labeling.py` | `firewall/layer1/labeling.py` | identical |
| `layers/piguard_scorer.py` | `firewall/layer1/piguard_scorer.py` | identical |
| `layers/scan.py` | `firewall/layer1/scan.py` | import-only changed |
| `layers/scan_cli.py` | `firewall/layer1/scan_cli.py` | import-only changed |
| `layers/segmenter.py` | `firewall/layer1/segmenter.py` | import-only changed |
| `layers/suspicion.py` | `firewall/layer1/suspicion.py` | identical |
| `layers/threat_store.py` | `firewall/layer1/threat_store.py` | import-only changed |

Changed files contain only normalized import changes, approved project-root/manifest path changes, or the required manifest-verification update. The new `firewall/layer1/_paths.py` is support code and has no old counterpart.

## Edited test files

- `tests/test_detectors.py`: Updated Layer 1 imports to firewall.layer1.
- `tests/test_filter_v2.py`: Updated Layer 1 imports to firewall.layer1.
- `tests/test_firewall_day5.py`: Updated the import-hygiene target from legacy layers modules to firewall.layer1.
- `tests/test_firewall_day7.py`: Updated lazy fake-module injection targets to firewall.layer1.scan.
- `tests/test_hard_eval.py`: Moved the temporary manifest fixture paths to firewall/layer1.
- `tests/test_judge_pipeline.py`: Updated Layer 1 imports to firewall.layer1.
- `tests/test_layer2_eval.py`: Updated the fake judge import/patch target to firewall.layer1.judge.
- `tests/test_scan.py`: Updated Layer 1 imports to firewall.layer1.
- `tests/test_segmenter.py`: Updated the segmenter import to firewall.layer1.
- `tests/test_threat_store.py`: Updated Layer 1 imports to firewall.layer1.
- `tests/test_layer1_move.py`: Added path discovery, compatibility warning, and module-identity regression tests.

## Commands run

- `venv\Scripts\python.exe -X dev -m pytest -v -x --durations=25 (three runs)`
- `venv\Scripts\python.exe tools\verify_move.py`
- `venv\Scripts\python.exe -m harness.eval_layer2 --manifest config\layer2_eval_manifest_v2.json (outputs redirected to a temporary directory)`
- `python -m firewall.layer1.scan_cli ... (from a different working directory)`
- `python -m layers.scan_cli ... (from a different working directory)`

## Notes

- API/Gemini access was disabled via environment and cache-only code paths; no live judge was constructed.
- Pytest reports the same baseline skips; `pytest-timeout` is unavailable in this environment, so pytest emits its existing unknown timeout-option warnings. The outer runner applied a 900-second process guard.
- The old Layer 1 manifest remains as provenance; `config/layer1_manifest_v2.json` now verifies the relocated source files.
- The deprecated top-level `layers/` shim preserves legacy imports and module execution.
