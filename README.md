# Prompt Injection Firewall

## Running tests offline

Install development dependencies with `python -m pip install -r requirements-dev.txt` so pytest-timeout is available. The test configuration enables offline Hugging Face/Transformers mode, a 120-second test timeout, and a 100-second faulthandler dump.

- Full suite: `python -X dev -m pytest`
- Firewall suite: `python -X dev -W error::ResourceWarning -m pytest tests/test_firewall_day5.py tests/test_firewall_day6.py tests/test_firewall_day7.py tests/test_firewall_day8.py tests/test_firewall_day9.py`
- Layer 1 and evaluation suite: `python -X dev -m pytest tests/test_detectors.py tests/test_filter_v2.py tests/test_hard_eval.py tests/test_judge_pipeline.py tests/test_scan.py tests/test_segmenter.py tests/test_threat_store.py`
- Real Layer 1 cache-only integration: set `RUN_LAYER1_INTEGRATION=1`, `HF_HUB_OFFLINE=1`, and `TRANSFORMERS_OFFLINE=1`, then run `python -X dev -m pytest tests/test_firewall_day7.py::test_optional_real_layer1_adapter_integration -m integration`.

The integration test only uses local model files and cached judge answers. Missing cached judge answers remain unreviewed; the test never calls a hosted judge.
