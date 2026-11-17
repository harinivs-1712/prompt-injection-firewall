"""Replay the frozen Day 10 evaluation into a temporary directory only."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _strip_metadata(value):
    ignored = {"timestamp", "created_at", "updated_at", "git_commit", "firewall_sha256",
               "manifest_sha256", "manifest_hash", "manifest_warnings"}
    if isinstance(value, dict):
        return {key: _strip_metadata(item) for key, item in value.items() if key not in ignored}
    if isinstance(value, list):
        return [_strip_metadata(item) for item in value]
    return value


def main() -> int:
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ.pop("GEMINI_API_KEY", None)
    import harness.eval_layer2 as evaluation

    baseline = json.loads((ROOT / "data" / "results" / "refactor" / "baseline.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="day10-release-replay-") as temporary:
        old_results = evaluation.RESULTS_DIR
        evaluation.RESULTS_DIR = Path(temporary)
        try:
            status = evaluation.main(["--manifest", "config/layer2_eval_manifest_v2.json", "--allow-changed"])
            csv_hash = hashlib.sha256((Path(temporary) / "per_trace.csv").read_bytes()).hexdigest()
            result = json.loads((Path(temporary) / "results.json").read_text(encoding="utf-8"))
            result_hash = hashlib.sha256(json.dumps(_strip_metadata(result), sort_keys=True,
                                                    separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        finally:
            evaluation.RESULTS_DIR = old_results
    expected = baseline["day10_fingerprint"]
    passed = status == 0 and csv_hash == expected["per_trace_csv_sha256"] and result_hash == expected["stripped_results_json_sha256"]
    report = ["# Day 10 temporary replay", "", "| Check | Result | Detail |", "|---|---|---|",
              f"| evaluator status | {'PASS' if status == 0 else 'FAIL'} | {status} |",
              f"| per_trace.csv SHA-256 | {'PASS' if csv_hash == expected['per_trace_csv_sha256'] else 'FAIL'} | {csv_hash} |",
              f"| metadata-stripped results SHA-256 | {'PASS' if result_hash == expected['stripped_results_json_sha256'] else 'FAIL'} | {result_hash} |"]
    text = "\n".join(report) + "\n"
    (ROOT / "data" / "results" / "release" / "day10_fingerprint.md").write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
