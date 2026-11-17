"""Verify the Layer 1 package move against the pre-move baseline."""
from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import warnings
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
BASELINE = ROOT / "data" / "results" / "refactor" / "baseline.json"
REPORT = ROOT / "data" / "results" / "refactor" / "move_report.md"
START_TAG = "pre-layer1-move"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def _strip_metadata(value):
    ignored = {"timestamp", "created_at", "updated_at", "git_commit", "firewall_sha256",
               "manifest_sha256", "manifest_hash", "manifest_warnings"}
    if isinstance(value, dict):
        return {key: _strip_metadata(item) for key, item in value.items() if key not in ignored}
    if isinstance(value, list):
        return [_strip_metadata(item) for item in value]
    return value


def _git_old_file(old_path: str) -> str:
    result = subprocess.run(["git", "show", f"{START_TAG}:{old_path}"], cwd=ROOT,
                            capture_output=True, check=True)
    return result.stdout.decode("utf-8")


def _canonical_import(line: str) -> str:
    if line.strip() == "from ._paths import get_project_root":
        return ""
    if line.strip() == "from firewall.layer1._paths import get_project_root":
        return ""
    patterns = (
        (r"^(\s*from) layers\.([A-Za-z0-9_.]+)( import .*)$", r"\1 @LAYER1@.\2\3"),
        (r"^(\s*from) firewall\.layer1\.([A-Za-z0-9_.]+)( import .*)$", r"\1 @LAYER1@.\2\3"),
        (r"^(\s*from) \.([A-Za-z0-9_.]+)( import .*)$", r"\1 @LAYER1@.\2\3"),
        (r"^(\s*import) layers\.([A-Za-z0-9_.]+)$", r"\1 @LAYER1@.\2"),
        (r"^(\s*import) firewall\.layer1\.([A-Za-z0-9_.]+)$", r"\1 @LAYER1@.\2"),
    )
    for pattern, replacement in patterns:
        line = re.sub(pattern, replacement, line)
    return line


def _normalize_source(text: str, old_path: str) -> str:
    lines = text.splitlines()
    normalized = []
    in_scan_manifest_components = False
    skip_added_file_hash_loop = False
    for line in lines:
        stripped = line.strip()
        if old_path == "layers/scan.py":
            if stripped.startswith("def manifest_components("):
                in_scan_manifest_components = True
            if in_scan_manifest_components and stripped == '"path_resolver_sha256": _sha(root / "firewall" / "layer1" / "_paths.py"),':
                continue
            if in_scan_manifest_components and stripped == 'components = {':
                line = "    return {"
            if in_scan_manifest_components and stripped == "root = layer1_settings.ROOT":
                pass
            if in_scan_manifest_components and stripped.startswith("for path in sorted((root / \"firewall\" / \"layer1\")"):
                skip_added_file_hash_loop = True
            if skip_added_file_hash_loop:
                if stripped == "return components":
                    skip_added_file_hash_loop = False
                continue
            if in_scan_manifest_components and '"path_resolver_sha256":' in line:
                continue
            if in_scan_manifest_components and stripped == "}":
                normalized.append(line)
                continue
            if in_scan_manifest_components and stripped.startswith("def _manifest_digest("):
                in_scan_manifest_components = False
            if stripped.startswith("MANIFEST_PATH ="):
                line = 'MANIFEST_PATH = <PROJECT_ROOT> / "config" / "layer1_final_manifest.json"'
            line = line.replace('root / "layers" /', 'root / "@MOVED_LAYER1@" /')
            line = line.replace('root / "firewall" / "layer1" /', 'root / "@MOVED_LAYER1@" /')
        if old_path == "layers/segmenter.py":
            if stripped == 'data_dir = Path(__file__).parent.parent / "data"':
                line = '        data_dir = <PROJECT_ROOT> / "data"'
            elif stripped == 'data_dir = get_project_root() / "data"':
                line = '        data_dir = <PROJECT_ROOT> / "data"'
        line = _canonical_import(line)
        if line:
            normalized.append(line)
    return "\n".join(normalized) + "\n"


def _capture_values() -> dict[str, Any]:
    import config.filter_v2_config as f2
    import config.judge_config as jc
    import config.layer1_settings as ls
    import config.rules_config as rc
    import config.threat_config as tc
    import firewall.layer1.instruction_rules as rules_v1
    import firewall.layer1.instruction_rules_v2 as rules_v2
    import firewall.layer1.judge as judge
    import firewall.layer1.piguard_scorer as piguard
    import firewall.layer1.segmenter as segmenter

    def plain(value):
        if isinstance(value, Path): return str(value)
        if isinstance(value, dict): return {str(k): plain(v) for k, v in value.items()}
        if isinstance(value, (tuple, list, set, frozenset)): return [plain(v) for v in value]
        if hasattr(value, "pattern") and hasattr(value, "flags"):
            return {"pattern": value.pattern, "flags": value.flags}
        return value

    return {
        "judge_prompt_constants": {
            "JUDGE_SYSTEM_INSTRUCTION": judge.JUDGE_SYSTEM_INSTRUCTION,
            "JUDGE_USER_TEMPLATE": judge.JUDGE_USER_TEMPLATE,
            "JUDGE_RESPONSE_SCHEMA": plain(judge.JUDGE_RESPONSE_SCHEMA),
            "EXPECTED_FIELDS": sorted(judge._EXPECTED_FIELDS),
            "DELIMITERS": list(judge._DELIMITERS),
        },
        "PROMPT_VERSION": jc.PROMPT_VERSION,
        "judge_model_name": jc.MODEL_NAME,
        "PIGuard_model_name": piguard.MODEL_NAME,
        "PIGuard_threshold": jc.PIGUARD_THRESHOLD,
        "RULES_VERSION_default": rc.RULES_VERSION,
        "rules_v1": {
            "SPACY_MODEL": rules_v1.SPACY_MODEL,
            "POLITE_IMPERATIVE_LEADS": sorted(rules_v1.POLITE_IMPERATIVE_LEADS),
            "ACTION_VERBS": sorted(rules_v1.ACTION_VERBS),
            "ASSISTANT_PATTERNS": [{"name": name, "pattern": pattern.pattern, "flags": pattern.flags}
                                   for name, pattern in rules_v1.ASSISTANT_PATTERNS],
            "WORDS_PATTERN": rules_v1._WORDS_RE.pattern,
            "WORDS_FLAGS": rules_v1._WORDS_RE.flags,
        },
        "rules_v2": {
            "FAMILY_PATTERNS": plain(f2.FAMILY_PATTERNS),
            "COOCCUR_CONTEXT_WORDS": list(f2.COOCCUR_CONTEXT_WORDS),
            "WORD_SPAN_PATTERN": rules_v2._WORD_SPAN.pattern,
            "WORD_SPAN_FLAGS": rules_v2._WORD_SPAN.flags,
        },
        "suspicion_level_table": json.loads((ROOT / "config" / "threat_config.json").read_text(encoding="utf-8")),
        "layer1_settings_defaults": {key: plain(value) for key, value in vars(ls).items() if key.isupper()},
        "segmenter_settings": {
            "split_sentences_signature": str(__import__("inspect").signature(segmenter.split_sentences)),
            "make_segments_signature": str(__import__("inspect").signature(segmenter.make_segments)),
            "process_file_signature": str(__import__("inspect").signature(segmenter.process_file)),
            "run_all_signature": str(__import__("inspect").signature(segmenter.run_all)),
            "abbreviations": sorted(segmenter._ABBREVS),
            "naive_split_pattern": segmenter._NAIVE_SPLIT_RE.pattern,
            "naive_split_flags": segmenter._NAIVE_SPLIT_RE.flags,
            "trailing_token_pattern": segmenter._TRAILING_TOKEN_RE.pattern,
            "trailing_token_flags": segmenter._TRAILING_TOKEN_RE.flags,
        },
    }


def _suite_once(index: int, baseline: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    print(f"Starting full pytest run {index}/3.", flush=True)
    command = [sys.executable, "-X", "dev", "-m", "pytest", "-v", "-x", "--durations=25"]
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=900)
    except subprocess.TimeoutExpired:
        return {"pass": False, "detail": f"pytest run {index} exceeded the 900-second guard."}
    output = result.stdout + "\n" + result.stderr
    collected_match = re.search(r"collected (\d+) items?", output)
    summary_lines = [line for line in output.splitlines() if re.search(r"\d+ passed|\d+ failed|\d+ skipped", line)]
    last = summary_lines[-1] if summary_lines else "No pytest summary found."
    def count(label):
        match = re.search(rf"(\d+) {label}", last)
        return int(match.group(1)) if match else 0
    counts = {"collected": int(collected_match.group(1)) if collected_match else 0,
              "passed": count("passed"), "skipped": count("skipped"), "failed": count("failed"),
              "returncode": result.returncode, "summary": last}
    ok = (result.returncode == 0 and counts["collected"] >= baseline["test_suite"]["collected"] and
          counts["passed"] >= baseline["test_suite"]["passed"] and counts["failed"] == 0 and
          counts["skipped"] <= baseline["test_suite"]["skipped"])
    counts["pass"] = ok
    print(f"Pytest run {index}/3: {last}; exit={result.returncode}", flush=True)
    if not ok:
        counts["failure_tail"] = "\n".join(output.splitlines()[-80:])
    return counts


def _run_layer1_replay() -> dict[str, Any]:
    from experiments import layer1_final_check as check
    scan_module = check.scan_module
    scan_module._PIGUARD_SCORER = check._CachedPIGuard()
    scan_module.instruction_signals = check._CachedRules()
    original = check.scan
    calls = []
    def tracked(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append({"doc_id": kwargs.get("doc_id"), "mode": kwargs.get("mode"),
                      "cache_hits": result.summary["cache_hits"],
                      "judge_calls": result.summary["judge_calls_made"],
                      "segments": result.summary["segment_count"]})
        return result
    check.scan = tracked
    with contextlib.redirect_stdout(io.StringIO()):
        all_rows, cascade_rows, hard_issues = check._run_hard_eval()
        early_issues = check._run_early_labeled()
    cache_hits = sum(row["cache_hits"] for row in calls)
    by_mode = {
        "hard_eval_all": sum(row["cache_hits"] for row in calls if row["doc_id"].startswith("hard_") and row["mode"] == "all"),
        "hard_eval_cascade": sum(row["cache_hits"] for row in calls if row["doc_id"].startswith("hard_") and row["mode"] == "cascade"),
        "labeled_cascade": sum(row["cache_hits"] for row in calls if row["doc_id"].startswith("doc_") and row["mode"] == "cascade"),
        "labeled_legit_all": sum(row["cache_hits"] for row in calls if row["doc_id"].startswith("legit_") and row["mode"] == "all"),
    }
    return {"hard_eval_all_segments": len(all_rows), "hard_eval_all_judge_coverage": sum(bool(r["judge_ran"]) for r in all_rows),
            "hard_eval_cascade_segments": len(cascade_rows),
            "hard_eval_cascade_candidates": sum(r["judge_coverage_reason"] != "not_selected" for r in cascade_rows),
            "hard_eval_mismatches": len(hard_issues), "early_labeled_and_legit_mismatches": len(early_issues),
            "total_mismatches": len(hard_issues) + len(early_issues),
            "judge_api_calls": sum(row["judge_calls"] for row in calls),
            "judge_cache_hits_total": cache_hits, "cache_hits_by_dataset_and_mode": by_mode,
            "documents_scanned": len(calls)}


def _run_day10_fingerprint(baseline: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    import harness.eval_layer2 as evaluation
    manifest = ROOT / "config" / "layer2_eval_manifest_v2.json"
    temp = tempfile.TemporaryDirectory(prefix="layer2-move-verification-")
    old_results_dir = evaluation.RESULTS_DIR
    evaluation.RESULTS_DIR = Path(temp.name)
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            code = evaluation.main(["--manifest", str(manifest)])
        csv_hash = _sha(Path(temp.name) / "per_trace.csv")
        result_value = json.loads((Path(temp.name) / "results.json").read_text(encoding="utf-8"))
        results_hash = _json_hash(_strip_metadata(result_value))
        api_calls = sum(int(row.get("api_calls", 0)) for row in result_value.get("real_layer1", []))
    finally:
        evaluation.RESULTS_DIR = old_results_dir
        temp.cleanup()
    expected = baseline["day10_fingerprint"]
    ok = (code == 0 and csv_hash == expected["per_trace_csv_sha256"] and
          results_hash == expected["stripped_results_json_sha256"] and api_calls == 0)
    return {"pass": ok, "per_trace_csv_sha256": csv_hash,
            "expected_per_trace_csv_sha256": expected["per_trace_csv_sha256"],
            "stripped_results_json_sha256": results_hash,
            "expected_stripped_results_json_sha256": expected["stripped_results_json_sha256"],
            "api_calls": api_calls, "run_output": captured.getvalue().splitlines()[-3:]}


def _cli_output(module: str, baseline: dict[str, Any], env: dict[str, str], cwd: Path) -> dict[str, Any]:
    old_command = baseline["cache_only_cli_demo"]["command"]
    command = list(old_command)
    command[2] = module
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=180)
    normalized = re.sub(r'("elapsed_seconds"\s*:\s*)[0-9]+(?:\.[0-9]+)?', r"\1<elapsed>", result.stdout)
    saved = re.sub(r'("elapsed_seconds"\s*:\s*)[0-9]+(?:\.[0-9]+)?', r"\1<elapsed>",
                   baseline["cache_only_cli_demo"]["stdout"])
    return {"exit_code": result.returncode, "matches_baseline": result.returncode == 0 and normalized == saved,
            "stdout": normalized, "stderr_tail": result.stderr.splitlines()[-6:]}


def _write_report(checks: list[dict[str, Any]], mapping: list[dict[str, Any]], edited_tests: list[str], commands: list[str]):
    lines = ["# Layer 1 package move equivalence report", "",
             "The original `layers/` package was moved with `git mv` to `firewall/layer1/`. No push, reset, rebase, merge, or deletion was performed.", "",
             "## Equivalence checks", "", "| Check | Result | Evidence |", "|---|---|---|"]
    for item in checks:
        lines.append(f"| {item['name']} | {'PASS' if item['pass'] else 'FAIL'} | {item['detail']} |")
    lines += ["", "## Moved-file mapping", "", "| Old path | New path | Change |", "|---|---|---|"]
    for row in mapping:
        lines.append(f"| `{row['old_path']}` | `{row['new_path']}` | {row['change_type']} |")
    lines += ["", "Changed files contain only normalized import changes, approved project-root/manifest path changes, or the required manifest-verification update. The new `firewall/layer1/_paths.py` is support code and has no old counterpart.", "",
              "## Edited test files", ""]
    if edited_tests:
        lines.extend(f"- `{path}`: {reason}" for path, reason in edited_tests)
    else:
        lines.append("None.")
    lines += ["", "## Commands run", ""]
    lines.extend(f"- `{command}`" for command in commands)
    lines += ["", "## Notes", "",
              "- API/Gemini access was disabled via environment and cache-only code paths; no live judge was constructed.",
              "- Pytest reports the same baseline skips; `pytest-timeout` is unavailable in this environment, so pytest emits its existing unknown timeout-option warnings. The outer runner applied a 900-second process guard.",
              "- The old Layer 1 manifest remains as provenance; `config/layer1_manifest_v2.json` now verifies the relocated source files.",
              "- The deprecated top-level `layers/` shim preserves legacy imports and module execution.", ""]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ.pop("GEMINI_API_KEY", None)
    env = os.environ.copy()
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / "config" / "layer1_manifest_v2.json").read_text(encoding="utf-8"))
    mapping = manifest["moved_files"]
    checks: list[dict[str, Any]] = []
    def record(name: str, ok: bool, detail: str):
        checks.append({"name": name, "pass": bool(ok), "detail": detail})
        print(f"{'PASS' if ok else 'FAIL'} | {name} | {detail}", flush=True)
        if not ok:
            _write_report(checks, mapping, TEST_EDITS, COMMANDS)
            raise SystemExit(1)

    # 1. Normalize only approved imports, path lookups, and manifest-verification updates.
    differences = []
    for row in mapping:
        old = _normalize_source(_git_old_file(row["old_path"]), row["old_path"])
        new = _normalize_source((ROOT / row["new_path"]).read_text(encoding="utf-8"), row["old_path"])
        if old != new:
            import difflib
            diff = "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                                  fromfile=row["old_path"], tofile=row["new_path"]))
            differences.append({"old_path": row["old_path"], "diff": diff})
    if differences:
        detail = "Normalized source differs: " + "; ".join(x["old_path"] for x in differences)
        _write_report(checks + [{"name":"normalized moved-file content", "pass":False, "detail":detail + "\n" + "\n".join(x["diff"] for x in differences)}], mapping, TEST_EDITS, COMMANDS)
        raise SystemExit("FAIL | normalized moved-file content; see move_report.md for diffs")
    current_hashes_ok = all(_sha(ROOT / row["new_path"]) == row["new_sha256"] for row in mapping)
    record("moved-file content", current_hashes_ok, f"{len(mapping)} files normalize to tagged originals; import/path/manifest-only differences.")

    # 2. Values, not just hashes.
    values = _capture_values()
    expected_values = baseline["layer1_values"]
    record("Layer 1 constants and defaults", values == expected_values,
           "judge prompts/models, rule lists, suspicion levels, scan/segment defaults compare to baseline.")

    # 3. Three full pytest runs.
    suite_runs = []
    for index in range(1, 4):
        run = _suite_once(index, baseline, env)
        suite_runs.append(run)
        record(f"full pytest run {index}/3", run.get("pass", False), run.get("summary", run.get("detail", "failed")))

    # 4. Cached Layer 1 replay and judge cache invariants.
    replay = _run_layer1_replay()
    cache_path = ROOT / baseline["judge_cache"]["path"]
    cache_count = sum(1 for line in cache_path.open(encoding="utf-8") if line.strip())
    cache_sha_ok = _sha(cache_path) == baseline["judge_cache"]["sha256"]
    replay_ok = (replay["total_mismatches"] == 0 and replay["judge_api_calls"] == 0 and
                 replay["judge_cache_hits_total"] == baseline["layer1_regression_replay"]["judge_cache_hits_total"] and
                 replay["cache_hits_by_dataset_and_mode"] == baseline["layer1_regression_replay"]["cache_hits_by_dataset_and_mode"] and
                 replay["hard_eval_all_judge_coverage"] == 330 and replay["hard_eval_cascade_candidates"] == 114 and
                 cache_count == baseline["judge_cache"]["entries"] and cache_sha_ok)
    record("Layer 1 cached regression and cache", replay_ok,
           f"mismatches={replay['total_mismatches']}; judge/API calls={replay['judge_api_calls']}; cache hits={replay['judge_cache_hits_total']}; entries={cache_count}; cache hash unchanged={cache_sha_ok}.")

    # 5. Day 10 evaluation fingerprints, with outputs isolated in a temp directory.
    print("Starting Day 10 fingerprint rerun with v2 manifest (offline).", flush=True)
    day10 = _run_day10_fingerprint(baseline, env)
    record("Day 10 evaluation fingerprints", day10["pass"],
           f"per_trace.csv match={day10['per_trace_csv_sha256']==day10['expected_per_trace_csv_sha256']}; stripped results.json match={day10['stripped_results_json_sha256']==day10['expected_stripped_results_json_sha256']}; API calls={day10['api_calls']}.")

    # 6. Import hygiene and compatibility alias.
    probe = "import json,sys; import firewall; print(json.dumps(sorted(sys.modules)))"
    imported = subprocess.run([sys.executable, "-c", probe], cwd=ROOT, env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=60, check=True)
    modules = json.loads(imported.stdout.strip().splitlines()[-1])
    forbidden = [name for name in modules if name in {"torch", "transformers", "google", "firewall.layer1", "layers"}
                 or name.startswith(("torch.", "transformers.", "google.", "firewall.layer1.", "layers."))]
    record("import firewall stays lightweight", not forbidden,
           "forbidden modules loaded: " + (", ".join(forbidden) if forbidden else "none"))
    alias_code = ("import importlib,json,warnings; "
                  "with_warns=warnings.catch_warnings(); with_warns.__enter__(); "
                  "warnings.simplefilter('always',DeprecationWarning); "
                  "import layers; old=importlib.import_module('layers.scan'); "
                  "new=importlib.import_module('firewall.layer1.scan'); "
                  "items=[w for w in with_warns.__dict__.get('log',[]) if issubclass(w.category,DeprecationWarning)]; "
                  "print(json.dumps({'same':old is new,'warning_count':len(items)})); with_warns.__exit__(None,None,None)")
    # Use a small script with a conventional warnings context; keep it isolated from pytest warning filters.
    alias_code = """import importlib, json, warnings
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter('always', DeprecationWarning)
    import layers
    old = importlib.import_module('layers.scan')
    new = importlib.import_module('firewall.layer1.scan')
count = sum(issubclass(item.category, DeprecationWarning) for item in caught)
print(json.dumps({'same': old is new, 'warning_count': count}))
"""
    alias = subprocess.run([sys.executable, "-c", alias_code], cwd=ROOT, env=env, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=60, check=True)
    alias_result = json.loads(alias.stdout.strip().splitlines()[-1])
    record("legacy layers shim", alias_result == {"same": True, "warning_count": 1}, str(alias_result))

    # 7. CLI output from a path with spaces and an unrelated cwd.
    with tempfile.TemporaryDirectory(prefix="move-cli-cwd-") as temp:
        other_cwd = Path(temp) / "different cwd with spaces"
        other_cwd.mkdir()
        cli_env = env.copy()
        cli_env.pop("FIREWALL_PROJECT_ROOT", None)
        current_path = cli_env.get("PYTHONPATH", "")
        cli_env["PYTHONPATH"] = str(ROOT) + (os.pathsep + current_path if current_path else "")
        new_cli = _cli_output("firewall.layer1.scan_cli", baseline, cli_env, other_cwd)
        old_cli = _cli_output("layers.scan_cli", baseline, cli_env, other_cwd)
        cli_ok = (new_cli["matches_baseline"] and old_cli["matches_baseline"] and
                  new_cli["stdout"] == old_cli["stdout"])
        record("new and compatibility CLIs", cli_ok,
               f"new exit={new_cli['exit_code']}; legacy exit={old_cli['exit_code']}; output matches saved baseline after elapsed-time normalization.")

    # 8. The full suite above includes privacy and agent-agnostic tests; assert their direct targets too.
    privacy = subprocess.run([sys.executable, "-X", "dev", "-m", "pytest", "-q",
                              "tests/test_firewall_day5.py::test_decisions_audit_and_sessions_never_record_argument_values",
                              "tests/test_firewall_day8.py::test_firewall_tree_stays_agent_agnostic"],
                             cwd=ROOT, env=env, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=120)
    record("privacy and agent-agnostic checks", privacy.returncode == 0,
           "explicit audit-value privacy and firewall grep tests passed." if privacy.returncode == 0 else
           "targeted test failure: " + " ".join((privacy.stdout + privacy.stderr).splitlines()[-10:]))

    _write_report(checks, mapping, TEST_EDITS, COMMANDS)
    print("\nPASS/FAIL TABLE")
    print("| Check | Result | Evidence |\n|---|---|---|")
    for item in checks:
        print(f"| {item['name']} | {'PASS' if item['pass'] else 'FAIL'} | {item['detail']} |")
    print(f"Report: {REPORT}")
    return 0


TEST_EDITS = [
    ("tests/test_detectors.py", "Updated Layer 1 imports to firewall.layer1."),
    ("tests/test_filter_v2.py", "Updated Layer 1 imports to firewall.layer1."),
    ("tests/test_firewall_day5.py", "Updated the import-hygiene target from legacy layers modules to firewall.layer1."),
    ("tests/test_firewall_day7.py", "Updated lazy fake-module injection targets to firewall.layer1.scan."),
    ("tests/test_hard_eval.py", "Moved the temporary manifest fixture paths to firewall/layer1."),
    ("tests/test_judge_pipeline.py", "Updated Layer 1 imports to firewall.layer1."),
    ("tests/test_layer2_eval.py", "Updated the fake judge import/patch target to firewall.layer1.judge."),
    ("tests/test_scan.py", "Updated Layer 1 imports to firewall.layer1."),
    ("tests/test_segmenter.py", "Updated the segmenter import to firewall.layer1."),
    ("tests/test_threat_store.py", "Updated Layer 1 imports to firewall.layer1."),
    ("tests/test_layer1_move.py", "Added path discovery, compatibility warning, and module-identity regression tests."),
]

COMMANDS = [
    "venv\\Scripts\\python.exe -X dev -m pytest -v -x --durations=25 (three runs)",
    "venv\\Scripts\\python.exe tools\\verify_move.py",
    "venv\\Scripts\\python.exe -m harness.eval_layer2 --manifest config\\layer2_eval_manifest_v2.json (outputs redirected to a temporary directory)",
    "python -m firewall.layer1.scan_cli ... (from a different working directory)",
    "python -m layers.scan_cli ... (from a different working directory)",
]


if __name__ == "__main__":
    raise SystemExit(main())
