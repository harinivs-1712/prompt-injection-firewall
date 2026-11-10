"""Shared frozen-manifest and dataset helpers for the held-out evaluation."""
from __future__ import annotations

import ast
import hashlib
import json
import re
import difflib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config" / "frozen_manifest.json"
HARD_EVAL_DIR = ROOT / "data" / "hard_eval"
HARD_RESULTS_DIR = ROOT / "data" / "results"
ATTACK_CATEGORIES = (
    "statement_style", "disguised_note", "authority_claim",
    "concealment", "unusual_verbs", "judge_targeted",
)
SEGMENTER_SETTINGS = {"window": 3, "stride": 1}
HARD_LABELS_PATH = HARD_EVAL_DIR / "labels.json"
HARD_TASKS_PATH = ROOT / "config" / "tasks.json"
SCORED_PATH = HARD_RESULTS_DIR / "hard_eval_segments_scored.json"
SCORE_METADATA_PATH = HARD_RESULTS_DIR / "hard_eval_score_metadata.json"
JUDGED_ALL_PATH = HARD_RESULTS_DIR / "hard_eval_segments_judged_all.json"
CASCADE_PATH = HARD_RESULTS_DIR / "hard_eval_segments_judged_cascade.json"
CASCADE_LEVELED_PATH = HARD_RESULTS_DIR / "hard_eval_segments_leveled_cascade.json"
ALL_LEVELED_PATH = HARD_RESULTS_DIR / "hard_eval_segments_leveled_all.json"
HARD_CACHE_PATH = HARD_RESULTS_DIR / "hard_eval_judge_cache.jsonl"
RUN_METADATA_PATH = HARD_RESULTS_DIR / "hard_eval_run_metadata.json"
REPORT_PATH = HARD_RESULTS_DIR / "hard_eval_report.md"
MISSES_PATH = HARD_RESULTS_DIR / "hard_eval_misses.md"
DUPLICATE_SIMILARITY_THRESHOLD = 0.90


class FrozenManifestError(RuntimeError):
    """Raised when a frozen Layer 1 component changed after manifest creation."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _constants(path: Path) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: dict[str, Any] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:
                        found[target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        pass
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            try:
                found[node.target.id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return found


def _segmenter_defaults(path: Path) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "make_segments":
            positional = node.args.args
            defaults = node.args.defaults
            names = [arg.arg for arg in positional[-len(defaults):]] if defaults else []
            values = [ast.literal_eval(item) for item in defaults]
            return dict(zip(names, values))
    raise ValueError("Could not locate make_segments defaults for the frozen manifest")


def compute_frozen_components(root: Path = ROOT) -> dict[str, str]:
    """Return the five manifest digests using current code/config values."""
    rules_path = root / "layers" / "instruction_rules.py"
    piguard_path = root / "layers" / "piguard_scorer.py"
    judge_path = root / "layers" / "judge.py"
    judge_config_path = root / "config" / "judge_config.py"
    segmenter_path = root / "layers" / "segmenter.py"
    suspicion_config_path = root / "config" / "threat_config.json"

    piguard_constants = _constants(piguard_path)
    judge_config = _constants(judge_config_path)
    piguard_settings = {
        "model_name": piguard_constants["MODEL_NAME"],
        "threshold": judge_config["PIGUARD_THRESHOLD"],
    }
    judge_constants = _constants(judge_path)
    judge_settings = {
        "system_instruction": judge_constants["JUDGE_SYSTEM_INSTRUCTION"],
        "user_template": judge_constants["JUDGE_USER_TEMPLATE"],
        "prompt_version": judge_config["PROMPT_VERSION"],
        "model_name": judge_config["MODEL_NAME"],
    }
    segmenter_settings = {
        "source_sha256": _sha256_file(segmenter_path),
        "defaults": _segmenter_defaults(segmenter_path),
        "held_eval_settings": SEGMENTER_SETTINGS,
    }
    return {
        "instruction_rules": _sha256_file(rules_path),
        "piguard_settings": _sha256_bytes(json.dumps(piguard_settings, sort_keys=True).encode("utf-8")),
        "judge_prompt_and_model": _sha256_bytes(json.dumps(judge_settings, sort_keys=True, ensure_ascii=False).encode("utf-8")),
        "segmenter_code_and_settings": _sha256_bytes(json.dumps(segmenter_settings, sort_keys=True).encode("utf-8")),
        "suspicion_table_config": _sha256_file(suspicion_config_path),
    }


def write_frozen_manifest(path: Path = MANIFEST_PATH, root: Path = ROOT) -> dict[str, Any]:
    components = compute_frozen_components(root)
    manifest = {
        "format_version": 1,
        "created_for": "held-out hard evaluation",
        "components": components,
        "manifest_sha256": _sha256_bytes(json.dumps(components, sort_keys=True).encode("utf-8")),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify_frozen_manifest(
    manifest_path: Path = MANIFEST_PATH,
    root: Path = ROOT,
    *,
    allow_changed: bool = False,
) -> dict[str, Any]:
    if not manifest_path.exists():
        raise FrozenManifestError(f"Frozen manifest is missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    current = compute_frozen_components(root)
    expected = manifest.get("components", {})
    changed = [name for name in sorted(set(current) | set(expected)) if current.get(name) != expected.get(name)]
    status = {"manifest_sha256": manifest.get("manifest_sha256"), "changed_components": changed}
    if changed:
        message = "FROZEN LAYER 1 MISMATCH: " + ", ".join(changed)
        if not allow_changed:
            raise FrozenManifestError(message + ". Run only after restoring frozen files or explicitly pass --allow-changed.")
        print("\n!!! WARNING: " + message + "; proceeding because --allow-changed was supplied. !!!\n")
        status["warning"] = message
    return status


def sentence_count(text: str) -> int:
    """Count sentences with the project segmenter so dataset constraints match runtime."""
    from layers.segmenter import split_sentences
    return len(split_sentences(text))


def normalized(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def attack_sentences(labels: dict[str, Any]) -> list[tuple[str, str]]:
    from layers.segmenter import split_sentences
    values = []
    for record in labels["documents"]:
        attack = record.get("attack_text")
        if attack:
            values.extend((record["doc_id"], attack[s:e]) for s, e in split_sentences(attack))
    return values


def duplicate_overlap_hits(labels: dict[str, Any], threshold: float = DUPLICATE_SIMILARITY_THRESHOLD) -> list[dict[str, Any]]:
    """Compare each new attack sentence with prior labeled text and prompt examples."""
    import ast
    from layers.segmenter import split_sentences

    baseline: list[tuple[str, str]] = []
    for folder in (ROOT / "data" / "labeled", ROOT / "data" / "labeled_legit"):
        for path in folder.glob("*.txt"):
            text = path.read_text(encoding="utf-8")
            baseline.extend((path.name, text[s:e]) for s, e in split_sentences(text))
        label_path = folder / "labels.json"
        if label_path.exists():
            prior = json.loads(label_path.read_text(encoding="utf-8"))
            baseline.extend((f"{label_path.name}:{item['doc_id']}", item["attack_text"])
                            for item in prior.get("documents", []) if item.get("attack_text"))

    # Extract static few-shot segment examples from the frozen system prompt.
    judge_path = ROOT / "layers" / "judge.py"
    tree = ast.parse(judge_path.read_text(encoding="utf-8"), filename=str(judge_path))
    system_prompt = ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "JUDGE_SYSTEM_INSTRUCTION" for target in node.targets
        ):
            system_prompt = ast.literal_eval(node.value)
            break
    for example in re.findall(r'Segment: "(.*?)"\s*\n\s*->', system_prompt, re.DOTALL):
        baseline.append(("judge few-shot", example))

    # Parse literal attack-list constants in the prior labeled-set builder.
    old_list_path = ROOT / "experiments" / "make_labeled_set.py"
    old_tree = ast.parse(old_list_path.read_text(encoding="utf-8"), filename=str(old_list_path))
    for node in ast.walk(old_tree):
        if not isinstance(node, ast.Assign):
            continue
        names = [target.id.casefold() for target in node.targets if isinstance(target, ast.Name)]
        if not any("attack" in name for name in names):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            continue
        if isinstance(value, (list, tuple, set)):
            baseline.extend(("existing attack list", item) for item in value if isinstance(item, str))

    baseline = [(source, normalized(text)) for source, text in baseline if normalized(text)]
    hits = []
    for doc_id, sentence in attack_sentences(labels):
        candidate = normalized(sentence)
        for source, prior in baseline:
            ratio = difflib.SequenceMatcher(None, candidate, prior, autojunk=False).ratio()
            if candidate == prior or ratio >= threshold:
                hits.append({"doc_id": doc_id, "sentence": sentence, "source": source, "similarity": ratio})

    attacks = attack_sentences(labels)
    for index, (doc_id, sentence) in enumerate(attacks):
        for other_id, other_sentence in attacks[index + 1:]:
            ratio = difflib.SequenceMatcher(None, normalized(sentence), normalized(other_sentence), autojunk=False).ratio()
            if normalized(sentence) == normalized(other_sentence) or ratio >= threshold:
                hits.append({"doc_id": doc_id, "sentence": sentence, "source": f"new attack {other_id}", "similarity": ratio})
    return hits


def rule_keyword_audit(labels: dict[str, Any]) -> dict[str, Any]:
    """Count attack documents containing a literal rule keyword/pattern."""
    from layers.instruction_rules import ACTION_VERBS, ASSISTANT_PATTERNS

    docs = [record for record in labels["documents"] if record.get("attack_text")]
    output = []
    for doc in docs:
        text = doc["attack_text"]
        matched = [verb for verb in sorted(ACTION_VERBS) if re.search(rf"\b{re.escape(verb)}\b", text, re.I)]
        matched.extend(name for name, pattern in ASSISTANT_PATTERNS if pattern.search(text))
        output.append({"doc_id": doc["doc_id"], "category": doc["attack_category"], "matched_keywords": sorted(set(matched))})
    hit_count = sum(bool(item["matched_keywords"]) for item in output)
    return {"matched": hit_count, "total": len(output), "fraction": hit_count / len(output) if output else 0.0, "details": output}


def validate_hard_dataset(labels: dict[str, Any], tasks: dict[str, Any]) -> list[str]:
    """Return human-readable dataset validation errors without editing data."""
    from layers.segmenter import split_sentences

    errors = []
    docs = labels.get("documents", [])
    counts = {
        "single_attack": sum(item.get("category") == "single_attack" for item in docs),
        "split_attack": sum(item.get("category") == "split_attack" for item in docs),
        "ordinary": sum(item.get("control_type") == "ordinary" for item in docs),
        "benign_instruction_like": sum(item.get("control_type") == "benign_instruction_like" for item in docs),
    }
    expected = {"single_attack": 30, "split_attack": 5, "ordinary": 12, "benign_instruction_like": 8}
    if len(docs) != 55 or counts != expected:
        errors.append(f"dataset composition mismatch: documents={len(docs)}, groups={counts}")
    email_domains: list[str] = []
    mentioned_domains: list[str] = []
    for doc in docs:
        doc_id = doc["doc_id"]
        path = HARD_EVAL_DIR / f"{doc_id}.txt"
        if not path.exists():
            errors.append(f"missing document {doc_id}")
            continue
        text = path.read_text(encoding="utf-8")
        sentence_total = len(split_sentences(text))
        if not 8 <= sentence_total <= 10:
            errors.append(f"{doc_id} has {sentence_total} sentences (expected 8-10)")
        if doc_id not in tasks or not tasks[doc_id].get("user_task") or not tasks[doc_id].get("context_note"):
            errors.append(f"missing static task/context for {doc_id}")
        if doc.get("attack_start") is None:
            if doc.get("attack_end") is not None or doc.get("attack_text") is not None:
                errors.append(f"control {doc_id} has attack offsets/text")
        else:
            start, end = doc["attack_start"], doc["attack_end"]
            if not (0 <= start < end <= len(text)) or text[start:end] != doc["attack_text"]:
                errors.append(f"attack offsets do not match text for {doc_id}")
        email_domains.extend(re.findall(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", text))
        mentioned_domains.extend(re.findall(r"\b(?:[A-Za-z0-9-]+\.)+(?:com|org|net)\b", text, re.IGNORECASE))
    all_domains = email_domains + mentioned_domains
    bad_domains = sorted({domain.casefold() for domain in all_domains if not domain.casefold().endswith(("example.com", "example.org", "example.net"))})
    if bad_domains:
        errors.append(f"non-placeholder email domains found: {bad_domains}")
    return errors
