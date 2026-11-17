"""Build and verify the v0.1.0 release file manifest."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config" / "firewall_v0_1_0_manifest.json"


def release_files(root: Path = ROOT) -> list[Path]:
    files = []
    for folder in ("firewall", "policies", "harness", "examples", "tools"):
        base = root / folder
        if base.exists():
            files.extend(path for path in base.rglob("*") if path.is_file() and "__pycache__" not in path.parts)
    docs = root / "docs"
    files.extend(docs.glob("*.md"))
    files.extend([root / "README.md", root / "pyproject.toml", root / "LICENSE", root / "CHANGELOG.md", root / "RELEASE.md"])
    for folder in (root / "data" / "layer2_eval", root / "config"):
        if folder.exists():
            files.extend(folder.glob("*.yaml"))
            if folder.name == "config":
                files.extend(folder / name for name in ("layer2_eval_manifest_v2.json", "layer1_manifest_v2.json") if (folder / name).is_file())
    files.extend(root / "data" / "results" / "layer2_eval" / name
                 for name in ("results.json", "per_trace.csv", "results.md"))
    return sorted(set(path.resolve() for path in files if path.is_file()))


def calculate_entries(root: Path = ROOT) -> dict[str, str]:
    return {path.relative_to(root.resolve()).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in release_files(root)}


def build_manifest(path: Path = MANIFEST, root: Path = ROOT) -> dict:
    payload = {"format_version": 1, "release_version": "0.1.0", "files": calculate_entries(root)}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def verify_manifest(path: Path = MANIFEST, root: Path = ROOT) -> tuple[bool, list[str]]:
    try:
        frozen = json.loads(path.read_text(encoding="utf-8")).get("files", {})
    except Exception:
        return False, ["manifest cannot be read"]
    current = calculate_entries(root)
    changes = [name for name in sorted(set(frozen) | set(current)) if frozen.get(name) != current.get(name)]
    return not changes, changes
