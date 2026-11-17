import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_relative_markdown_links_resolve():
    sources = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
    broken = []
    pattern = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
    for source in sources:
        for target in pattern.findall(source.read_text(encoding="utf-8")):
            target = target.strip().split()[0].strip("<>")
            if not target or target.startswith(("https://", "http://", "mailto:", "#", "data:")):
                continue
            local = target.split("#", 1)[0].split("?", 1)[0]
            if local and not (source.parent / local).resolve().exists():
                broken.append(f"{source.relative_to(ROOT)} -> {target}")
    assert not broken, "Broken relative links: " + ", ".join(broken)


def test_version_agrees_with_project_metadata():
    import tomllib
    from firewall.__version__ import __version__

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["version"] == __version__ == "0.1.0"


def test_pyproject_parses_and_core_dependency_is_small():
    import tomllib

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["requires-python"] == ">=3.10"
    assert metadata["project"]["dependencies"] == ["PyYAML>=6.0"]


def test_release_manifest_detects_a_changed_file(tmp_path):
    import json
    from tools.release_manifest import verify_manifest

    fake_manifest = tmp_path / "manifest.json"
    fake_manifest.write_text(json.dumps({"files": {"README.md": "0" * 64}}), encoding="utf-8")
    valid, changes = verify_manifest(fake_manifest, ROOT)
    assert not valid
    assert "README.md" in changes
