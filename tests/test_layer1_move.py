from __future__ import annotations

import importlib
import warnings
from pathlib import Path

from firewall.layer1._paths import get_project_root

ROOT = Path(__file__).resolve().parents[1]


def test_project_root_from_different_working_directory(monkeypatch, tmp_path):
    other = tmp_path / "a different working directory"
    other.mkdir()
    monkeypatch.delenv("FIREWALL_PROJECT_ROOT", raising=False)
    monkeypatch.chdir(other)
    assert get_project_root() == ROOT


def test_project_root_override_with_spaces(monkeypatch):
    monkeypatch.setenv("FIREWALL_PROJECT_ROOT", str(ROOT))
    assert " " in str(ROOT)
    assert get_project_root() == ROOT


def test_invalid_project_root_override_fails_closed(monkeypatch, tmp_path):
    invalid = tmp_path / "not a project"
    invalid.mkdir()
    monkeypatch.setenv("FIREWALL_PROJECT_ROOT", str(invalid))
    try:
        get_project_root()
    except FileNotFoundError as exc:
        assert "config/ and data/" in str(exc)
    else:
        raise AssertionError("invalid project-root override was accepted")


def test_legacy_scan_import_warns_once_and_aliases_same_module():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        import layers  # noqa: F401
        old_scan = importlib.import_module("layers.scan")
        new_scan = importlib.import_module("firewall.layer1.scan")
    deprecations = [item for item in caught if issubclass(item.category, DeprecationWarning)]
    assert len(deprecations) == 1
    assert old_scan is new_scan
