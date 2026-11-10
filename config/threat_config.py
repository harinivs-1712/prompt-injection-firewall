"""Configuration data for suspicion levels and provenance defaults."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
THREAT_CONFIG_PATH = Path(__file__).with_name("threat_config.json")
_DATA: dict[str, Any] = json.loads(THREAT_CONFIG_PATH.read_text(encoding="utf-8"))

ACTIVE_LEVEL_TABLE = _DATA["ACTIVE_LEVEL_TABLE"]
LEVEL_ORDER = tuple(_DATA["LEVEL_ORDER"])
SOURCE_TRUST: dict[str, str] = dict(_DATA["SOURCE_TRUST"])
DEFAULT_SOURCE_TYPE = _DATA["DEFAULT_SOURCE_TYPE"]
SOURCE_TYPE_BY_DOC_ID: dict[str, str] = dict(_DATA["SOURCE_TYPE_BY_DOC_ID"])
LEVEL_TABLES: dict[str, dict[str, Any]] = dict(_DATA["LEVEL_TABLES"])
THREAT_STORE_PATH = ROOT / "data" / "results" / "threat_store.sqlite"
JUDGED_SEGMENTS_PATH = ROOT / "data" / "results" / "segments_judged.json"
LABELED_DIR = ROOT / "data" / "labeled"
LABELS_PATH = LABELED_DIR / "labels.json"
LEVELED_SEGMENTS_PATH = ROOT / "data" / "results" / "segments_leveled.json"
LABELING_REPORT_PATH = ROOT / "data" / "results" / "labeling_comparison.md"
SUSPICION_REPORT_PATH = ROOT / "data" / "results" / "suspicion_evaluation.md"


def trust_for_source(source_type: str) -> str:
    """Return source trust; unconfigured external types remain untrusted."""
    return SOURCE_TRUST.get(source_type, "untrusted")
