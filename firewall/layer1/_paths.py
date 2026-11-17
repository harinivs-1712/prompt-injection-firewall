"""Project-root discovery for Layer 1 data and configuration paths."""
from __future__ import annotations

import os
from pathlib import Path


def _is_project_root(path: Path) -> bool:
    return (path / "config").is_dir() and (path / "data").is_dir()


def get_project_root() -> Path:
    """Find the repository root from an explicit override, cwd, or this file."""
    configured = os.environ.get("FIREWALL_PROJECT_ROOT")
    if configured:
        root = Path(configured).expanduser().resolve()
        if not _is_project_root(root):
            raise FileNotFoundError("FIREWALL_PROJECT_ROOT must contain config/ and data/.")
        return root

    starts = (Path.cwd(), Path(__file__).resolve().parent)
    for start in starts:
        for candidate in (start, *start.parents):
            if _is_project_root(candidate):
                return candidate
    raise FileNotFoundError("Could not find a project root containing config/ and data/.")
