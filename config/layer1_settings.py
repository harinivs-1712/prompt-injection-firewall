"""Runtime settings for the unified Layer 1 scan entry point."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JUDGE_MODE = "all"  # "all" or "cascade"
MAX_JUDGE_CALLS_PER_DOC: int | None = None
JUDGE_PRIORITY = ("both", "rules_only", "piguard_only", "unflagged")
OFFLINE_CACHE_ONLY = True
WINDOW = 3
STRIDE = 1
DEFAULT_CONTEXT_NOTES = {
    "email": "Email content supplied by the user for analysis.",
    "document": "Document content supplied by the user for analysis.",
    "web": "Web content retrieved from an external source.",
    "tool_output": "Output returned by a tool called by the assistant.",
}
SCAN_CACHE_PATH = ROOT / "data" / "results" / "layer1_scan_cache.jsonl"
LEGACY_CACHE_PATHS = (
    ROOT / "data" / "results" / "judge_cache.jsonl",
    ROOT / "data" / "results" / "hard_eval_judge_cache.jsonl",
)
