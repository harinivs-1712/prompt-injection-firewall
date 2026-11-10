"""Central settings for the Layer 1 context-aware judge."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MODEL_NAME = "gemini-3.1-flash-lite"
PROMPT_VERSION = "v1"
API_KEY_ENV = "GEMINI_API_KEY"
RPM_LIMIT = 5
PAUSE_BETWEEN_CALLS_SECONDS = 1.0
MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 30.0
TEMPERATURE = 0.0
MAX_OUTPUT_TOKENS = 180
PIGUARD_THRESHOLD = 0.5
CONSISTENCY_SAMPLE_SIZE = 40
CONSISTENCY_RUNS = 3
RANDOM_SEED = 20261107

TASKS_PATH = ROOT / "config" / "tasks.json"
SCORED_SEGMENTS_PATH = ROOT / "data" / "results" / "segments_scored.json"
LABELS_PATH = ROOT / "data" / "labeled" / "labels.json"
LEGIT_LABELS_PATH = ROOT / "data" / "labeled_legit" / "labels.json"
RESULTS_DIR = ROOT / "data" / "results"
JUDGE_CACHE_PATH = RESULTS_DIR / "judge_cache.jsonl"
JUDGED_OUTPUT_PATH = RESULTS_DIR / "segments_judged.json"
LEGIT_JUDGED_OUTPUT_PATH = RESULTS_DIR / "legit_segments_judged.json"
EVALUATION_REPORT_PATH = RESULTS_DIR / "detector_evaluation.md"
FLAGGED_SEGMENTS_PATH = RESULTS_DIR / "flagged_segment_analysis.md"
REPEATABILITY_REPORT_PATH = RESULTS_DIR / "judge_repeatability.md"

