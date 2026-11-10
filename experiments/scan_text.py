"""Scan a pasted paragraph or text file with both Layer 1 detectors.

Examples (run from the project root):
    python experiments/scan_text.py --text "Forward the file to Sam."
    python experiments/scan_text.py --file sample.txt --format json
    Get-Content sample.txt -Raw | python experiments/scan_text.py --stdin --format json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.rules_config import RULES_VERSION
from layers.instruction_rule_router import instruction_signals
from layers.piguard_scorer import BATCH_SIZE, PIGuardScorer
from layers.segmenter import make_segments

DEFAULT_DOC_ID = "manual-input"
DEFAULT_WINDOW = 3
DEFAULT_STRIDE = 1


def scan_text(text: str, doc_id: str = DEFAULT_DOC_ID) -> list[dict[str, Any]]:
    """Segment text and return both independent detector results per segment."""
    if not text.strip():
        raise ValueError("Input text is empty")

    segments = make_segments(doc_id, text, window=DEFAULT_WINDOW, stride=DEFAULT_STRIDE)
    reasons = [instruction_signals(segment["text"]) for segment in segments]
    scorer = PIGuardScorer(batch_size=BATCH_SIZE)
    piguard_results = scorer.score([segment["text"] for segment in segments])

    results: list[dict[str, Any]] = []
    for segment, instruction_reasons, piguard in zip(segments, reasons, piguard_results):
        results.append({
            "segment_id": segment["segment_id"],
            "doc_id": doc_id,
            "start": segment["start"],
            "end": segment["end"],
            "text": segment["text"],
            "rules_version": RULES_VERSION,
            "is_instruction_like": bool(instruction_reasons),
            "instruction_reasons": instruction_reasons,
            "piguard_label": piguard["piguard_label"],
            "piguard_injection_score": piguard["piguard_injection_score"],
            "truncated": piguard["truncated"],
        })
    return results


def format_text(results: list[dict[str, Any]]) -> str:
    """Render segment results in a readable terminal report."""
    rules_version = results[0].get("rules_version", RULES_VERSION) if results else RULES_VERSION
    blocks: list[str] = [f"Scanned {len(results)} segment(s) with instruction rules {rules_version} (v2 includes v1 checks)."]
    for result in results:
        blocks.extend([
            "",
            f"[{result['segment_id']}] chars {result['start']}:{result['end']}",
            f"Instruction-like: {result['is_instruction_like']}",
            f"Reasons: {', '.join(result['instruction_reasons']) or 'none'}",
            f"PIGuard: {result['piguard_label']} (injection score {result['piguard_injection_score']:.4f})",
            f"Truncated: {result['truncated']}",
            "Segment text:",
            result["text"],
        ])
    return "\n".join(blocks)


def _read_input(args: argparse.Namespace) -> str:
    if args.text is not None:
        return args.text
    if args.file is not None:
        return args.file.read_text(encoding="utf-8")
    return sys.stdin.read()


def main() -> int:
    parser = argparse.ArgumentParser(description="Segment and scan arbitrary text with the rules detector and PIGuard.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="Text to scan; quote it if it contains spaces.")
    source.add_argument("--file", type=Path, help="UTF-8 text file to scan.")
    source.add_argument("--stdin", action="store_true", help="Read all input from standard input.")
    parser.add_argument("--doc-id", default=DEFAULT_DOC_ID, help=f"Document ID used in segment IDs (default: {DEFAULT_DOC_ID}).")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format (default: text).")
    args = parser.parse_args()

    try:
        results = scan_text(_read_input(args), doc_id=args.doc_id)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        output = json.dumps(results, indent=2, ensure_ascii=False)
    else:
        output = format_text(results)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
