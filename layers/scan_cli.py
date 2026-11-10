"""Command-line interface for the unified Layer 1 scan pipeline."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from config import judge_config, layer1_settings
from layers.scan import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline-first prompt-injection scan for external content.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="UTF-8 file to scan")
    source.add_argument("--text", help="Text content to scan")
    parser.add_argument("--task", required=True, help="Trusted user task (not scanned as document content)")
    parser.add_argument("--source-type", required=True, choices=("email", "document", "web", "tool_output"))
    parser.add_argument("--doc-id", help="Stable document ID; defaults to the file stem or manual-input")
    parser.add_argument("--context-note", help="Trusted static context note; never derived from content")
    parser.add_argument("--mode", choices=("all", "cascade"), default=None)
    parser.add_argument("--max-judge-calls", type=int, default=None)
    parser.add_argument("--live", action="store_true", help="Opt in to real Gemini calls; default is offline cache-only")
    parser.add_argument("--max-live-calls", type=int, default=3, help="Live-call cap (maximum 5; default 3)")
    parser.add_argument("--yes", action="store_true", help="Required acknowledgement for --live")
    args = parser.parse_args(argv)
    if args.max_judge_calls is not None and args.max_judge_calls < 0:
        parser.error("--max-judge-calls must be nonnegative")

    judge = None
    budget = args.max_judge_calls
    if args.live:
        if not args.yes:
            parser.error("--live requires --yes")
        if not 1 <= args.max_live_calls <= 5:
            parser.error("--max-live-calls must be between 1 and 5")
        if not os.environ.get(judge_config.API_KEY_ENV):
            print(f"Live mode requires {judge_config.API_KEY_ENV} in the environment.", file=sys.stderr)
            return 2
        from layers.judge import GeminiJudge
        judge = GeminiJudge(rpm=judge_config.RPM_LIMIT)
        budget = args.max_live_calls if budget is None else min(budget, args.max_live_calls)
    elif args.max_live_calls != 3 or args.yes:
        parser.error("--max-live-calls and --yes are only valid with --live")

    try:
        content = args.file.read_text(encoding="utf-8") if args.file else args.text
    except OSError as exc:
        print(f"Could not read input file ({type(exc).__name__}).", file=sys.stderr)
        return 1
    doc_id = args.doc_id or (args.file.stem if args.file else "manual-input")
    try:
        result = scan(
            content, doc_id=doc_id, source_type=args.source_type, user_task=args.task,
            context_note=args.context_note, mode=args.mode, max_judge_calls=budget, judge=judge,
        )
    except Exception as exc:
        # Avoid displaying arbitrary exception text that could contain sensitive environment data.
        print(f"Scan failed ({type(exc).__name__}).", file=sys.stderr)
        return 1

    print(f"Mode: {result.mode}; rules: {result.versions['rules_version']}; judge: {result.versions['judge_model']}")
    print("ID | suspicion | judge coverage | text")
    for row in result.segments:
        preview = " ".join(row["text"].split())
        if len(preview) > 115:
            preview = preview[:112] + "..."
        print(f"{row['segment_id']} | {row['suspicion_level']} | {row['judge_coverage_reason']} | {preview}")
    print("Summary:")
    print(json.dumps(result.summary, indent=2))
    if result.versions.get("manifest_warning"):
        print(result.versions["manifest_warning"])
    if args.live:
        print(f"Live mode was explicitly enabled; this scan made {result.summary['judge_calls_made']} logical judge call(s).")
    elif layer1_settings.OFFLINE_CACHE_ONLY:
        print("Offline cache-only mode; no API client was created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
