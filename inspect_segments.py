"""
inspect_segments.py

A quick interactive tool to visually inspect segmenter output.
Run from the project root with the venv activated.

Usage examples:
  # Show all segments for one document
  python inspect_segments.py --doc doc_10_product_catalog

  # Show only first N segments
  python inspect_segments.py --doc doc_06_article --limit 5

  # Test a raw string directly (great for edge cases)
  python inspect_segments.py --text "Dr. Smith charged $5,000.50. The invoice is due Nov. 30."

  # Run the built-in edge case gallery
  python inspect_segments.py --edge-cases
"""

import sys
import io
import json
import argparse
# Force UTF-8 output on Windows so box-drawing chars don't crash
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from layers.segmenter import split_sentences, make_segments

ROOT = Path(__file__).parent
SEG_DIR = ROOT / "data" / "segments"
ORI_DIR = ROOT / "data" / "original"

# ANSI colors (Windows 10+ supports these; fall back gracefully)
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"


def divider(char="─", width=70):
    print(char * width)


def show_segments(doc_id: str, text: str, limit: int = None):
    segments = make_segments(doc_id, text)
    sentences = split_sentences(text)

    print(f"\n{BOLD}{CYAN}Document:{RESET} {doc_id}")
    print(f"{BOLD}Sentences detected:{RESET} {len(sentences)}")
    print(f"{BOLD}Segments produced:{RESET} {len(segments)}")
    divider()

    shown = segments if limit is None else segments[:limit]
    for seg in shown:
        # Verify invariant inline
        actual = text[seg["start"]:seg["end"]]
        ok = actual == seg["text"]
        status = f"{GREEN}✓ invariant ok{RESET}" if ok else f"{RED}✗ INVARIANT BROKEN{RESET}"

        print(f"\n{BOLD}[{seg['segment_id']}]{RESET}  chars {seg['start']}–{seg['end']}  {status}")
        print(f"{DIM}{'─'*60}{RESET}")
        # Show text with newlines visible
        display = seg["text"].replace("\n", "↵\n")
        print(display)

    if limit and len(segments) > limit:
        print(f"\n{YELLOW}... {len(segments) - limit} more segments not shown (remove --limit to see all){RESET}")


def show_sentences(text: str, label: str = "input"):
    """Print individual sentences with offsets — useful for edge case debugging."""
    spans = split_sentences(text)
    print(f"\n{BOLD}{CYAN}Input:{RESET} {label}")
    print(f"{BOLD}Sentences detected:{RESET} {len(spans)}")
    divider()
    for i, (s, e) in enumerate(spans):
        chunk = text[s:e]
        print(f"\n  {BOLD}Sentence {i+1}{RESET}  [{s}:{e}]")
        print(f"  {repr(chunk)}")


EDGE_CASES = [
    {
        "label": "Abbreviation: Dr. should NOT split",
        "text": "The patient was treated by Dr. Smith at the clinic. He was discharged the next day.",
        "expected": 2,
    },
    {
        "label": "Abbreviation: e.g. should NOT split",
        "text": "Warm colors, e.g. red and orange, are energizing. Cool colors are calming.",
        "expected": 2,
    },
    {
        "label": "Abbreviation: approx. should NOT split",
        "text": "Assembly takes approx. 20 minutes. Tools are included.",
        "expected": 2,
    },
    {
        "label": "Abbreviation: Nov. (month) should NOT split",
        "text": "The deadline is Nov. 30. Please submit before midnight.",
        "expected": 2,
    },
    {
        "label": "Decimal number: 3.14 should NOT split",
        "text": "Pi is approximately 3.14159. It is used in many calculations.",
        "expected": 2,
    },
    {
        "label": "Price decimal: $1,147.94 should NOT split",
        "text": "The total due is $1,147.94. Payment is due within 30 days.",
        "expected": 2,
    },
    {
        "label": "Short doc: fewer sentences than window=3",
        "text": "Only two sentences here. This is the second one.",
        "expected_segs": 1,
    },
    {
        "label": "Single sentence doc",
        "text": "Just one sentence with no terminal punctuation",
        "expected_segs": 1,
    },
    {
        "label": "Empty string",
        "text": "",
        "expected_segs": 0,
    },
    {
        "label": "Bullet list — blank lines act as boundaries",
        "text": "Project goals:\n\n- Improve test coverage\n- Reduce bugs\n\nThese will be reviewed next month.",
        "expected": ">=2",
    },
    {
        "label": "Question mark split",
        "text": "Is this a valid sentence? Yes, it is! Great, let us continue now.",
        "expected": 3,
    },
    {
        "label": "Multiple abbreviations in one sentence",
        "text": "Dr. Smith and Prof. Jones, e.g. two experts, confirmed the results. The paper was published.",
        "expected": 2,
    },
]


def run_edge_cases():
    print(f"\n{BOLD}{CYAN}═══ EDGE CASE GALLERY ═══{RESET}\n")
    passed = 0
    failed = 0

    for ec in EDGE_CASES:
        text = ec["text"]
        label = ec["label"]
        spans = split_sentences(text)
        segs = make_segments("edge-case", text)

        # Determine expected
        exp_sents = ec.get("expected")
        exp_segs = ec.get("expected_segs")

        # Evaluate
        if exp_sents == ">=2":
            ok = len(spans) >= 2
            exp_str = "≥2 sentences"
        elif exp_sents is not None:
            ok = len(spans) == exp_sents
            exp_str = f"{exp_sents} sentences"
        elif exp_segs is not None:
            ok = len(segs) == exp_segs
            exp_str = f"{exp_segs} segments"
        else:
            ok = True
            exp_str = "—"

        status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        if ok:
            passed += 1
        else:
            failed += 1

        print(f"  {status}  {label}")
        print(f"         Expected: {exp_str}")
        print(f"         Got:      {len(spans)} sentence(s), {len(segs)} segment(s)")
        if not ok or True:  # always show the detected sentences
            for i, (s, e) in enumerate(spans):
                print(f"         [{i+1}] {repr(text[s:e][:80])}")
        print()

    divider()
    print(f"\n  Results: {GREEN}{passed} passed{RESET}  |  {RED}{failed} failed{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Inspect segmenter output")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--doc", help="Document ID, e.g. doc_10_product_catalog")
    group.add_argument("--text", help="Raw text to segment (wrap in quotes)")
    group.add_argument("--edge-cases", action="store_true", help="Run built-in edge case gallery")
    parser.add_argument("--limit", type=int, default=None, help="Max segments to show for --doc")
    parser.add_argument("--sentences", action="store_true", help="Show individual sentences instead of windows")

    args = parser.parse_args()

    if args.edge_cases:
        run_edge_cases()
        return

    if args.text:
        text = args.text
        doc_id = "cli-input"
    else:
        txt_path = ORI_DIR / f"{args.doc}.txt"
        if not txt_path.exists():
            print(f"{RED}File not found:{RESET} {txt_path}")
            print(f"Available docs: {[f.stem for f in sorted(ORI_DIR.glob('*.txt'))]}")
            sys.exit(1)
        text = txt_path.read_text(encoding="utf-8")
        doc_id = args.doc

    if args.sentences:
        show_sentences(text, label=doc_id)
    else:
        show_segments(doc_id, text, limit=args.limit)


if __name__ == "__main__":
    main()
