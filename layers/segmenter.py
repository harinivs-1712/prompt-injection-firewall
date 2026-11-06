"""
layers/segmenter.py

Content segmentation for the prompt-injection-firewall project.

Responsibilities:
  - Split raw document text into individual sentences (with char offsets).
  - Group sentences into overlapping windows to form segments.
  - Assign every segment a stable, unique ID.
  - Guarantee: segment["text"] == original_text[segment["start"]:segment["end"]]

Edge cases handled:
  - Common abbreviations (Dr., Mr., e.g., i.e., approx., vs., etc.)
    are NOT treated as sentence boundaries.
  - Decimal numbers like 3.14 or 5000.50 are not split.
  - Bullet lists / headings with no trailing punctuation use blank-line
    boundaries (two or more consecutive newlines).
  - Files with fewer sentences than the window size still produce segments.
  - Segments are never empty (empty-string segments are dropped).

Implementation note on lookbehind:
  Python's `re` module requires fixed-width lookbehinds. We cannot use
  `(?<!Dr|Mr|...)` with variable-length alternatives. Instead we use a
  two-pass strategy:
    Pass 1 — naive split on sentence-ending punctuation + whitespace/capital
              OR double newline.
    Pass 2 — merge any split that was preceded by a known abbreviation or
              a digit (to handle decimals like 3.14).
"""

import re
import json
from pathlib import Path
from typing import List, Tuple, Dict, Any

# ---------------------------------------------------------------------------
# Abbreviations whose trailing period should NOT end a sentence
# ---------------------------------------------------------------------------

_ABBREVS: set = {
    # Titles / honorifics
    "dr", "mr", "mrs", "ms", "prof", "rev", "gen",
    "sgt", "cpl", "pvt", "sen", "rep", "gov",
    # Latin / English shortforms
    "e.g", "i.e", "etc", "approx", "vs", "cf",
    "p.m", "a.m",
    "no", "vol", "pp", "ed", "eds",
    # Units
    "km", "mi", "ft", "lb", "kg", "min", "sec", "hr",
    # Month abbreviations
    "jan", "feb", "mar", "apr", "jun", "jul",
    "aug", "sep", "oct", "nov", "dec",
    # Place / org suffixes
    "st", "ave", "blvd", "dept", "univ", "corp",
    "inc", "ltd", "llc",
}

# Pass 1: naive split pattern
# Split at:
#   (a) [.!?] followed by optional whitespace then a capital letter
#   (b) Two or more consecutive newlines (paragraph / heading boundary)
_NAIVE_SPLIT_RE = re.compile(
    r"(?<=[.!?])\s+(?=[A-Z])"   # (a) punctuation then capital
    r"|"
    r"\n{2,}",                   # (b) blank line
    re.MULTILINE,
)

# Pass 2: detect false splits caused by abbreviations or decimals
# A split is "false" if the token immediately before the period is:
#   - a known abbreviation token (case-insensitive), OR
#   - a digit  (handles "3.14", "$5,000.50", "approx. 20")
_TRAILING_TOKEN_RE = re.compile(r"(\S+)\.$")


def _is_false_split(left_chunk: str) -> bool:
    """
    Return True if the right edge of *left_chunk* looks like an abbreviation
    or decimal, meaning the split boundary should be merged back.
    """
    stripped = left_chunk.rstrip()

    # Decimal / numeric: last char before period is a digit
    # e.g.  "total is $1,147.94"  →  stripped ends with "4" then "."
    # We check the last character of the stripped text
    if stripped and stripped[-1].isdigit():
        return True

    # Abbreviation: last token (before trailing period) is in our set
    m = _TRAILING_TOKEN_RE.search(stripped)
    if m:
        token_before_period = m.group(1).lower().rstrip(".")
        if token_before_period in _ABBREVS:
            return True

    return False


def split_sentences(text: str) -> List[Tuple[int, int]]:
    """
    Return a list of (start, end) character-offset pairs for each sentence.

    Invariant guaranteed: for every (s, e), text[s:e].strip() != "".

    Algorithm:
      1. Naively split *text* at sentence-ending punctuation + capital or
         double newlines.
      2. Re-merge any split where the left side ends with a known
         abbreviation or digit (to avoid splitting "Dr. Smith" or "3.14").
      3. Collect tight (stripped) offsets for each final chunk.
    """
    # --- Pass 1: collect raw chunks and their start positions in text -------
    raw_chunks: List[Tuple[int, str]] = []  # (absolute_start, chunk_text)
    cursor = 0
    for m in _NAIVE_SPLIT_RE.finditer(text):
        chunk = text[cursor: m.start()]
        raw_chunks.append((cursor, chunk))
        cursor = m.end()
    # Remainder
    raw_chunks.append((cursor, text[cursor:]))

    # --- Pass 2: merge false splits ------------------------------------------
    merged: List[Tuple[int, str]] = []
    for abs_start, chunk in raw_chunks:
        if merged and _is_false_split(merged[-1][1]):
            # Extend the previous chunk to include this one (re-add the
            # whitespace that the split consumed by computing from offsets).
            prev_start, prev_chunk = merged[-1]
            # The gap between prev_chunk's end and abs_start is the split
            # whitespace; recover it from the original text.
            prev_end_in_text = prev_start + len(prev_chunk)
            gap = text[prev_end_in_text: abs_start]
            merged[-1] = (prev_start, prev_chunk + gap + chunk)
        else:
            merged.append((abs_start, chunk))

    # --- Collect tight offsets -----------------------------------------------
    spans: List[Tuple[int, int]] = []
    for abs_start, chunk in merged:
        stripped = chunk.strip()
        if not stripped:
            continue
        # Find the tight start/end within the original text
        leading_ws = len(chunk) - len(chunk.lstrip())
        trailing_ws = len(chunk) - len(chunk.rstrip())
        tight_start = abs_start + leading_ws
        tight_end = abs_start + len(chunk) - trailing_ws
        if tight_end > tight_start:
            spans.append((tight_start, tight_end))

    return spans


def _segment_id(doc_id: str, window: int, index: int) -> str:
    """Generate a deterministic, human-readable segment ID."""
    return f"{doc_id}-w{window}-{index:04d}"


def make_segments(
    doc_id: str,
    text: str,
    window: int = 3,
    stride: int = 1,
) -> List[Dict[str, Any]]:
    """
    Produce overlapping sentence-window segments from *text*.

    Parameters
    ----------
    doc_id  : Unique identifier for the source document.
    text    : Full raw document text.
    window  : Number of sentences per segment.
    stride  : Step size between consecutive windows.

    Returns
    -------
    List of segment dicts with keys:
      segment_id  — unique string ID
      doc_id      — source document identifier
      window_size — number of sentences in this segment
      sent_index  — index of the first sentence in this segment
      start       — start char offset in *text*
      end         — end char offset in *text*
      text        — text[start:end]  (guaranteed invariant)
    """
    sentences = split_sentences(text)
    segments: List[Dict[str, Any]] = []

    if not sentences:
        return segments

    # If the document has fewer sentences than the window, yield one segment
    # containing all sentences.
    effective_window = min(window, len(sentences))
    step = max(1, stride)

    num_windows = max(1, len(sentences) - effective_window + 1)

    for i in range(0, num_windows, step):
        chunk = sentences[i : i + effective_window]
        seg_start = chunk[0][0]
        seg_end = chunk[-1][1]
        seg_text = text[seg_start:seg_end]

        # Skip empty segments (e.g., windows that collapse to whitespace)
        if not seg_text.strip():
            continue

        segments.append(
            {
                "segment_id": _segment_id(doc_id, effective_window, i),
                "doc_id": doc_id,
                "window_size": effective_window,
                "sent_index": i,
                "start": seg_start,
                "end": seg_end,
                "text": seg_text,
            }
        )

    return segments


# ---------------------------------------------------------------------------
# Batch runner: process all files in data/original/ → data/segments/
# ---------------------------------------------------------------------------

def process_file(src_path: Path, out_dir: Path, window: int = 3, stride: int = 1) -> Dict[str, Any]:
    """
    Read a document from *src_path*, segment it, write JSON to *out_dir*,
    and return a summary dict.
    """
    text = src_path.read_text(encoding="utf-8")
    doc_id = src_path.stem  # filename without extension, e.g. "doc_01_invoice"

    segments = make_segments(doc_id, text, window=window, stride=stride)

    output = {
        "doc_id": doc_id,
        "source_file": str(src_path),
        "char_length": len(text),
        "sentence_count": len(split_sentences(text)),
        "segment_count": len(segments),
        "window_size": window,
        "stride": stride,
        "segments": segments,
    }

    out_path = out_dir / f"{doc_id}.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "doc_id": doc_id,
        "sentences": output["sentence_count"],
        "segments": output["segment_count"],
        "out_file": str(out_path),
    }


def run_all(
    data_dir: Path = None,
    window: int = 3,
    stride: int = 1,
) -> None:
    """Segment every .txt file in data/original/ and save to data/segments/."""
    if data_dir is None:
        # Resolve relative to this script's location
        data_dir = Path(__file__).parent.parent / "data"

    original_dir = data_dir / "original"
    segments_dir = data_dir / "segments"
    segments_dir.mkdir(parents=True, exist_ok=True)

    txt_files = sorted(original_dir.glob("*.txt"))
    if not txt_files:
        print("No .txt files found in", original_dir)
        return

    print(f"Processing {len(txt_files)} file(s) with window={window}, stride={stride}\n")
    print(f"{'File':<35} {'Sentences':>10} {'Segments':>10}")
    print("-" * 60)

    for path in txt_files:
        summary = process_file(path, segments_dir, window=window, stride=stride)
        print(
            f"{summary['doc_id']:<35} {summary['sentences']:>10} {summary['segments']:>10}"
        )

    print("-" * 60)
    print(f"\nSegment JSON files written to: {segments_dir}\n")


if __name__ == "__main__":
    run_all()
