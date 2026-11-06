"""
tests/test_segmenter.py

Unit tests for layers/segmenter.py

Run with:
    pytest tests/ -v

Test categories:
  1. Core invariant — segment["text"] == original[start:end]
  2. Unique IDs
  3. No empty segments
  4. Edge case: short document (< window sentences)
  5. Edge case: single sentence
  6. Edge case: empty string
  7. Abbreviations should NOT split ("Dr.", "e.g.", decimal numbers)
  8. Bullet / heading text with no terminal period uses blank-line split
  9. All 10 sample documents round-trip correctly
"""

import sys
import json
import pytest
from pathlib import Path

# Allow importing from project root when running from any directory
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from layers.segmenter import split_sentences, make_segments, process_file

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLES_DIR = PROJECT_ROOT / "data" / "original"
SEGMENTS_DIR = PROJECT_ROOT / "data" / "segments"

SAMPLE_FILES = sorted(SAMPLES_DIR.glob("*.txt"))


# ---------------------------------------------------------------------------
# 1. Core invariant: text == original[start:end]
# ---------------------------------------------------------------------------

class TestCoreInvariant:

    def _check_invariant(self, text: str, doc_id: str = "test-doc") -> None:
        segments = make_segments(doc_id, text)
        for seg in segments:
            assert seg["text"] == text[seg["start"]:seg["end"]], (
                f"Invariant broken for segment {seg['segment_id']}: "
                f"stored text does not match original[start:end]"
            )

    def test_simple_paragraph(self):
        text = (
            "The quick brown fox jumps over the lazy dog. "
            "It was a sunny afternoon in the park. "
            "Nobody expected what happened next."
        )
        self._check_invariant(text)

    def test_multiline_paragraph(self):
        text = "First paragraph sentence one. First paragraph sentence two.\n\nSecond paragraph starts here. It continues on."
        self._check_invariant(text)

    def test_question_and_exclamation(self):
        text = "Is this a test? Yes, it is! Great, let's continue."
        self._check_invariant(text)

    def test_with_newlines_mixed(self):
        text = "Line one ends here.\nLine two starts here.\n\nNew paragraph."
        self._check_invariant(text)


# ---------------------------------------------------------------------------
# 2. Unique IDs
# ---------------------------------------------------------------------------

class TestUniqueIds:

    def test_no_duplicate_ids(self):
        text = " ".join([f"This is sentence number {i}." for i in range(20)])
        segments = make_segments("uniqueness-test", text)
        ids = [s["segment_id"] for s in segments]
        assert len(ids) == len(set(ids)), "Duplicate segment IDs found"

    def test_ids_contain_doc_id(self):
        text = "Sentence one. Sentence two. Sentence three. Sentence four."
        doc_id = "my-special-doc"
        segments = make_segments(doc_id, text)
        for seg in segments:
            assert seg["segment_id"].startswith(doc_id), (
                f"Segment ID '{seg['segment_id']}' does not start with doc_id '{doc_id}'"
            )


# ---------------------------------------------------------------------------
# 3. No empty segments
# ---------------------------------------------------------------------------

class TestNoEmptySegments:

    def test_no_empty_text(self):
        text = "Alpha. Beta. Gamma. Delta. Epsilon."
        segments = make_segments("empty-test", text)
        for seg in segments:
            assert seg["text"].strip() != "", f"Empty segment found: {seg}"

    def test_whitespace_only_input(self):
        text = "   \n\n   "
        segments = make_segments("ws-doc", text)
        assert segments == [], "Expected no segments from whitespace-only input"

    def test_empty_string_input(self):
        segments = make_segments("empty-doc", "")
        assert segments == [], "Expected no segments from empty string"


# ---------------------------------------------------------------------------
# 4. Edge case: short document (fewer sentences than window size)
# ---------------------------------------------------------------------------

class TestShortDocuments:

    def test_two_sentences_window_three(self):
        text = "Only two sentences here. This is the second one."
        segments = make_segments("short-doc", text, window=3)
        # Should produce exactly 1 segment containing both sentences
        assert len(segments) == 1, f"Expected 1 segment, got {len(segments)}"
        # Invariant must still hold
        for seg in segments:
            assert seg["text"] == text[seg["start"]:seg["end"]]

    def test_one_sentence_window_three(self):
        text = "Just one sentence."
        segments = make_segments("one-sent", text, window=3)
        assert len(segments) == 1
        assert segments[0]["text"] == text[segments[0]["start"]:segments[0]["end"]]

    def test_zero_sentences(self):
        text = ""
        segments = make_segments("zero-sent", text, window=3)
        assert segments == []


# ---------------------------------------------------------------------------
# 5. Abbreviation edge cases
# ---------------------------------------------------------------------------

class TestAbbreviations:

    def test_dr_abbreviation(self):
        """'Dr. Smith' should not be split into two sentences."""
        text = "The patient was seen by Dr. Smith at the clinic. He was given a prescription."
        sentences = split_sentences(text)
        # Should produce 2 sentences, not 3
        assert len(sentences) == 2, (
            f"Expected 2 sentences (Dr. should not split), got {len(sentences)}: "
            f"{[text[s:e] for s,e in sentences]}"
        )

    def test_eg_abbreviation(self):
        """'e.g.' should not be treated as a sentence boundary."""
        text = (
            "Common colors include warm tones, e.g. red, orange, and yellow. "
            "Cool tones include blue and green."
        )
        sentences = split_sentences(text)
        assert len(sentences) == 2, (
            f"Expected 2 sentences, got {len(sentences)}: "
            f"{[text[s:e] for s,e in sentences]}"
        )

    def test_decimal_number(self):
        """'3.14' or '5000.50' should not cause a sentence split."""
        text = "The value of pi is approximately 3.14159. This is used in geometry calculations."
        sentences = split_sentences(text)
        assert len(sentences) == 2, (
            f"Expected 2 sentences (decimal should not split), got {len(sentences)}: "
            f"{[text[s:e] for s,e in sentences]}"
        )

    def test_price_decimal(self):
        """'$1,147.94' should not split."""
        text = "The total due is $1,147.94. Please pay within 30 days."
        sentences = split_sentences(text)
        assert len(sentences) == 2, (
            f"Expected 2 sentences, got {len(sentences)}: "
            f"{[text[s:e] for s,e in sentences]}"
        )


# ---------------------------------------------------------------------------
# 6. Bullet list / heading with blank-line boundary
# ---------------------------------------------------------------------------

class TestBlankLineSplitting:

    def test_bullet_list_no_period(self):
        """Blank lines should act as paragraph boundaries."""
        text = (
            "Project goals for this quarter:\n\n"
            "- Improve test coverage\n"
            "- Reduce bug count\n"
            "- Ship new dashboard\n\n"
            "These will be reviewed in December."
        )
        sentences = split_sentences(text)
        assert len(sentences) >= 2, (
            f"Expected at least 2 segments from blank-line-separated content, "
            f"got {len(sentences)}"
        )

    def test_heading_no_period(self):
        text = "INTRODUCTION\n\nThis section covers the background. It is important to read carefully."
        sentences = split_sentences(text)
        assert len(sentences) >= 2


# ---------------------------------------------------------------------------
# 7. All 10 sample files — invariant + non-empty + at least 1 segment
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filepath", SAMPLE_FILES, ids=[f.name for f in SAMPLE_FILES])
class TestSampleFiles:

    def test_invariant(self, filepath):
        """For every segment: text == original[start:end]."""
        text = filepath.read_text(encoding="utf-8")
        doc_id = filepath.stem
        segments = make_segments(doc_id, text)
        for seg in segments:
            assert seg["text"] == text[seg["start"]:seg["end"]], (
                f"[{filepath.name}] Invariant broken in segment {seg['segment_id']}"
            )

    def test_no_empty_segments(self, filepath):
        text = filepath.read_text(encoding="utf-8")
        segments = make_segments(filepath.stem, text)
        for seg in segments:
            assert seg["text"].strip() != "", (
                f"[{filepath.name}] Empty segment found: {seg['segment_id']}"
            )

    def test_produces_segments(self, filepath):
        text = filepath.read_text(encoding="utf-8")
        segments = make_segments(filepath.stem, text)
        assert len(segments) >= 1, (
            f"[{filepath.name}] Expected at least 1 segment, got 0"
        )

    def test_unique_ids(self, filepath):
        text = filepath.read_text(encoding="utf-8")
        segments = make_segments(filepath.stem, text)
        ids = [s["segment_id"] for s in segments]
        assert len(ids) == len(set(ids)), (
            f"[{filepath.name}] Duplicate segment IDs: {ids}"
        )

    def test_json_roundtrip(self, filepath, tmp_path):
        """Ensure JSON serialization is lossless."""
        text = filepath.read_text(encoding="utf-8")
        summary = process_file(filepath, tmp_path)
        json_path = tmp_path / f"{filepath.stem}.json"
        loaded = json.loads(json_path.read_text(encoding="utf-8"))
        assert loaded["doc_id"] == filepath.stem
        assert loaded["segment_count"] == summary["segments"]
        # Re-check invariant from the loaded JSON
        for seg in loaded["segments"]:
            assert seg["text"] == text[seg["start"]:seg["end"]], (
                f"[{filepath.name}] Invariant broken after JSON round-trip in {seg['segment_id']}"
            )
