"""Tests for ransom note matching logic."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_server.embeddings.embed import keyword_match
from mcp_server.models import RansomNoteMatch

FIXTURES = Path(__file__).parent / "fixtures"


class TestKeywordMatching:
    """Tests for keyword-based ransom note matching."""

    def test_lockbit_keywords_detected(self):
        note = "Your data has been stolen and encrypted by LockBit 3.0"
        matches = keyword_match(note)
        assert len(matches) > 0
        # LockBit should be the top match
        assert matches[0][0] == "lockbit"
        assert matches[0][1] > 0.0

    def test_alphv_keywords_detected(self):
        note = "BlackCat/ALPHV ransomware has encrypted your files"
        matches = keyword_match(note)
        assert len(matches) > 0
        group_names = [m[0] for m in matches]
        assert "alphv" in group_names

    def test_clop_keywords_detected(self):
        note = "This is cl0p ransomware. Your files are encrypted."
        matches = keyword_match(note)
        assert len(matches) > 0
        group_names = [m[0] for m in matches]
        assert "clop" in group_names

    def test_empty_note_returns_empty(self):
        matches = keyword_match("")
        assert matches == []

    def test_generic_note_may_not_match(self):
        note = "Your files have been encrypted. Pay us."
        matches = keyword_match(note)
        # Generic note might match some groups or none
        # Just verify it doesn't crash
        assert isinstance(matches, list)

    def test_scores_are_capped(self):
        note = "lockbit lockbit3 lb3 lockbit ransomware restore-my-files lockbit-decryptor"
        matches = keyword_match(note)
        for _, score in matches:
            assert score <= 0.85

    def test_matches_sorted_by_score(self):
        note = "LockBit 3.0 has encrypted your files. ALPHV backup encryption."
        matches = keyword_match(note)
        if len(matches) >= 2:
            scores = [m[1] for m in matches]
            assert scores == sorted(scores, reverse=True)


class TestRansomNoteMatch:
    """Tests for the RansomNoteMatch model."""

    def test_model_creation(self):
        match = RansomNoteMatch(
            group_name="lockbit",
            similarity_score=0.85,
            matched_note_preview="Your files have been...",
            match_method="embedding",
        )
        assert match.group_name == "lockbit"
        assert match.similarity_score == 0.85
        assert match.match_method == "embedding"

    def test_model_defaults(self):
        match = RansomNoteMatch(
            group_name="test",
            similarity_score=0.5,
        )
        assert match.matched_note_preview == ""
        assert match.match_method == "embedding"

    def test_fixture_notes_load(self):
        with open(FIXTURES / "sample_ransom_notes.json") as f:
            notes = json.load(f)
        assert "lockbit_style" in notes
        assert "alphv_style" in notes
        assert len(notes["lockbit_style"]) > 0
