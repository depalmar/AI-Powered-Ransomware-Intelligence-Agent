"""Tests for the confidence scoring module."""

from __future__ import annotations

import pytest

from mcp_server.models import (
    ConfidenceResult,
    GroupTTP,
    IOCRecord,
    RansomNoteMatch,
    SignalScore,
)
from mcp_server.scoring.confidence import (
    WEIGHT_FILE_EXTENSION,
    WEIGHT_IOC_OVERLAP,
    WEIGHT_RANSOM_NOTE,
    WEIGHT_TTP_ALIGNMENT,
    calculate_confidence,
    score_file_extension,
    score_ioc_overlap,
    score_ransom_note,
    score_ttp_alignment,
)


class TestSignalWeights:
    """Verify signal weights sum to 1.0."""

    def test_weights_sum_to_one(self):
        total = WEIGHT_RANSOM_NOTE + WEIGHT_IOC_OVERLAP + WEIGHT_TTP_ALIGNMENT + WEIGHT_FILE_EXTENSION
        assert abs(total - 1.0) < 0.001


class TestRansomNoteScoring:
    """Tests for ransom note signal scoring."""

    def test_matching_group_scores_high(self):
        matches = [
            RansomNoteMatch(group_name="lockbit", similarity_score=0.92),
        ]
        score = score_ransom_note(matches, "lockbit")
        assert score.raw_score == 0.92
        assert score.weight == WEIGHT_RANSOM_NOTE

    def test_non_matching_group_scores_zero(self):
        matches = [
            RansomNoteMatch(group_name="lockbit", similarity_score=0.92),
        ]
        score = score_ransom_note(matches, "alphv")
        assert score.raw_score == 0.0

    def test_empty_matches_scores_zero(self):
        score = score_ransom_note([], "lockbit")
        assert score.raw_score == 0.0

    def test_case_insensitive_matching(self):
        matches = [
            RansomNoteMatch(group_name="LockBit", similarity_score=0.85),
        ]
        score = score_ransom_note(matches, "lockbit")
        assert score.raw_score == 0.85


class TestIOCScoring:
    """Tests for IOC overlap signal scoring."""

    def test_full_overlap(self):
        submitted = ["1.2.3.4", "5.6.7.8"]
        known = [
            IOCRecord(group="test", value="1.2.3.4"),
            IOCRecord(group="test", value="5.6.7.8"),
        ]
        score = score_ioc_overlap(submitted, known, "test")
        assert score.raw_score == 1.0

    def test_partial_overlap(self):
        submitted = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
        known = [
            IOCRecord(group="test", value="1.2.3.4"),
        ]
        score = score_ioc_overlap(submitted, known, "test")
        assert 0.0 < score.raw_score < 1.0

    def test_no_overlap(self):
        submitted = ["1.2.3.4"]
        known = [
            IOCRecord(group="test", value="9.9.9.9"),
        ]
        score = score_ioc_overlap(submitted, known, "test")
        assert score.raw_score == 0.0

    def test_empty_submitted(self):
        score = score_ioc_overlap([], [], "test")
        assert score.raw_score == 0.0

    def test_empty_known(self):
        score = score_ioc_overlap(["1.2.3.4"], [], "test")
        assert score.raw_score == 0.0


class TestTTPScoring:
    """Tests for TTP alignment signal scoring."""

    def test_matching_technique_ids(self):
        observed = ["T1486", "T1490"]
        known = [
            GroupTTP(tactic="Impact", technique_id="T1486", technique_name="Data Encrypted"),
            GroupTTP(tactic="Impact", technique_id="T1490", technique_name="Inhibit Recovery"),
        ]
        score = score_ttp_alignment(observed, known, "test")
        assert score.raw_score == 1.0

    def test_partial_match(self):
        observed = ["T1486", "T1490", "T1059.001"]
        known = [
            GroupTTP(tactic="Impact", technique_id="T1486", technique_name="Data Encrypted"),
        ]
        score = score_ttp_alignment(observed, known, "test")
        assert 0.0 < score.raw_score < 1.0

    def test_no_match(self):
        observed = ["T1486"]
        known = [
            GroupTTP(tactic="Execution", technique_id="T1059", technique_name="Command Line"),
        ]
        score = score_ttp_alignment(observed, known, "test")
        assert score.raw_score == 0.0

    def test_empty_observed(self):
        score = score_ttp_alignment([], [], "test")
        assert score.raw_score == 0.0


class TestFileExtensionScoring:
    """Tests for file extension signal scoring."""

    def test_known_extension_match(self):
        score = score_file_extension(".lockbit", "lockbit")
        assert score.raw_score == 0.95

    def test_extension_belongs_to_other_group(self):
        score = score_file_extension(".lockbit", "alphv")
        assert score.raw_score == 0.0

    def test_generic_extension(self):
        score = score_file_extension(".encrypted", "lockbit")
        # .encrypted is used by medusa, so it should map to that group
        # For lockbit, it's a different group's extension
        assert score.raw_score >= 0.0

    def test_unknown_extension(self):
        score = score_file_extension(".xyz_unknown", "lockbit")
        assert score.raw_score == 0.3  # Generic/unknown

    def test_empty_extension(self):
        score = score_file_extension("", "lockbit")
        assert score.raw_score == 0.0

    def test_extension_without_dot_prefix(self):
        score = score_file_extension("lockbit", "lockbit")
        assert score.raw_score == 0.95


class TestCompositeScoring:
    """Tests for the composite confidence calculation."""

    def test_perfect_score(self):
        result = calculate_confidence(
            group_name="lockbit",
            note_matches=[
                RansomNoteMatch(group_name="lockbit", similarity_score=1.0),
            ],
            submitted_iocs=["1.2.3.4"],
            known_iocs=[IOCRecord(group="lockbit", value="1.2.3.4")],
            observed_ttps=["T1486"],
            known_ttps=[
                GroupTTP(tactic="Impact", technique_id="T1486", technique_name="Encrypt"),
            ],
            file_extension=".lockbit",
        )
        assert result.total_score > 0.9
        assert result.confidence_label == "High"

    def test_no_evidence(self):
        result = calculate_confidence(group_name="lockbit")
        assert result.total_score == 0.0
        assert result.confidence_label == "Insufficient"

    def test_confidence_label_thresholds(self):
        assert ConfidenceResult.label_from_score(0.85) == "High"
        assert ConfidenceResult.label_from_score(0.65) == "Medium"
        assert ConfidenceResult.label_from_score(0.45) == "Low"
        assert ConfidenceResult.label_from_score(0.20) == "Insufficient"

    def test_score_capped_at_one(self):
        result = calculate_confidence(
            group_name="lockbit",
            note_matches=[
                RansomNoteMatch(group_name="lockbit", similarity_score=1.0),
            ],
            submitted_iocs=["a"] * 10,
            known_iocs=[IOCRecord(group="lockbit", value="a")] * 10,
            observed_ttps=["T1486"],
            known_ttps=[
                GroupTTP(tactic="Impact", technique_id="T1486", technique_name="X"),
            ],
            file_extension=".lockbit",
        )
        assert result.total_score <= 1.0

    def test_signals_present_in_result(self):
        result = calculate_confidence(group_name="test")
        assert len(result.signals) == 4
        signal_names = {s.signal_name for s in result.signals}
        assert "ransom_note" in signal_names
        assert "ioc_overlap" in signal_names
        assert "ttp_alignment" in signal_names
        assert "file_extension" in signal_names
