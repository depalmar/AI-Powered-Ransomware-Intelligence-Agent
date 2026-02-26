"""Tests for IR brief generation and related utilities."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_server.models import (
    AttributionResult,
    ConfidenceResult,
    IncidentArtifacts,
    IRBriefData,
    NegotiationAdvisory,
    RansomNoteArtifact,
    SignalScore,
    VictimInfo,
)
from mcp_server.tools.ioc_lookup import classify_ioc, extract_ioc_value
from mcp_server.models import IOCType

FIXTURES = Path(__file__).parent / "fixtures"


class TestIOCClassification:
    """Tests for IOC type detection."""

    def test_sha256_detection(self):
        result = classify_ioc("abcdef1234567890" * 4)
        assert result == IOCType.SHA256

    def test_sha1_detection(self):
        result = classify_ioc("abcdef1234567890abcdef1234567890abcdef12")
        assert result == IOCType.SHA1

    def test_md5_detection(self):
        result = classify_ioc("abcdef1234567890abcdef1234567890")
        assert result == IOCType.MD5

    def test_ip_detection(self):
        result = classify_ioc("192.168.1.1")
        assert result == IOCType.IP

    def test_domain_detection(self):
        result = classify_ioc("malware.example.com")
        assert result == IOCType.DOMAIN

    def test_prefixed_hash(self):
        result = classify_ioc("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        assert result == IOCType.SHA256

    def test_unknown_value(self):
        result = classify_ioc("not-an-ioc")
        assert result is None

    def test_empty_string(self):
        result = classify_ioc("")
        assert result is None


class TestIOCValueExtraction:
    """Tests for IOC value extraction."""

    def test_strips_sha256_prefix(self):
        result = extract_ioc_value("sha256:abc123")
        assert result == "abc123"

    def test_strips_md5_prefix(self):
        result = extract_ioc_value("md5:abc123")
        assert result == "abc123"

    def test_preserves_unprefixed(self):
        result = extract_ioc_value("192.168.1.1")
        assert result == "192.168.1.1"

    def test_strips_whitespace(self):
        result = extract_ioc_value("  192.168.1.1  ")
        assert result == "192.168.1.1"


class TestIRBriefDataModel:
    """Tests for the IR brief data model."""

    def test_minimal_brief_data(self):
        data = IRBriefData(
            incident_id="TEST-001",
            artifacts=IncidentArtifacts(incident_id="TEST-001"),
            attribution=AttributionResult(
                primary_group="Unknown",
                confidence=ConfidenceResult(
                    group_name="Unknown",
                    total_score=0.0,
                    confidence_pct=0.0,
                    confidence_label="Insufficient",
                ),
            ),
        )
        assert data.incident_id == "TEST-001"
        assert data.attribution.primary_group == "Unknown"

    def test_full_brief_data(self):
        data = IRBriefData(
            incident_id="TEST-002",
            artifacts=IncidentArtifacts(
                incident_id="TEST-002",
                victim=VictimInfo(company="Test Corp", sector="Tech"),
                ransom_note=RansomNoteArtifact(
                    filename="README.txt",
                    content="Your files are encrypted",
                ),
                file_extension=".locked",
            ),
            attribution=AttributionResult(
                primary_group="lockbit",
                confidence=ConfidenceResult(
                    group_name="lockbit",
                    total_score=0.85,
                    confidence_pct=85.0,
                    confidence_label="High",
                    signals=[
                        SignalScore(
                            signal_name="ransom_note",
                            raw_score=0.92,
                            weight=0.35,
                            weighted_score=0.322,
                            detail="92% match",
                        ),
                    ],
                ),
            ),
            negotiation=NegotiationAdvisory(
                typical_demand_range="$500K-$2M",
                avg_discount_pct=30.0,
                response_window="48-72 hours",
            ),
            recommended_actions=["Isolate hosts", "Deploy YARA rules"],
            executive_summary="Test Corp was targeted by lockbit.",
        )
        assert data.attribution.confidence.confidence_pct == 85.0
        assert len(data.recommended_actions) == 2
        assert data.negotiation.avg_discount_pct == 30.0


class TestScenarioFixture:
    """Tests for the demo scenario fixture."""

    def test_scenario_loads(self):
        scenario_path = Path(__file__).parent.parent / "demo" / "scenario.json"
        with open(scenario_path) as f:
            data = json.load(f)

        assert data["incident_id"] == "IR-2026-0219"
        assert data["victim"]["company"] == "Pinnacle Manufacturing Corp"

    def test_scenario_has_all_artifact_types(self):
        scenario_path = Path(__file__).parent.parent / "demo" / "scenario.json"
        with open(scenario_path) as f:
            data = json.load(f)

        artifacts = data["artifacts"]
        assert "ransom_note" in artifacts
        assert "hashes" in artifacts
        assert "file_extension" in artifacts
        assert "network_iocs" in artifacts
        assert "persistence" in artifacts
        assert "lateral_movement" in artifacts
        assert "lolbas" in artifacts

    def test_scenario_ransom_note_is_detailed(self):
        scenario_path = Path(__file__).parent.parent / "demo" / "scenario.json"
        with open(scenario_path) as f:
            data = json.load(f)

        note = data["artifacts"]["ransom_note"]["content"]
        assert len(note) > 200  # Detailed enough for matching
        assert "PMC-8A3F-29D1-CC47" in note  # Has a victim ID
