#!/usr/bin/env python3
"""Live API integration tests — validates connectivity and data flow.

These tests hit the real ransomware.live API. They are skipped automatically
if no API key is configured (unit tests still run without a key).

Run with:
    pytest tests/test_live_api.py -v
    pytest tests/test_live_api.py -v -k "free"     # free endpoints only
    pytest tests/test_live_api.py -v -k "pro"       # PRO endpoints only

Requires:
    RANSOMWARE_LIVE_PRO_KEY set in .env or environment
"""

from __future__ import annotations

import os
import pytest

from mcp_server.config import settings

# Skip all tests in this module if no API key is configured
pytestmark = pytest.mark.skipif(
    not settings.has_pro_api,
    reason="RANSOMWARE_LIVE_PRO_KEY not set — skipping live API tests",
)

# Also define a marker for free-only tests that can always run
needs_pro = pytest.mark.skipif(
    not settings.has_pro_api,
    reason="PRO API key required",
)


# ---------------------------------------------------------------------------
# Free API tests (run even without PRO key)
# ---------------------------------------------------------------------------

class TestFreeAPILive:
    """Tests against the free ransomware.live API."""

    # Override the module-level skip for free tests
    pytestmark = []

    @pytest.mark.asyncio
    async def test_get_groups(self):
        """Verify we can fetch the groups list."""
        from mcp_server.api.client import APIClient
        from mcp_server.api.free_api import FreeAPI

        async with APIClient() as client:
            free = FreeAPI(client)
            groups = await free.get_groups()

        assert isinstance(groups, list)
        assert len(groups) > 0, "Expected at least some groups from the API"
        # Each group should have a name
        first = groups[0]
        assert "name" in first, f"Group missing 'name' field: {first}"

    @pytest.mark.asyncio
    async def test_get_group_profile(self):
        """Verify we can fetch a specific group profile."""
        from mcp_server.api.client import APIClient
        from mcp_server.api.free_api import FreeAPI

        async with APIClient() as client:
            free = FreeAPI(client)
            profile = await free.get_group("lockbit3")

        assert profile is not None, "lockbit3 profile should exist"
        assert profile.name, "Profile should have a name"

    @pytest.mark.asyncio
    async def test_get_recent_victims(self):
        """Verify we can fetch recent victims."""
        from mcp_server.api.client import APIClient
        from mcp_server.api.free_api import FreeAPI

        async with APIClient() as client:
            free = FreeAPI(client)
            victims = await free.get_recent_victims()

        assert isinstance(victims, list)
        assert len(victims) > 0, "Expected some recent victims"

    @pytest.mark.asyncio
    async def test_search_victims(self):
        """Verify victim search works."""
        from mcp_server.api.client import APIClient
        from mcp_server.api.free_api import FreeAPI

        async with APIClient() as client:
            free = FreeAPI(client)
            results = await free.search_victims("manufacturing")

        assert isinstance(results, list)
        # Manufacturing should have some hits

    @pytest.mark.asyncio
    async def test_get_yara_rules(self):
        """Verify YARA rules can be fetched."""
        from mcp_server.api.client import APIClient
        from mcp_server.api.free_api import FreeAPI

        async with APIClient() as client:
            free = FreeAPI(client)
            rules = await free.get_group_yara("lockbit3")

        assert isinstance(rules, list)
        # lockbit3 should have YARA rules


# ---------------------------------------------------------------------------
# PRO API tests (require API key)
# ---------------------------------------------------------------------------

class TestProAPILive:
    """Tests against the ransomware.live PRO API."""

    @needs_pro
    @pytest.mark.asyncio
    async def test_get_group_ttps(self):
        """Verify TTP fetching works with PRO key."""
        from mcp_server.api.client import APIClient
        from mcp_server.api.pro_api import ProAPI

        async with APIClient() as client:
            pro = ProAPI(client)
            ttps = await pro.get_group_ttps("lockbit3")

        assert isinstance(ttps, list)
        assert len(ttps) > 0, "lockbit3 should have known TTPs"
        assert ttps[0].technique_id, "TTP should have a technique_id"

    @needs_pro
    @pytest.mark.asyncio
    async def test_get_group_iocs(self):
        """Verify IOC fetching works with PRO key."""
        from mcp_server.api.client import APIClient
        from mcp_server.api.pro_api import ProAPI

        async with APIClient() as client:
            pro = ProAPI(client)
            iocs = await pro.get_group_iocs("lockbit3")

        assert isinstance(iocs, list)
        # Should have IOCs for lockbit3

    @needs_pro
    @pytest.mark.asyncio
    async def test_get_negotiations(self):
        """Verify negotiation transcript fetching."""
        from mcp_server.api.client import APIClient
        from mcp_server.api.pro_api import ProAPI

        async with APIClient() as client:
            pro = ProAPI(client)
            negotiations = await pro.get_negotiations("lockbit3")

        assert isinstance(negotiations, list)

    @needs_pro
    @pytest.mark.asyncio
    async def test_get_ransom_note_text(self):
        """Verify ransom note text fetching."""
        from mcp_server.api.client import APIClient
        from mcp_server.api.pro_api import ProAPI

        async with APIClient() as client:
            pro = ProAPI(client)
            note = await pro.get_ransom_note_text("lockbit3")

        assert isinstance(note, str)
        # lockbit3 should have a known ransom note

    @needs_pro
    @pytest.mark.asyncio
    async def test_get_8k_filings(self):
        """Verify SEC 8-K filing fetching."""
        from mcp_server.api.client import APIClient
        from mcp_server.api.pro_api import ProAPI

        async with APIClient() as client:
            pro = ProAPI(client)
            filings = await pro.get_8k_filings()

        assert isinstance(filings, list)


# ---------------------------------------------------------------------------
# MCP Tool integration tests (use real API)
# ---------------------------------------------------------------------------

class TestToolsLive:
    """End-to-end tests of MCP tools against the real API."""

    @pytest.mark.asyncio
    async def test_group_profile_tool(self):
        """Test the get_group_profile tool end-to-end."""
        from mcp_server.tools.group_profile import get_group_profile

        result = await get_group_profile("lockbit3")
        assert result["available"] is True
        assert result["profile"] is not None
        assert result["profile"].name

    @needs_pro
    @pytest.mark.asyncio
    async def test_ttp_correlation_tool(self):
        """Test TTP correlation with real group data."""
        from mcp_server.tools.ttp_correlation import correlate_ttps

        result = await correlate_ttps(
            observed_ttps=[
                "RDP lateral movement",
                "vssadmin shadow copy deletion",
                "schtasks persistence",
                "rclone data exfiltration",
                "powershell encoded commands",
            ],
            candidate_groups=["lockbit3", "alphv", "blackbasta"],
        )

        assert len(result["mitre_ids"]) > 0, "Should map observations to MITRE IDs"
        assert result["group_scores"], "Should have scored at least one group"

    @needs_pro
    @pytest.mark.asyncio
    async def test_negotiation_intel_tool(self):
        """Test negotiation intelligence tool."""
        from mcp_server.tools.negotiation import get_negotiation_intel

        result = await get_negotiation_intel("lockbit3")
        assert result["advisory"] is not None

    @pytest.mark.asyncio
    async def test_victim_search_tool(self):
        """Test victim search tool."""
        from mcp_server.tools.victim_search import search_victims

        result = await search_victims(keyword="bank")
        assert result["total_count"] >= 0
        assert isinstance(result["victims"], list)

    @pytest.mark.asyncio
    async def test_recent_victims_tool(self):
        """Test recent victims tool with breakdowns."""
        from mcp_server.tools.victim_search import get_recent_victims

        result = await get_recent_victims(limit=20)
        assert result["total_count"] > 0
        assert result["group_breakdown"], "Should have a group breakdown"

    @needs_pro
    @pytest.mark.asyncio
    async def test_threat_landscape_tool(self):
        """Test the threat landscape assessment."""
        from mcp_server.tools.threat_landscape import assess_threat_landscape

        report = await assess_threat_landscape(
            sector="Manufacturing",
            geography="United States",
            lookback_months=6,
            top_k=3,
        )

        assert report.sector == "Manufacturing"
        assert report.summary, "Should produce a summary"


# ---------------------------------------------------------------------------
# Full pipeline test
# ---------------------------------------------------------------------------

class TestFullPipelineLive:
    """End-to-end pipeline test using the demo scenario."""

    @needs_pro
    @pytest.mark.asyncio
    async def test_full_ir_brief_from_scenario(self):
        """Run the full IR brief pipeline on the demo scenario.

        This is the big one — exercises the entire system end-to-end.
        """
        import json
        from pathlib import Path
        from mcp_server.models import (
            HashArtifact, IOCType, IncidentArtifacts, NetworkIOC,
            RansomNoteArtifact, VictimInfo,
        )
        from mcp_server.tools.ir_brief import generate_ir_brief

        # Load the demo scenario
        scenario_path = Path(__file__).parent.parent / "demo" / "scenario.json"
        with open(scenario_path) as f:
            data = json.load(f)

        artifacts_data = data["artifacts"]

        # Build minimal artifacts for speed (skip some fields)
        artifacts = IncidentArtifacts(
            incident_id=data["incident_id"],
            victim=VictimInfo(
                company=data["victim"]["company"],
                sector=data["victim"]["sector"],
                geography=data["victim"]["geography"],
            ),
            ransom_note=RansomNoteArtifact(
                filename=artifacts_data["ransom_note"]["filename"],
                content=artifacts_data["ransom_note"]["content"],
            ),
            file_extension=artifacts_data["file_extension"],
            network_iocs=[
                NetworkIOC(ioc_type=IOCType.IP, value=ioc["value"])
                for ioc in artifacts_data["network_iocs"]
            ],
            lolbas=artifacts_data["lolbas"],
        )

        result = await generate_ir_brief(artifacts)

        # Validate the output structure
        assert result["brief"], "Should produce a non-empty brief"
        assert result["attribution"], "Should produce an attribution"
        assert result["attribution"].primary_group, "Should attribute to some group"
        assert result["attribution"].confidence.confidence_pct >= 0, "Should have a confidence score"
        assert "## Executive Summary" in result["brief"], "Brief should have executive summary"
        assert "## Attribution" in result["brief"], "Brief should have attribution section"

        # Print summary for manual review
        print(f"\n--- Pipeline Result ---")
        print(f"Attributed to: {result['attribution'].primary_group}")
        print(f"Confidence: {result['attribution'].confidence.confidence_pct}% "
              f"({result['attribution'].confidence.confidence_label})")
        print(f"Brief length: {len(result['brief'])} chars")
