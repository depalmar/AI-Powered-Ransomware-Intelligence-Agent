"""FastMCP server entry point for the Ransomware Intelligence Agent.

Exposes all ransomware intelligence tools as MCP tools that can be
called from Claude Desktop, Claude Code, or any MCP-compatible client.

Run with:
    python -m mcp_server.server
    # or via the registered script:
    ransomware-mcp
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

from fastmcp import FastMCP

from mcp_server.models import IncidentArtifacts, VictimInfo, RansomNoteArtifact
from mcp_server.tools.group_profile import (
    get_group_profile as _get_group_profile,
    get_group_ttps as _get_group_ttps,
    get_group_yara as _get_group_yara,
)
from mcp_server.tools.ioc_lookup import lookup_iocs as _lookup_iocs
from mcp_server.tools.ir_brief import generate_ir_brief as _generate_ir_brief
from mcp_server.tools.negotiation import get_negotiation_intel as _get_negotiation_intel
from mcp_server.tools.ransom_note import match_ransom_note as _match_ransom_note
from mcp_server.tools.sec_filings import get_8k_filings as _get_8k_filings
from mcp_server.tools.threat_landscape import assess_threat_landscape as _assess_threat_landscape
from mcp_server.tools.ttp_correlation import correlate_ttps as _correlate_ttps
from mcp_server.tools.victim_search import (
    get_recent_victims as _get_recent_victims,
    search_victims as _search_victims,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)

# Create the MCP server
mcp = FastMCP(
    "Ransomware Intelligence Agent",
    description=(
        "AI-powered ransomware intelligence tools that cross-reference "
        "forensic artifacts against ransomware.live's real-time database "
        "to attribute threat actors, surface IOCs, and generate IR briefs."
    ),
)


# ---------------------------------------------------------------------------
# MCP Tool Definitions
# ---------------------------------------------------------------------------


@mcp.tool()
async def match_ransom_note(note_text: str, top_k: int = 3) -> str:
    """Match a ransom note against known ransomware group notes.

    Compares the submitted ransom note text against known notes using
    embedding similarity (via Ollama + ChromaDB). Falls back to keyword
    matching if embeddings are unavailable.

    Args:
        note_text: Full text content of the ransom note found on the system.
        top_k: Number of top candidate matches to return (default 3).

    Returns:
        JSON string with top candidate groups and confidence scores.
    """
    matches = await _match_ransom_note(note_text, top_k=top_k)
    return json.dumps(
        [m.model_dump() for m in matches],
        indent=2,
    )


@mcp.tool()
async def lookup_iocs(
    ioc_values: list[str],
    candidate_groups: list[str] | None = None,
) -> str:
    """Look up IOCs (hashes, IPs, domains) against the ransomware.live database.

    Accepts hashes (MD5/SHA1/SHA256), IP addresses, and domains. Queries
    the ransomware.live IOC database and returns matches. Also flags
    IOCs that don't match any known group.

    Args:
        ioc_values: List of IOC strings. Hashes can include type prefix
            (e.g. "sha256:abc123..."). IPs and domains detected automatically.
        candidate_groups: Optional list of specific groups to check against.

    Returns:
        JSON string with matched IOCs, unmatched IOCs, and classifications.
    """
    result = await _lookup_iocs(ioc_values, candidate_groups)
    return json.dumps(
        {
            "matched": [m.model_dump() for m in result["matched"]],
            "unmatched": result["unmatched"],
            "classified": result["classified"],
            "groups_checked": result["groups_checked"],
        },
        indent=2,
    )


@mcp.tool()
async def get_negotiation_intel(group_name: str) -> str:
    """Get negotiation intelligence for a ransomware group.

    Pulls negotiation transcripts and analyzes them for: typical demands,
    discount curves, response windows, and decryptor reliability.

    Args:
        group_name: Ransomware group name (e.g. "lockbit3", "alphv").

    Returns:
        JSON string with negotiation advisory and transcript analysis.
    """
    result = await _get_negotiation_intel(group_name)
    return json.dumps(
        {
            "advisory": result["advisory"].model_dump(),
            "transcript_count": result["transcript_count"],
            "available": result["available"],
        },
        indent=2,
    )


@mcp.tool()
async def get_group_profile(group_name: str) -> str:
    """Get the profile of a ransomware group.

    Returns group description, operating locations, target sectors,
    and historical victim count.

    Args:
        group_name: Ransomware group name (e.g. "lockbit3", "alphv").

    Returns:
        JSON string with group profile data.
    """
    result = await _get_group_profile(group_name)
    return json.dumps(
        {
            "profile": result["profile"].model_dump() if result["profile"] else None,
            "victim_count": result["victim_count"],
            "available": result["available"],
        },
        indent=2,
    )


@mcp.tool()
async def get_group_ttps(group_name: str) -> str:
    """Get MITRE ATT&CK TTP mappings for a ransomware group.

    Returns the group's known tactics, techniques, and procedures mapped
    to the MITRE ATT&CK framework.

    Args:
        group_name: Ransomware group name.

    Returns:
        JSON string with TTPs and tactic summary.
    """
    result = await _get_group_ttps(group_name)
    return json.dumps(
        {
            "ttps": [t.model_dump() for t in result["ttps"]],
            "tactic_summary": result["tactic_summary"],
            "available": result["available"],
        },
        indent=2,
    )


@mcp.tool()
async def get_group_yara(group_name: str) -> str:
    """Get YARA detection rules for a ransomware group.

    Returns YARA rules that can be deployed for network sweeps and
    endpoint detection.

    Args:
        group_name: Ransomware group name.

    Returns:
        JSON string with YARA rules.
    """
    result = await _get_group_yara(group_name)
    return json.dumps(
        {
            "rules": [r.model_dump() for r in result["rules"]],
            "combined_rules": result["combined_rules"],
            "available": result["available"],
        },
        indent=2,
    )


@mcp.tool()
async def search_victims(
    keyword: str | None = None,
    sector: str | None = None,
    year: int | None = None,
    month: int | None = None,
) -> str:
    """Search for ransomware victims with filtering.

    Supports keyword search, sector filtering, and temporal filtering.
    Without any filter, returns recent victims.

    Args:
        keyword: Search term (company name, keyword, etc.).
        sector: Industry sector filter (e.g. "Manufacturing", "Healthcare").
        year: Filter by year (e.g. 2024).
        month: Filter by month (1-12, requires year).

    Returns:
        JSON string with victim records and counts.
    """
    result = await _search_victims(keyword, sector, year, month)
    return json.dumps(
        {
            "victims": [v.model_dump() for v in result["victims"][:50]],
            "total_count": result["total_count"],
            "filters_applied": result["filters_applied"],
        },
        indent=2,
    )


@mcp.tool()
async def get_recent_victims(limit: int = 50) -> str:
    """Get the most recent ransomware victims for trend analysis.

    Returns recent victim data with breakdowns by group and sector.

    Args:
        limit: Maximum number of results (default 50).

    Returns:
        JSON string with victims, group breakdown, and sector breakdown.
    """
    result = await _get_recent_victims(limit)
    return json.dumps(
        {
            "victims": [v.model_dump() for v in result["victims"]],
            "total_count": result["total_count"],
            "group_breakdown": result["group_breakdown"],
            "sector_breakdown": result["sector_breakdown"],
        },
        indent=2,
    )


@mcp.tool()
async def correlate_ttps(
    observed_ttps: list[str],
    candidate_groups: list[str] | None = None,
    top_k: int = 5,
) -> str:
    """Correlate observed TTPs against known ransomware group playbooks.

    Accepts observed TTPs (RDP lateral movement, schtasks persistence,
    LOLBAS usage, etc.) and maps them against known group TTPs. Returns
    ranked group matches with MITRE ATT&CK overlay.

    Args:
        observed_ttps: List of TTP descriptions, MITRE technique IDs,
            or LOLBAS observations (e.g. "RDP lateral movement",
            "schtasks persistence", "vssadmin shadow copy deletion").
        candidate_groups: Optional list of specific groups to check.
        top_k: Number of top-matching groups to return (default 5).

    Returns:
        JSON string with MITRE mappings and ranked group scores.
    """
    result = await _correlate_ttps(observed_ttps, candidate_groups, top_k)
    return json.dumps(result, indent=2)


@mcp.tool()
async def generate_ir_brief(
    incident_id: str,
    ransom_note_text: str = "",
    ransom_note_filename: str = "",
    hashes: list[str] | None = None,
    file_extension: str = "",
    network_iocs: list[str] | None = None,
    observed_ttps: list[str] | None = None,
    victim_company: str = "",
    victim_sector: str = "",
    victim_geography: str = "",
    output_format: str = "markdown",
) -> str:
    """Generate a full ransomware incident intelligence brief.

    This is the main orchestrator tool. Provide all available forensic
    artifacts and it will run the complete attribution pipeline:
    ransom note matching, IOC lookup, TTP correlation, confidence scoring,
    group profiling, and report generation.

    Args:
        incident_id: Unique incident identifier (e.g. "IR-2024-0101").
        ransom_note_text: Full text of the ransom note (if found).
        ransom_note_filename: Filename of the ransom note.
        hashes: File hashes found (SHA256, MD5, etc.). Use "sha256:abc..."
            format or raw hash values.
        file_extension: Encrypted file extension (e.g. ".lockbit", ".encrypted").
        network_iocs: Network indicators — IPs, domains.
        observed_ttps: Observed TTPs and LOLBAS usage descriptions.
        victim_company: Victim organization name.
        victim_sector: Victim industry sector.
        victim_geography: Victim geographic location.
        output_format: "markdown" or "json" (default "markdown").

    Returns:
        Full intelligence brief as markdown (or JSON).
    """
    # Build the IncidentArtifacts model
    from mcp_server.models import HashArtifact, NetworkIOC, IOCType
    from mcp_server.tools.ioc_lookup import classify_ioc, extract_ioc_value

    hash_artifacts = []
    for h in (hashes or []):
        clean = extract_ioc_value(h)
        hash_type = classify_ioc(clean)
        hash_artifacts.append(HashArtifact(
            hash_type=hash_type or IOCType.SHA256,
            value=clean,
        ))

    network_artifacts = []
    for n in (network_iocs or []):
        ioc_type = classify_ioc(n)
        network_artifacts.append(NetworkIOC(
            ioc_type=ioc_type or IOCType.IP,
            value=n,
        ))

    note = None
    if ransom_note_text:
        note = RansomNoteArtifact(
            filename=ransom_note_filename or "ransom_note.txt",
            content=ransom_note_text,
        )

    artifacts = IncidentArtifacts(
        incident_id=incident_id,
        victim=VictimInfo(
            company=victim_company,
            sector=victim_sector,
            geography=victim_geography,
        ),
        ransom_note=note,
        hashes=hash_artifacts,
        file_extension=file_extension,
        network_iocs=network_artifacts,
        lolbas=observed_ttps or [],
    )

    result = await _generate_ir_brief(artifacts, output_format)

    if output_format == "json":
        return json.dumps(result["brief"], indent=2, default=str)
    return result["brief"]


@mcp.tool()
async def assess_threat_landscape(
    sector: str,
    geography: str = "",
    lookback_months: int = 3,
    top_k: int = 5,
) -> str:
    """Assess the current ransomware threat landscape for a sector/geography.

    Proactive hunting tool: analyzes recent attack patterns to identify
    which groups are most actively targeting your sector and region.
    Returns a prioritized threat actor watchlist with pre-deployable IOCs.

    Args:
        sector: Industry sector (e.g. "Manufacturing", "Healthcare",
            "Financial Services", "Education").
        geography: Geographic region (e.g. "United States", "Europe").
        lookback_months: Months of historical data to analyze (default 3).
        top_k: Number of top threat actors to return (default 5).

    Returns:
        JSON string with threat landscape assessment.
    """
    report = await _assess_threat_landscape(sector, geography, lookback_months, top_k)
    return json.dumps(report.model_dump(mode="json"), indent=2, default=str)


@mcp.tool()
async def get_8k_filings(
    ticker: str | None = None,
    cik: str | None = None,
) -> str:
    """Get SEC cybersecurity 8-K incident disclosures.

    Pulls SEC filings related to cybersecurity incidents. Supports
    filtering by stock ticker or CIK number.

    Args:
        ticker: Stock ticker symbol (e.g. "MSFT", "UNH").
        cik: SEC Central Index Key number.

    Returns:
        JSON string with SEC filing records.
    """
    result = await _get_8k_filings(ticker, cik)
    return json.dumps(
        {
            "filings": [f.model_dump() for f in result["filings"]],
            "total_count": result["total_count"],
            "available": result["available"],
        },
        indent=2,
    )


def main() -> None:
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
