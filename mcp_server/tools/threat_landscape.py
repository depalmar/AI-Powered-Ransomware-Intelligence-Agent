"""assess_threat_landscape tool — proactive hunting capability.

Accepts an industry sector + geography, analyzes recent attack patterns,
and returns a prioritized threat actor watchlist with pre-deployable IOCs.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from mcp_server.api.client import APIClient
from mcp_server.api.free_api import FreeAPI
from mcp_server.api.pro_api import ProAPI
from mcp_server.models import ThreatLandscapeEntry, ThreatLandscapeReport

logger = logging.getLogger("ransomware_intel.tools.threat_landscape")


async def assess_threat_landscape(
    sector: str,
    geography: str = "",
    lookback_months: int = 3,
    top_k: int = 5,
) -> ThreatLandscapeReport:
    """Assess the current ransomware threat landscape for a sector/geography.

    Analyzes recent victim data to identify which groups are most actively
    targeting the specified sector and region. Enriches each group with
    IOCs for proactive blocking.

    Args:
        sector: Industry sector (e.g. "Manufacturing", "Healthcare").
        geography: Geographic region (e.g. "United States", "Europe").
        lookback_months: How many months of data to analyze.
        top_k: Number of top threat actors to return.

    Returns:
        ThreatLandscapeReport with prioritized threat actors.
    """
    async with APIClient() as client:
        free = FreeAPI(client)
        pro = ProAPI(client)

        # Fetch sector-specific victims
        sector_victims = await free.get_sector_victims(sector)

        # Also get recent victims for cross-referencing
        recent_victims = await free.get_recent_victims()

    # Filter by lookback window
    cutoff = _months_ago(lookback_months)
    recent_sector = [
        v for v in sector_victims
        if _is_after(v.published, cutoff)
    ]

    # Filter by geography if specified
    if geography:
        geo_lower = geography.lower()
        recent_sector = [
            v for v in recent_sector
            if geo_lower in (v.country or "").lower()
        ]

    # Count attacks per group
    group_counts: dict[str, int] = {}
    for v in recent_sector:
        if v.group:
            group_counts[v.group] = group_counts.get(v.group, 0) + 1

    # Also check recent victims for sector targeting patterns
    for v in recent_victims:
        if sector.lower() in (v.sector or "").lower():
            if v.group:
                group_counts[v.group] = group_counts.get(v.group, 0) + 1

    # Rank groups by activity
    ranked = sorted(group_counts.items(), key=lambda x: x[1], reverse=True)
    top_groups = ranked[:top_k]

    # Enrich each top group
    entries: list[ThreatLandscapeEntry] = []
    for group_name, count in top_groups:
        entry = await _enrich_group_entry(group_name, count, sector, pro, free)
        entries.append(entry)

    # Build summary
    if entries:
        top_names = ", ".join(e.group_name for e in entries[:3])
        summary = (
            f"Top {len(entries)} threat actors targeting {sector}"
            + (f" in {geography}" if geography else "")
            + f" over the past {lookback_months} months: {top_names}. "
            f"Total {sum(group_counts.values())} attacks observed in this sector."
        )
    else:
        summary = (
            f"No significant ransomware activity targeting {sector}"
            + (f" in {geography}" if geography else "")
            + f" over the past {lookback_months} months."
        )

    return ThreatLandscapeReport(
        sector=sector,
        geography=geography,
        threat_actors=entries,
        summary=summary,
    )


async def _enrich_group_entry(
    group_name: str,
    victim_count: int,
    sector: str,
    pro: ProAPI,
    free: FreeAPI,
) -> ThreatLandscapeEntry:
    """Build a ThreatLandscapeEntry with enriched data for a group."""
    # Get group profile for context
    profile = await free.get_group(group_name)

    # Get IOCs for proactive blocking
    iocs = await pro.get_group_iocs(group_name)
    recent_ioc_values = [r.value for r in iocs[:10]] if iocs else []

    # Determine risk level based on activity
    if victim_count >= 10:
        risk_level = "Critical"
    elif victim_count >= 5:
        risk_level = "High"
    elif victim_count >= 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    description = ""
    if profile:
        description = profile.description

    return ThreatLandscapeEntry(
        group_name=group_name,
        risk_level=risk_level,
        recent_victim_count=victim_count,
        primary_sectors=[sector],
        recent_iocs=recent_ioc_values,
        summary=(
            f"{group_name}: {victim_count} attacks on {sector} sector. "
            f"Risk: {risk_level}. "
            + (description[:150] if description else "No group description available.")
        ),
    )


def _months_ago(months: int) -> str:
    """Get an ISO date string for N months ago."""
    now = datetime.utcnow()
    year = now.year
    month = now.month - months
    while month <= 0:
        month += 12
        year -= 1
    return f"{year}-{month:02d}-01"


def _is_after(date_str: str, cutoff: str) -> bool:
    """Check if a date string is after the cutoff."""
    if not date_str:
        return False
    try:
        return date_str >= cutoff
    except (TypeError, ValueError):
        return False
