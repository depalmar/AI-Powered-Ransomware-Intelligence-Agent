"""Victim search tools — search_victims and get_recent_victims.

Provides keyword search across all victims with sector and temporal
filtering, plus recent victim data for trend analysis.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from mcp_server.api.client import APIClient
from mcp_server.api.free_api import FreeAPI
from mcp_server.models import VictimRecord

logger = logging.getLogger("ransomware_intel.tools.victim_search")


async def search_victims(
    keyword: str | None = None,
    sector: str | None = None,
    year: int | None = None,
    month: int | None = None,
) -> dict[str, Any]:
    """Search for ransomware victims with filtering.

    Supports keyword search, sector filtering, and temporal filtering.
    Multiple filters can be combined — results are intersected.

    Args:
        keyword: Search term (company name, keyword, etc.).
        sector: Industry sector filter.
        year: Filter by year.
        month: Filter by month (requires year).

    Returns:
        Dict with:
            - victims: list of VictimRecord objects
            - total_count: number of results
            - filters_applied: dict of applied filters
    """
    filters_applied: dict[str, str] = {}
    victims: list[VictimRecord] = []

    async with APIClient() as client:
        free = FreeAPI(client)

        if keyword:
            filters_applied["keyword"] = keyword
            victims = await free.search_victims(keyword)
        elif sector:
            filters_applied["sector"] = sector
            victims = await free.get_sector_victims(sector)
        elif year:
            filters_applied["year"] = str(year)
            m = month or datetime.now().month
            filters_applied["month"] = str(m)
            victims = await free.get_victims_by_month(year, m)
        else:
            victims = await free.get_recent_victims()
            filters_applied["type"] = "recent"

    # Apply additional filters on already-fetched results
    if keyword and sector:
        filters_applied["sector"] = sector
        victims = [
            v for v in victims
            if sector.lower() in (v.sector or "").lower()
        ]

    if keyword and year:
        filters_applied["year"] = str(year)
        victims = [
            v for v in victims
            if str(year) in (v.published or "")
        ]

    return {
        "victims": victims,
        "total_count": len(victims),
        "filters_applied": filters_applied,
    }


async def get_recent_victims(limit: int = 50) -> dict[str, Any]:
    """Get the most recent ransomware victims for trend analysis.

    Args:
        limit: Maximum number of results to return.

    Returns:
        Dict with:
            - victims: list of VictimRecord objects
            - total_count: number of results
            - group_breakdown: dict mapping group → count
            - sector_breakdown: dict mapping sector → count
    """
    async with APIClient() as client:
        free = FreeAPI(client)
        victims = await free.get_recent_victims()

    # Trim to limit
    victims = victims[:limit]

    # Build breakdowns
    group_breakdown: dict[str, int] = {}
    sector_breakdown: dict[str, int] = {}

    for v in victims:
        if v.group:
            group_breakdown[v.group] = group_breakdown.get(v.group, 0) + 1
        if v.sector:
            sector_breakdown[v.sector] = sector_breakdown.get(v.sector, 0) + 1

    # Sort breakdowns by count
    group_breakdown = dict(
        sorted(group_breakdown.items(), key=lambda x: x[1], reverse=True)
    )
    sector_breakdown = dict(
        sorted(sector_breakdown.items(), key=lambda x: x[1], reverse=True)
    )

    return {
        "victims": victims,
        "total_count": len(victims),
        "group_breakdown": group_breakdown,
        "sector_breakdown": sector_breakdown,
    }
