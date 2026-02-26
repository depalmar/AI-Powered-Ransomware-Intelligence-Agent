"""Group intelligence tools — get_group_profile, get_group_ttps, get_group_yara.

Retrieves comprehensive intelligence about a ransomware group including
their profile, MITRE ATT&CK mappings, and YARA detection rules.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_server.api.client import APIClient
from mcp_server.api.free_api import FreeAPI
from mcp_server.api.pro_api import ProAPI
from mcp_server.models import GroupProfile, GroupTTP, GroupYaraRule

logger = logging.getLogger("ransomware_intel.tools.group_profile")


async def get_group_profile(group_name: str) -> dict[str, Any]:
    """Get the full profile of a ransomware group.

    Includes description, operating locations, target sectors,
    and historical victim count.

    Args:
        group_name: Ransomware group name (e.g. "lockbit3", "alphv").

    Returns:
        Dict with:
            - profile: GroupProfile object
            - victim_count: estimated victim count
            - available: whether data was found
    """
    async with APIClient() as client:
        free = FreeAPI(client)
        profile = await free.get_group(group_name)

    if not profile:
        logger.info("No profile found for group: %s", group_name)
        return {
            "profile": None,
            "victim_count": 0,
            "available": False,
        }

    # Try to get a rough victim count from the API
    victim_count = 0
    try:
        async with APIClient() as client:
            free = FreeAPI(client)
            victims = await free.search_victims(group_name)
            victim_count = len(victims)
    except Exception:
        pass

    return {
        "profile": profile,
        "victim_count": victim_count,
        "available": True,
    }


async def get_group_ttps(group_name: str) -> dict[str, Any]:
    """Get MITRE ATT&CK TTP mappings for a ransomware group.

    Args:
        group_name: Ransomware group name.

    Returns:
        Dict with:
            - ttps: list of GroupTTP objects
            - tactic_summary: dict mapping tactic → list of techniques
            - available: whether data was found
    """
    async with APIClient() as client:
        pro = ProAPI(client)
        ttps = await pro.get_group_ttps(group_name)

    if not ttps:
        logger.info("No TTPs found for group: %s", group_name)
        return {
            "ttps": [],
            "tactic_summary": {},
            "available": False,
        }

    # Build a tactic → techniques summary
    tactic_summary: dict[str, list[str]] = {}
    for ttp in ttps:
        tactic = ttp.tactic or "Unknown"
        entry = f"{ttp.technique_id}: {ttp.technique_name}"
        tactic_summary.setdefault(tactic, []).append(entry)

    return {
        "ttps": ttps,
        "tactic_summary": tactic_summary,
        "available": True,
    }


async def get_group_yara(group_name: str) -> dict[str, Any]:
    """Get YARA detection rules for a ransomware group.

    Args:
        group_name: Ransomware group name.

    Returns:
        Dict with:
            - rules: list of GroupYaraRule objects
            - combined_rules: all rules concatenated as a single string
            - available: whether data was found
    """
    async with APIClient() as client:
        free = FreeAPI(client)
        rules = await free.get_group_yara(group_name)

    if not rules:
        logger.info("No YARA rules found for group: %s", group_name)
        return {
            "rules": [],
            "combined_rules": "",
            "available": False,
        }

    combined = "\n\n".join(r.rule_content for r in rules if r.rule_content)

    return {
        "rules": rules,
        "combined_rules": combined,
        "available": True,
    }
