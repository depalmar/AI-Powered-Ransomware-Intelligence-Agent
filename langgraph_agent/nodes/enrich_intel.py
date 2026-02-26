"""enrich_intel node — enriches attribution with profile, negotiations, YARA."""

from __future__ import annotations

import logging
from typing import Any

from langgraph_agent.state import AgentState

logger = logging.getLogger("ransomware_intel.agent.nodes.enrich")


async def enrich_intel(state: AgentState) -> dict[str, Any]:
    """Enrich the attributed group with additional intelligence.

    Fetches group profile, negotiation transcripts, and YARA rules
    for the primary attributed group.
    """
    from mcp_server.tools.group_profile import (
        get_group_profile,
        get_group_yara,
    )
    from mcp_server.tools.negotiation import get_negotiation_intel

    errors = list(state.get("errors", []))
    primary_group = state.get("primary_group", "")

    if not primary_group or primary_group == "Unknown":
        logger.info("No attributed group to enrich")
        return {
            "group_profile": {},
            "negotiation_intel": {},
            "yara_rules": [],
            "errors": errors,
        }

    logger.info("Enriching intelligence for %s...", primary_group)

    # Fetch enrichment data
    group_profile = {}
    try:
        profile_result = await get_group_profile(primary_group)
        if profile_result.get("profile"):
            group_profile = profile_result["profile"].model_dump()
    except Exception as exc:
        logger.warning("Failed to get group profile: %s", exc)
        errors.append(f"Group profile fetch failed: {exc}")

    negotiation_intel = {}
    try:
        neg_result = await get_negotiation_intel(primary_group)
        negotiation_intel = {
            "advisory": neg_result["advisory"].model_dump(),
            "transcript_count": neg_result["transcript_count"],
            "available": neg_result["available"],
        }
    except Exception as exc:
        logger.warning("Failed to get negotiation intel: %s", exc)
        errors.append(f"Negotiation intel fetch failed: {exc}")

    yara_rules = []
    try:
        yara_result = await get_group_yara(primary_group)
        yara_rules = [r.model_dump() for r in yara_result.get("rules", [])]
    except Exception as exc:
        logger.warning("Failed to get YARA rules: %s", exc)
        errors.append(f"YARA rules fetch failed: {exc}")

    return {
        "group_profile": group_profile,
        "negotiation_intel": negotiation_intel,
        "yara_rules": yara_rules,
        "errors": errors,
    }
