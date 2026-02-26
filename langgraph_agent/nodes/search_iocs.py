"""search_iocs node — looks up IOCs against ransomware.live."""

from __future__ import annotations

import logging
from typing import Any

from langgraph_agent.state import AgentState

logger = logging.getLogger("ransomware_intel.agent.nodes.search_iocs")


async def search_iocs(state: AgentState) -> dict[str, Any]:
    """Look up all IOCs from the incident against known databases.

    Combines hashes and network IOCs, queries the ransomware.live
    database, and returns matches.
    """
    from mcp_server.tools.ioc_lookup import lookup_iocs

    errors = list(state.get("errors", []))

    # Collect all IOC values
    ioc_values = list(state.get("hashes", []))
    ioc_values.extend(state.get("network_iocs", []))

    if not ioc_values:
        logger.info("No IOCs to look up — skipping")
        return {"ioc_results": {"matched": [], "unmatched": []}, "errors": errors}

    # Use ransom note matches as candidate groups if available
    candidate_groups = [
        m.get("group_name", "") for m in state.get("note_matches", [])
    ]
    candidate_groups = [g for g in candidate_groups if g]

    try:
        result = await lookup_iocs(ioc_values, candidate_groups or None)
        # Serialize IOCRecord objects
        serialized = {
            "matched": [m.model_dump() for m in result["matched"]],
            "unmatched": result["unmatched"],
            "classified": result["classified"],
            "groups_checked": result["groups_checked"],
        }
        logger.info(
            "IOC lookup: %d matched, %d unmatched",
            len(serialized["matched"]),
            len(serialized["unmatched"]),
        )
        return {"ioc_results": serialized, "errors": errors}
    except Exception as exc:
        logger.error("IOC lookup failed: %s", exc)
        errors.append(f"IOC lookup failed: {exc}")
        return {"ioc_results": {"matched": [], "unmatched": ioc_values}, "errors": errors}
