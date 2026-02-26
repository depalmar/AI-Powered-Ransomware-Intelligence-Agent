"""attribute_group node — runs confidence scoring across all candidates."""

from __future__ import annotations

import logging
from typing import Any

from langgraph_agent.state import AgentState

logger = logging.getLogger("ransomware_intel.agent.nodes.attribute")


async def attribute_group(state: AgentState) -> dict[str, Any]:
    """Score all candidate groups and determine primary attribution.

    Collects candidates from ransom note matching, IOC lookup, and
    TTP correlation. Runs the weighted confidence scoring model
    against each candidate.
    """
    from mcp_server.models import IOCRecord, RansomNoteMatch
    from mcp_server.scoring.confidence import calculate_confidence
    from mcp_server.tools.group_profile import get_group_ttps

    errors = list(state.get("errors", []))

    # Collect unique candidate groups from all signals
    candidates: dict[str, bool] = {}
    for m in state.get("note_matches", []):
        name = m.get("group_name", "")
        if name:
            candidates[name] = True

    for m in state.get("ioc_results", {}).get("matched", []):
        name = m.get("group", "")
        if name:
            candidates[name] = True

    for gs in state.get("ttp_results", {}).get("group_scores", []):
        name = gs.get("group", "")
        if name:
            candidates[name] = True

    if not candidates:
        logger.warning("No candidate groups identified")
        return {
            "attribution": {},
            "primary_group": "Unknown",
            "confidence_score": 0.0,
            "confidence_label": "Insufficient",
            "errors": errors,
        }

    # Build note matches as RansomNoteMatch objects
    note_matches = [
        RansomNoteMatch(**m) for m in state.get("note_matches", [])
    ]

    # Collect IOC values
    ioc_values = list(state.get("hashes", []))
    ioc_values.extend(state.get("network_iocs", []))

    # Score each candidate
    scored = []
    for group_name in candidates:
        # Get known IOCs for this group
        known_iocs = [
            IOCRecord(**m)
            for m in state.get("ioc_results", {}).get("matched", [])
            if m.get("group", "").lower() == group_name.lower()
        ]

        # Get known TTPs
        try:
            ttp_data = await get_group_ttps(group_name)
            known_ttps = ttp_data.get("ttps", [])
        except Exception:
            known_ttps = []

        score = calculate_confidence(
            group_name=group_name,
            note_matches=note_matches,
            submitted_iocs=ioc_values,
            known_iocs=known_iocs,
            observed_ttps=state.get("observed_ttps", []),
            known_ttps=known_ttps,
            file_extension=state.get("file_extension", ""),
        )
        scored.append(score.model_dump())

    # Sort by total score
    scored.sort(key=lambda s: s["total_score"], reverse=True)

    primary = scored[0]
    threshold = float(state.get("confidence_threshold", 0.65))

    # If below threshold, be explicit
    if primary["total_score"] < threshold:
        logger.warning(
            "Attribution confidence %.1f%% is below threshold %.1f%%",
            primary["confidence_pct"],
            threshold * 100,
        )

    return {
        "attribution": {
            "primary": primary,
            "alternatives": scored[1:3] if len(scored) > 1 else [],
            "all_candidates": scored,
        },
        "primary_group": primary["group_name"],
        "confidence_score": primary["total_score"],
        "confidence_label": primary["confidence_label"],
        "errors": errors,
    }
