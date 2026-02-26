"""correlate_ttps node — maps observed TTPs against known group playbooks."""

from __future__ import annotations

import logging
from typing import Any

from langgraph_agent.state import AgentState

logger = logging.getLogger("ransomware_intel.agent.nodes.correlate_ttps")


async def correlate_ttps_node(state: AgentState) -> dict[str, Any]:
    """Correlate observed TTPs against known ransomware group TTPs.

    Maps forensic observations to MITRE ATT&CK and scores each
    candidate group by technique overlap.
    """
    from mcp_server.tools.ttp_correlation import correlate_ttps

    errors = list(state.get("errors", []))
    observed = state.get("observed_ttps", [])

    if not observed:
        logger.info("No TTPs to correlate — skipping")
        return {
            "ttp_results": {"mitre_ids": [], "group_scores": []},
            "mitre_ids": [],
            "errors": errors,
        }

    # Use candidate groups from previous nodes if available
    candidate_groups = [
        m.get("group_name", "") for m in state.get("note_matches", [])
    ]
    candidate_groups = [g for g in candidate_groups if g]

    try:
        result = await correlate_ttps(observed, candidate_groups or None)
        logger.info(
            "TTP correlation: %d MITRE IDs, %d group matches",
            len(result["mitre_ids"]),
            len(result["group_scores"]),
        )
        return {
            "ttp_results": result,
            "mitre_ids": result["mitre_ids"],
            "errors": errors,
        }
    except Exception as exc:
        logger.error("TTP correlation failed: %s", exc)
        errors.append(f"TTP correlation failed: {exc}")
        return {
            "ttp_results": {"mitre_ids": [], "group_scores": []},
            "mitre_ids": [],
            "errors": errors,
        }
