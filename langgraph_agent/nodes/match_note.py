"""match_note node — matches the ransom note against known groups."""

from __future__ import annotations

import logging
from typing import Any

from langgraph_agent.state import AgentState

logger = logging.getLogger("ransomware_intel.agent.nodes.match_note")


async def match_note(state: AgentState) -> dict[str, Any]:
    """Match the ransom note against known ransomware group notes.

    Uses the same matching logic as the MCP tool — embedding similarity
    with keyword fallback.
    """
    from mcp_server.tools.ransom_note import match_ransom_note

    note_text = state.get("ransom_note_text", "")
    errors = list(state.get("errors", []))

    if not note_text:
        logger.info("No ransom note text — skipping matching")
        return {"note_matches": [], "errors": errors}

    try:
        matches = await match_ransom_note(note_text, top_k=3)
        result = [m.model_dump() for m in matches]
        logger.info("Ransom note matched %d candidates", len(result))
        return {"note_matches": result, "errors": errors}
    except Exception as exc:
        logger.error("Ransom note matching failed: %s", exc)
        errors.append(f"Ransom note matching failed: {exc}")
        return {"note_matches": [], "errors": errors}
