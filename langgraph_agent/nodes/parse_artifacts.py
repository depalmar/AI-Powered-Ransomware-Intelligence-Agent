"""parse_artifacts node — parses and normalizes raw forensic artifacts.

First node in the graph. Takes raw input (JSON or dict) and normalizes
it into structured fields that downstream nodes can consume.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from langgraph_agent.state import AgentState

logger = logging.getLogger("ransomware_intel.agent.nodes.parse")


async def parse_artifacts(state: AgentState) -> dict[str, Any]:
    """Parse raw artifacts into normalized state fields.

    Handles both structured dict input and raw JSON string input.
    Extracts all artifact types into their respective state fields.
    """
    logger.info("Parsing forensic artifacts...")
    errors: list[str] = list(state.get("errors", []))

    raw = state.get("raw_artifacts", {})
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"Failed to parse artifacts JSON: {exc}")
            return {"errors": errors, "parsed_artifacts": {}}

    # Extract fields, preserving any that were set directly on state
    result: dict[str, Any] = {
        "parsed_artifacts": raw,
        "errors": errors,
    }

    # Ransom note
    if not state.get("ransom_note_text"):
        note_data = raw.get("ransom_note", {})
        if isinstance(note_data, dict):
            result["ransom_note_text"] = note_data.get("content", "")
        elif isinstance(note_data, str):
            result["ransom_note_text"] = note_data

    # Hashes
    if not state.get("hashes"):
        hash_data = raw.get("hashes", {})
        if isinstance(hash_data, dict):
            result["hashes"] = list(hash_data.values())
        elif isinstance(hash_data, list):
            result["hashes"] = hash_data

    # File extension
    if not state.get("file_extension"):
        result["file_extension"] = raw.get("file_extension", "")

    # Network IOCs
    if not state.get("network_iocs"):
        net_data = raw.get("network_iocs", [])
        result["network_iocs"] = [
            n.get("value", n) if isinstance(n, dict) else n
            for n in net_data
        ]

    # LOLBAS / TTPs
    if not state.get("observed_ttps") and not state.get("lolbas"):
        lolbas = raw.get("lolbas", [])
        persistence = raw.get("persistence", [])
        lateral = raw.get("lateral_movement", [])

        ttps = list(lolbas)
        for p in persistence:
            if isinstance(p, dict):
                ttps.append(f"{p.get('type', 'persistence')}: {p.get('name', p.get('command', ''))}")
        for lm in lateral:
            if isinstance(lm, dict):
                ttps.append(f"{lm.get('method', 'lateral_movement')} lateral movement")

        result["observed_ttps"] = ttps
        result["lolbas"] = lolbas

    # Victim info
    victim = raw.get("victim", state.get("raw_artifacts", {}).get("victim", {}))
    if isinstance(victim, dict):
        if not state.get("victim_company"):
            result["victim_company"] = victim.get("company", "")
        if not state.get("victim_sector"):
            result["victim_sector"] = victim.get("sector", "")
        if not state.get("victim_geography"):
            result["victim_geography"] = victim.get("geography", "")

    logger.info("Parsed artifacts: %d TTPs, %d IOCs, %d hashes",
                len(result.get("observed_ttps", [])),
                len(result.get("network_iocs", [])),
                len(result.get("hashes", [])))

    return result
