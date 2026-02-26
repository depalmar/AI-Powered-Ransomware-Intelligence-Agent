"""Agent state schema for the LangGraph ransomware intelligence agent.

The state object carries the full evidence chain through the graph so
any node can access upstream results. Uses TypedDict for LangGraph
compatibility.
"""

from __future__ import annotations

from typing import Any, TypedDict


class AgentState(TypedDict, total=False):
    """State that flows through the LangGraph agent.

    Each node reads from and writes to this state. All fields are
    optional so nodes can be called independently.
    """

    # Input artifacts
    incident_id: str
    raw_artifacts: dict[str, Any]
    ransom_note_text: str
    hashes: list[str]
    file_extension: str
    network_iocs: list[str]
    observed_ttps: list[str]
    lolbas: list[str]
    victim_company: str
    victim_sector: str
    victim_geography: str

    # Parsed artifacts (from parse_artifacts node)
    parsed_artifacts: dict[str, Any]

    # Ransom note matching results
    note_matches: list[dict[str, Any]]

    # IOC lookup results
    ioc_results: dict[str, Any]

    # TTP correlation results
    ttp_results: dict[str, Any]
    mitre_ids: list[str]

    # Attribution results
    attribution: dict[str, Any]
    primary_group: str
    confidence_score: float
    confidence_label: str

    # Enrichment data
    group_profile: dict[str, Any]
    negotiation_intel: dict[str, Any]
    yara_rules: list[dict[str, Any]]
    threat_landscape: dict[str, Any]

    # Output
    ir_brief: str
    brief_data: dict[str, Any]
    errors: list[str]

    # LLM messages (for conversational nodes)
    messages: list[Any]
