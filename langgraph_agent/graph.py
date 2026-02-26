"""State graph definition for the LangGraph ransomware intelligence agent.

Defines the node sequence:
  parse_artifacts → match_note → search_iocs → correlate_ttps →
  attribute_group → enrich_intel → generate_brief

Each node is a well-defined async function that can also be called
independently.
"""

from __future__ import annotations

import logging

from langgraph.graph import END, StateGraph

from langgraph_agent.nodes.attribute_group import attribute_group
from langgraph_agent.nodes.correlate_ttps import correlate_ttps_node
from langgraph_agent.nodes.enrich_intel import enrich_intel
from langgraph_agent.nodes.generate_brief import generate_brief
from langgraph_agent.nodes.match_note import match_note
from langgraph_agent.nodes.parse_artifacts import parse_artifacts
from langgraph_agent.nodes.search_iocs import search_iocs
from langgraph_agent.state import AgentState

logger = logging.getLogger("ransomware_intel.agent.graph")


def build_graph() -> StateGraph:
    """Build the LangGraph state graph for the attribution pipeline.

    Returns:
        Compiled StateGraph ready for invocation.
    """
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("parse_artifacts", parse_artifacts)
    graph.add_node("match_note", match_note)
    graph.add_node("search_iocs", search_iocs)
    graph.add_node("correlate_ttps", correlate_ttps_node)
    graph.add_node("attribute_group", attribute_group)
    graph.add_node("enrich_intel", enrich_intel)
    graph.add_node("generate_brief", generate_brief)

    # Define edges (linear pipeline)
    graph.set_entry_point("parse_artifacts")
    graph.add_edge("parse_artifacts", "match_note")
    graph.add_edge("match_note", "search_iocs")
    graph.add_edge("search_iocs", "correlate_ttps")
    graph.add_edge("correlate_ttps", "attribute_group")
    graph.add_edge("attribute_group", "enrich_intel")
    graph.add_edge("enrich_intel", "generate_brief")
    graph.add_edge("generate_brief", END)

    return graph.compile()


# Pre-built graph instance for convenience
attribution_graph = build_graph()
