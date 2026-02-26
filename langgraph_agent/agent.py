"""Main entry point for the LangGraph ransomware intelligence agent.

Can run standalone from the command line with either Ollama or Claude
as the reasoning backend.

Usage:
    python -m langgraph_agent.agent --scenario demo/scenario.json
    python -m langgraph_agent.agent --backend ollama --scenario demo/scenario.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ransomware_intel.agent")


async def run_agent(
    scenario_path: str | None = None,
    raw_artifacts: dict | None = None,
    incident_id: str = "UNKNOWN",
) -> dict:
    """Run the attribution pipeline on a set of artifacts.

    Args:
        scenario_path: Path to a scenario JSON file.
        raw_artifacts: Pre-parsed artifact dict (alternative to file).
        incident_id: Incident ID if not in the artifacts.

    Returns:
        Final agent state with the IR brief and all intermediate results.
    """
    from langgraph_agent.graph import attribution_graph

    # Load artifacts
    if scenario_path:
        with open(scenario_path) as f:
            data = json.load(f)
        incident_id = data.get("incident_id", incident_id)
        raw_artifacts = data.get("artifacts", data)
    elif raw_artifacts is None:
        raise ValueError("Provide either scenario_path or raw_artifacts")

    # Build initial state
    initial_state = {
        "incident_id": incident_id,
        "raw_artifacts": raw_artifacts,
        "errors": [],
    }

    # Check for victim info at the top level
    if scenario_path:
        with open(scenario_path) as f:
            full_data = json.load(f)
        victim = full_data.get("victim", {})
        if victim:
            initial_state["victim_company"] = victim.get("company", "")
            initial_state["victim_sector"] = victim.get("sector", "")
            initial_state["victim_geography"] = victim.get("geography", "")

    logger.info("Starting attribution pipeline for %s", incident_id)

    # Run the graph
    result = await attribution_graph.ainvoke(initial_state)

    logger.info(
        "Pipeline complete: %s attributed to %s (%.1f%%)",
        incident_id,
        result.get("primary_group", "Unknown"),
        result.get("confidence_score", 0.0) * 100,
    )

    return result


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Ransomware Intelligence Agent (LangGraph)"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="demo/scenario.json",
        help="Path to scenario JSON file",
    )
    parser.add_argument(
        "--backend",
        choices=["claude", "ollama"],
        default=None,
        help="LLM backend to use (default: from env)",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format",
    )
    args = parser.parse_args()

    if args.backend:
        import os
        os.environ["LLM_BACKEND"] = args.backend

    result = asyncio.run(run_agent(scenario_path=args.scenario))

    brief = result.get("ir_brief", "")
    if args.format == "json":
        print(json.dumps(result.get("brief_data", {}), indent=2, default=str))
    else:
        print(brief)

    # Print errors if any
    errors = result.get("errors", [])
    if errors:
        print("\n--- Processing Notes ---")
        for err in errors:
            print(f"  - {err}")


if __name__ == "__main__":
    main()
