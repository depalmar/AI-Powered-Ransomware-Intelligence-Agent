"""generate_brief node — assembles all data into a final IR brief."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from langgraph_agent.state import AgentState

logger = logging.getLogger("ransomware_intel.agent.nodes.brief")

TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"


async def generate_brief(state: AgentState) -> dict[str, Any]:
    """Generate the final IR brief from all collected intelligence.

    Assembles attribution, enrichment, and artifact data into a
    structured report rendered via Jinja2.
    """
    errors = list(state.get("errors", []))
    incident_id = state.get("incident_id", "UNKNOWN")

    # Build the template data
    brief_data = {
        "incident_id": incident_id,
        "generated_at": datetime.utcnow().isoformat(),
        "victim": {
            "company": state.get("victim_company", ""),
            "sector": state.get("victim_sector", ""),
            "geography": state.get("victim_geography", ""),
        },
        "attribution": {
            "primary_group": state.get("primary_group", "Unknown"),
            "confidence_score": state.get("confidence_score", 0.0),
            "confidence_label": state.get("confidence_label", "Insufficient"),
            "confidence_pct": round(state.get("confidence_score", 0.0) * 100, 1),
            "details": state.get("attribution", {}),
        },
        "note_matches": state.get("note_matches", []),
        "ioc_results": state.get("ioc_results", {}),
        "ttp_results": state.get("ttp_results", {}),
        "mitre_ids": state.get("mitre_ids", []),
        "group_profile": state.get("group_profile", {}),
        "negotiation_intel": state.get("negotiation_intel", {}),
        "yara_rules": state.get("yara_rules", []),
        "errors": errors,
    }

    # Generate executive summary
    summary = _build_summary(state)

    # Render the brief
    try:
        brief = _render_brief(brief_data, summary)
    except Exception as exc:
        logger.error("Brief rendering failed: %s", exc)
        errors.append(f"Brief rendering failed: {exc}")
        brief = _render_fallback(brief_data, summary)

    return {
        "ir_brief": brief,
        "brief_data": brief_data,
        "errors": errors,
    }


def _build_summary(state: AgentState) -> str:
    """Build executive summary from state."""
    company = state.get("victim_company", "The victim organization")
    sector = state.get("victim_sector", "")
    group = state.get("primary_group", "Unknown")
    confidence = state.get("confidence_score", 0.0) * 100

    parts = [
        f"{company}"
        + (f" ({sector})" if sector else "")
        + f" was targeted in a ransomware attack attributed to {group} "
        + f"with {confidence:.0f}% confidence."
    ]

    observed_ttps = state.get("observed_ttps", [])
    if observed_ttps:
        parts.append(
            f"Analysis identified {len(observed_ttps)} tactical indicators "
            f"including LOLBAS usage and lateral movement."
        )

    threshold = 0.65
    if state.get("confidence_score", 0.0) < threshold:
        parts.append(
            "NOTE: Attribution confidence is below the recommended threshold. "
            "Additional evidence is recommended before acting on this attribution."
        )

    return " ".join(parts)


def _render_brief(data: dict[str, Any], summary: str) -> str:
    """Render using the IR brief markdown format."""
    lines = [
        "# Ransomware Incident Intelligence Brief",
        "",
        f"**Incident ID:** {data['incident_id']}",
        f"**Generated:** {data['generated_at']}",
        f"**Confidence Level:** {data['attribution']['confidence_pct']}% "
        f"({data['attribution']['confidence_label']})",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        summary,
        "",
        "---",
        "",
        "## Attribution",
        "",
        f"**Primary Attribution:** {data['attribution']['primary_group']} "
        f"({data['attribution']['confidence_pct']}%)",
        "",
    ]

    # Signal breakdown
    details = data["attribution"].get("details", {})
    primary = details.get("primary", {})
    signals = primary.get("signals", [])
    if signals:
        lines.append("**Supporting Evidence:**")
        for signal in signals:
            lines.append(f"- **{signal['signal_name']}:** {signal['detail']}")
        lines.append("")

    # Group profile
    profile = data.get("group_profile", {})
    if profile:
        lines.extend([
            "---",
            "",
            "## Threat Actor Profile",
            "",
            f"**Group:** {profile.get('name', data['attribution']['primary_group'])}",
        ])
        if profile.get("first_seen"):
            lines.append(f"**Active Since:** {profile['first_seen']}")
        if profile.get("description"):
            lines.append(f"**Operational Style:** {profile['description']}")
        lines.append("")

    # Negotiation advisory
    neg = data.get("negotiation_intel", {})
    advisory = neg.get("advisory", {})
    if advisory:
        lines.extend([
            "---",
            "",
            "## Negotiation Advisory",
            "",
            f"- **Typical Demand:** {advisory.get('typical_demand_range', 'N/A')}",
            f"- **Historical Discount:** {advisory.get('avg_discount_pct', 0)}%",
            f"- **Response Window:** {advisory.get('response_window', 'N/A')}",
            f"- **Decryptor Reliability:** {advisory.get('decryptor_reliability', 'Unknown')}",
            f"- **Recommendation:** {advisory.get('recommendation', 'Consult legal counsel')}",
            "",
        ])

    # MITRE ATT&CK
    mitre_ids = data.get("mitre_ids", [])
    if mitre_ids:
        lines.extend([
            "---",
            "",
            "## MITRE ATT&CK Coverage",
            "",
            "| Technique ID |",
            "|---|",
        ])
        for tid in mitre_ids:
            lines.append(f"| {tid} |")
        lines.append("")

    # YARA rules
    yara_rules = data.get("yara_rules", [])
    if yara_rules:
        lines.extend(["---", "", "## YARA Rules", ""])
        for rule in yara_rules:
            content = rule.get("rule_content", "")
            if content:
                lines.append(f"```yara\n{content}\n```")
                lines.append("")

    # Errors
    if data.get("errors"):
        lines.extend(["---", "", "## Processing Notes", ""])
        for err in data["errors"]:
            lines.append(f"- {err}")
        lines.append("")

    lines.extend([
        "---",
        "",
        "*Generated by Ransomware Intelligence Agent | Data source: ransomware.live*",
        "*This report is machine-generated and should be validated by a qualified DFIR analyst.*",
    ])

    return "\n".join(lines)


def _render_fallback(data: dict[str, Any], summary: str) -> str:
    """Minimal fallback if rendering fails."""
    return json.dumps(
        {"summary": summary, "data": data},
        indent=2,
        default=str,
    )
