"""generate_ir_brief tool — orchestrator that runs the full attribution
pipeline and generates a structured intelligence report.

This is the primary composite tool: it calls other tools internally,
collects all evidence, runs attribution, and renders a Jinja2 template.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from mcp_server.config import settings
from mcp_server.models import (
    AttributionResult,
    ConfidenceResult,
    IRBriefData,
    IncidentArtifacts,
    NegotiationAdvisory,
)
from mcp_server.scoring.confidence import calculate_confidence
from mcp_server.tools.group_profile import get_group_profile, get_group_ttps, get_group_yara
from mcp_server.tools.ioc_lookup import extract_ioc_value, lookup_iocs
from mcp_server.tools.negotiation import get_negotiation_intel
from mcp_server.tools.ransom_note import match_ransom_note
from mcp_server.tools.ttp_correlation import correlate_ttps, map_observations_to_mitre

logger = logging.getLogger("ransomware_intel.tools.ir_brief")

# Template directory
TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"


async def generate_ir_brief(
    artifacts: IncidentArtifacts,
    output_format: str = "markdown",
) -> dict[str, Any]:
    """Run the full attribution pipeline and generate an IR brief.

    This is the orchestrator tool. It:
    1. Matches the ransom note against known groups
    2. Looks up IOCs against known infrastructure
    3. Correlates observed TTPs with group playbooks
    4. Calculates confidence scores for candidate groups
    5. Enriches with group profile, negotiation intel, and YARA rules
    6. Renders a structured IR brief using a Jinja2 template

    Args:
        artifacts: Collected forensic artifacts from the incident.
        output_format: Output format — "markdown" or "json".

    Returns:
        Dict with:
            - brief: rendered report (markdown string or dict)
            - attribution: full AttributionResult
            - brief_data: IRBriefData model
    """
    logger.info("Starting IR brief generation for incident %s", artifacts.incident_id)

    # Step 1: Match ransom note
    note_matches = []
    if artifacts.ransom_note and artifacts.ransom_note.content:
        logger.info("Matching ransom note...")
        note_matches = await match_ransom_note(artifacts.ransom_note.content)

    # Step 2: Look up IOCs
    ioc_values = []
    for h in artifacts.hashes:
        ioc_values.append(h.value)
    for n in artifacts.network_iocs:
        ioc_values.append(n.value)

    ioc_result: dict[str, Any] = {"matched": [], "unmatched": ioc_values}
    if ioc_values:
        logger.info("Looking up %d IOCs...", len(ioc_values))
        # Use top ransom note matches as candidate groups
        candidate_groups = [m.group_name for m in note_matches[:5]]
        ioc_result = await lookup_iocs(ioc_values, candidate_groups or None)

    # Step 3: Correlate TTPs
    observed_ttps = []
    for p in artifacts.persistence:
        observed_ttps.append(f"{p.persistence_type.value}: {p.name or p.command}")
    for lm in artifacts.lateral_movement:
        observed_ttps.append(f"{lm.method.value} lateral movement")
    observed_ttps.extend(artifacts.lolbas)

    ttp_result: dict[str, Any] = {"mitre_ids": [], "group_scores": []}
    if observed_ttps:
        logger.info("Correlating %d observed TTPs...", len(observed_ttps))
        candidate_groups = [m.group_name for m in note_matches[:5]]
        ttp_result = await correlate_ttps(observed_ttps, candidate_groups or None)

    # Step 4: Determine candidate groups and score them
    candidates = _collect_candidates(note_matches, ioc_result, ttp_result)
    logger.info("Scoring %d candidate groups...", len(candidates))

    scored_groups: list[ConfidenceResult] = []
    for group_name in candidates:
        # Get group-specific known data for scoring
        known_iocs = ioc_result.get("matched", [])
        known_ttps_data = await _get_known_ttps(group_name)

        score = calculate_confidence(
            group_name=group_name,
            note_matches=note_matches,
            submitted_iocs=[extract_ioc_value(v) for v in ioc_values],
            known_iocs=[i for i in known_iocs if i.group.lower() == group_name.lower()],
            observed_ttps=observed_ttps,
            known_ttps=known_ttps_data,
            file_extension=artifacts.file_extension,
        )
        scored_groups.append(score)

    # Sort by confidence
    scored_groups.sort(key=lambda s: s.total_score, reverse=True)

    # Step 5: Build attribution result
    primary_group = scored_groups[0].group_name if scored_groups else "Unknown"
    primary_confidence = scored_groups[0] if scored_groups else ConfidenceResult(
        group_name="Unknown",
        total_score=0.0,
        confidence_pct=0.0,
        confidence_label="Insufficient",
    )

    attribution = AttributionResult(
        primary_group=primary_group,
        confidence=primary_confidence,
        alternative_groups=scored_groups[1:3] if len(scored_groups) > 1 else [],
        ransom_note_matches=note_matches,
        matched_iocs=ioc_result.get("matched", []),
        matched_ttps=known_ttps_data if primary_group != "Unknown" else [],
    )

    # Step 6: Enrich with profile, negotiation, YARA
    profile_data = {}
    negotiation_data: dict[str, Any] = {"advisory": NegotiationAdvisory()}
    yara_data: dict[str, Any] = {"rules": []}

    if primary_group != "Unknown":
        logger.info("Enriching attribution for %s...", primary_group)
        profile_data = await get_group_profile(primary_group)
        negotiation_data = await get_negotiation_intel(primary_group)
        yara_data = await get_group_yara(primary_group)

        if profile_data.get("profile"):
            attribution.group_profile = profile_data["profile"]

    # Step 7: Build IR brief data
    brief_data = IRBriefData(
        incident_id=artifacts.incident_id,
        artifacts=artifacts,
        attribution=attribution,
        negotiation=negotiation_data.get("advisory"),
        yara_rules=yara_data.get("rules", []),
        recommended_actions=_generate_actions(primary_group, artifacts),
        executive_summary=_generate_summary(artifacts, attribution),
    )

    # Step 8: Render the report
    if output_format == "json":
        brief = brief_data.model_dump(mode="json")
    else:
        brief = _render_template(brief_data)

    logger.info(
        "IR brief generated: %s attributed to %s (%.1f%% confidence)",
        artifacts.incident_id,
        primary_group,
        primary_confidence.confidence_pct,
    )

    return {
        "brief": brief,
        "attribution": attribution,
        "brief_data": brief_data,
    }


def _collect_candidates(
    note_matches: list,
    ioc_result: dict,
    ttp_result: dict,
) -> list[str]:
    """Collect unique candidate groups from all signals."""
    candidates: dict[str, bool] = {}

    for m in note_matches:
        candidates[m.group_name] = True

    for ioc in ioc_result.get("matched", []):
        candidates[ioc.group] = True

    for gs in ttp_result.get("group_scores", []):
        candidates[gs["group"]] = True

    return list(candidates.keys())


async def _get_known_ttps(group_name: str) -> list:
    """Get known TTPs for a group (for confidence scoring)."""
    try:
        result = await get_group_ttps(group_name)
        return result.get("ttps", [])
    except Exception:
        return []


def _generate_summary(
    artifacts: IncidentArtifacts,
    attribution: AttributionResult,
) -> str:
    """Generate a 2-3 sentence executive summary."""
    group = attribution.primary_group
    confidence = attribution.confidence.confidence_pct
    victim = artifacts.victim.company or "the victim organization"
    sector = artifacts.victim.sector or "unknown sector"

    summary = (
        f"{victim} ({sector}) was targeted in a ransomware attack "
        f"attributed to {group} with {confidence:.0f}% confidence. "
    )

    if artifacts.lateral_movement:
        hosts = len(set(
            lm.destination for lm in artifacts.lateral_movement
        ))
        summary += f"The threat actor laterally moved across {hosts} systems. "

    if artifacts.lolbas:
        summary += (
            f"Living-off-the-land techniques were observed including "
            f"{', '.join(artifacts.lolbas[:3])}. "
        )

    return summary.strip()


def _generate_actions(group_name: str, artifacts: IncidentArtifacts) -> list[str]:
    """Generate recommended immediate actions."""
    actions = [
        "Isolate all confirmed compromised hosts from the network immediately",
        "Deploy YARA rules from this report across all endpoints for sweep",
        f"Block all IOCs from this report at network perimeter (firewall, proxy, DNS)",
    ]

    if artifacts.lateral_movement:
        hosts = set()
        for lm in artifacts.lateral_movement:
            hosts.add(lm.source)
            hosts.add(lm.destination)
        actions.append(
            f"Forensically image the following hosts: {', '.join(sorted(hosts))}"
        )

    actions.extend([
        "Reset all domain admin and service account credentials",
        "Notify legal counsel and begin regulatory disclosure assessment",
        f"Brief leadership on {group_name} attack profile and likely next steps",
        "Engage incident response retainer if not already done",
    ])

    return actions


def _render_template(data: IRBriefData) -> str:
    """Render the IR brief using the Jinja2 template."""
    try:
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template("ir_brief.md.j2")
        return template.render(data=data)
    except Exception as exc:
        logger.warning("Template rendering failed, using fallback: %s", exc)
        return _render_fallback(data)


def _render_fallback(data: IRBriefData) -> str:
    """Fallback plain-text rendering if Jinja2 template fails."""
    lines = [
        "# Ransomware Incident Intelligence Brief",
        f"**Incident ID:** {data.incident_id}",
        f"**Generated:** {data.generated_at.isoformat()}",
        f"**Confidence Level:** {data.attribution.confidence.confidence_pct}% "
        f"({data.attribution.confidence.confidence_label})",
        "",
        "## Executive Summary",
        data.executive_summary,
        "",
        "## Attribution",
        f"**Primary Attribution:** {data.attribution.primary_group} "
        f"({data.attribution.confidence.confidence_pct}%)",
        "",
        "### Signal Breakdown",
    ]

    for signal in data.attribution.confidence.signals:
        lines.append(f"- **{signal.signal_name}:** {signal.detail}")

    if data.negotiation:
        lines.extend([
            "",
            "## Negotiation Advisory",
            f"- **Typical Demand:** {data.negotiation.typical_demand_range}",
            f"- **Historical Discount:** {data.negotiation.avg_discount_pct}%",
            f"- **Response Window:** {data.negotiation.response_window}",
            f"- **Decryptor Reliability:** {data.negotiation.decryptor_reliability}",
            f"- **Recommendation:** {data.negotiation.recommendation}",
        ])

    if data.recommended_actions:
        lines.extend(["", "## Recommended Immediate Actions"])
        for i, action in enumerate(data.recommended_actions, 1):
            lines.append(f"{i}. {action}")

    if data.yara_rules:
        lines.extend(["", "## YARA Rules"])
        for rule in data.yara_rules:
            lines.append(f"```yara\n{rule.rule_content}\n```")

    lines.extend([
        "",
        "---",
        "*Generated by Ransomware Intelligence Agent | Data source: ransomware.live*",
        "*This report is machine-generated and should be validated by a qualified DFIR analyst.*",
    ])

    return "\n".join(lines)
