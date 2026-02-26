"""get_negotiation_intel tool — pulls negotiation transcripts for a group
and summarizes: typical demands, discount curves, response windows,
and decryptor reliability.
"""

from __future__ import annotations

import logging
import re

from mcp_server.api.client import APIClient
from mcp_server.api.pro_api import ProAPI
from mcp_server.models import NegotiationAdvisory, NegotiationEntry

logger = logging.getLogger("ransomware_intel.tools.negotiation")


async def get_negotiation_intel(group_name: str) -> dict:
    """Get negotiation intelligence for a ransomware group.

    Fetches negotiation transcripts from the PRO API and analyzes them
    to extract patterns: typical demands, discount behaviors, response
    windows, and decryptor reliability assessments.

    Args:
        group_name: Ransomware group name.

    Returns:
        Dict with:
            - advisory: NegotiationAdvisory summary
            - transcript_count: number of transcripts analyzed
            - raw_transcripts: list of NegotiationEntry objects
            - available: bool indicating if data was found
    """
    async with APIClient() as client:
        pro = ProAPI(client)
        transcripts = await pro.get_negotiations(group_name)

    if not transcripts:
        logger.info("No negotiation data available for %s", group_name)
        return {
            "advisory": NegotiationAdvisory(
                recommendation=(
                    f"No negotiation data available for {group_name}. "
                    "PRO API key may be required, or this group has no recorded negotiations."
                ),
            ),
            "transcript_count": 0,
            "raw_transcripts": [],
            "available": False,
        }

    advisory = _analyze_transcripts(group_name, transcripts)

    return {
        "advisory": advisory,
        "transcript_count": len(transcripts),
        "raw_transcripts": transcripts,
        "available": True,
    }


def _analyze_transcripts(
    group_name: str,
    transcripts: list[NegotiationEntry],
) -> NegotiationAdvisory:
    """Analyze negotiation transcripts to extract advisory intelligence.

    This is a heuristic-based analysis that looks for common patterns
    in negotiation transcripts. A production system would use an LLM
    for deeper analysis.

    Args:
        group_name: Group name for context.
        transcripts: List of negotiation entries.

    Returns:
        NegotiationAdvisory with analyzed intelligence.
    """
    all_text = " ".join(t.content for t in transcripts if t.content)

    # Extract demand amounts (look for dollar/BTC amounts)
    demands = _extract_monetary_values(all_text)
    if demands:
        min_d = min(demands)
        max_d = max(demands)
        demand_range = f"${min_d:,.0f} - ${max_d:,.0f} USD"
    else:
        demand_range = "Unable to extract — review transcripts manually"

    # Estimate discount patterns
    discount_pct = _estimate_discount(all_text)

    # Estimate response window
    response_window = _estimate_response_window(all_text)

    # Assess decryptor reliability
    reliability, reliability_detail = _assess_decryptor_reliability(group_name, all_text)

    # Generate recommendation
    recommendation = _generate_recommendation(
        group_name, len(transcripts), discount_pct, reliability
    )

    return NegotiationAdvisory(
        typical_demand_range=demand_range,
        avg_discount_pct=discount_pct,
        response_window=response_window,
        decryptor_reliability=reliability,
        reliability_detail=reliability_detail,
        recommendation=recommendation,
    )


def _extract_monetary_values(text: str) -> list[float]:
    """Extract dollar/monetary amounts from text."""
    values: list[float] = []
    # Match patterns like $100,000 or $1.5M or 100000 USD
    patterns = [
        r"\$\s*([\d,]+(?:\.\d+)?)\s*(?:million|m)\b",
        r"\$\s*([\d,]+(?:\.\d+)?)\s*(?:thousand|k)\b",
        r"\$\s*([\d,]+(?:\.\d+)?)",
        r"([\d,]+(?:\.\d+)?)\s*(?:USD|usd)",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            try:
                val = float(match.group(1).replace(",", ""))
                # Check if "million" was in the match context
                if "million" in match.group(0).lower() or match.group(0).lower().endswith("m"):
                    val *= 1_000_000
                elif "thousand" in match.group(0).lower() or match.group(0).lower().endswith("k"):
                    val *= 1_000
                if val > 0:
                    values.append(val)
            except ValueError:
                continue
    return values


def _estimate_discount(text: str) -> float:
    """Estimate typical discount percentage from negotiation text."""
    text_lower = text.lower()
    # Look for explicit discount mentions
    discount_matches = re.findall(r"(\d{1,2})%?\s*(?:discount|off|reduction)", text_lower)
    if discount_matches:
        discounts = [float(d) for d in discount_matches if 5 <= float(d) <= 90]
        if discounts:
            return round(sum(discounts) / len(discounts), 1)

    # Look for price reduction patterns
    if any(kw in text_lower for kw in ["negotiate", "lower", "reduce", "discount"]):
        return 30.0  # Common baseline for groups that negotiate

    return 0.0


def _estimate_response_window(text: str) -> str:
    """Estimate the typical response time window."""
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["24 hour", "1 day"]):
        return "24 hours"
    if any(kw in text_lower for kw in ["48 hour", "2 day"]):
        return "48 hours"
    if any(kw in text_lower for kw in ["72 hour", "3 day"]):
        return "72 hours"
    if any(kw in text_lower for kw in ["week", "7 day"]):
        return "7 days"
    return "48-72 hours (estimated)"


def _assess_decryptor_reliability(
    group_name: str,
    text: str,
) -> tuple[str, str]:
    """Assess decryptor reliability based on group reputation and transcript data."""
    text_lower = text.lower()

    # Groups with known reliable/unreliable decryptors (general industry knowledge)
    reliable_groups = {"lockbit", "alphv", "blackcat", "conti", "revil"}
    unreliable_groups = {"babuk", "hive"}

    group_lower = group_name.lower()

    if any(kw in text_lower for kw in ["decryptor works", "files restored", "successful"]):
        return "Moderate-High", "Positive reports found in negotiation transcripts"
    if any(kw in text_lower for kw in ["decryptor failed", "corrupted", "broken"]):
        return "Low", "Negative reports found in negotiation transcripts"

    if group_lower in reliable_groups:
        return "Moderate", f"{group_name} historically provides working decryptors"
    if group_lower in unreliable_groups:
        return "Low", f"{group_name} has history of unreliable decryptors"

    return "Unknown", "Insufficient data to assess decryptor reliability"


def _generate_recommendation(
    group_name: str,
    transcript_count: int,
    discount_pct: float,
    reliability: str,
) -> str:
    """Generate a high-level negotiation recommendation."""
    parts = []
    parts.append(
        f"Based on {transcript_count} analyzed negotiation(s) with {group_name}:"
    )

    if reliability in ("Low", "Unknown"):
        parts.append(
            "Decryptor reliability is uncertain — prioritize backup restoration "
            "and consider engaging a professional ransomware negotiator before "
            "making any payment decisions."
        )
    else:
        parts.append(
            "If restoration from backups is not viable, professional negotiation "
            "may be warranted."
        )

    if discount_pct > 0:
        parts.append(
            f"Historical data suggests ~{discount_pct:.0f}% discounts are achievable."
        )

    parts.append(
        "Consult legal counsel regarding regulatory obligations before engaging."
    )

    return " ".join(parts)
