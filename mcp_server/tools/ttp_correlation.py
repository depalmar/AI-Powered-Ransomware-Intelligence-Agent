"""correlate_ttps tool — accepts observed TTPs and maps them against
known group TTPs to produce ranked group matches with MITRE ATT&CK overlay.
"""

from __future__ import annotations

import logging
import re
from typing import Any


logger = logging.getLogger("ransomware_intel.tools.ttp_correlation")

# Map common forensic observations to MITRE ATT&CK technique IDs
OBSERVATION_TO_MITRE: dict[str, list[str]] = {
    "rdp": ["T1021.001"],
    "rdp lateral movement": ["T1021.001"],
    "psexec": ["T1021.002", "T1569.002"],
    "wmi": ["T1047"],
    "wmic": ["T1047"],
    "schtasks": ["T1053.005"],
    "scheduled task": ["T1053.005"],
    "registry run key": ["T1547.001"],
    "startup folder": ["T1547.001"],
    "rclone": ["T1567.002"],
    "data exfiltration": ["T1041", "T1567"],
    "mega.nz": ["T1567.002"],
    "vssadmin": ["T1490"],
    "shadow copy deletion": ["T1490"],
    "bcdedit": ["T1490"],
    "recovery disabled": ["T1490"],
    "cobalt strike": ["T1059.001", "T1071.001"],
    "powershell": ["T1059.001"],
    "mimikatz": ["T1003.001"],
    "credential dumping": ["T1003"],
    "lsass": ["T1003.001"],
    "phishing": ["T1566.001"],
    "spearphishing": ["T1566.001"],
    "exploit public": ["T1190"],
    "vpn exploit": ["T1190"],
    "ransomware deployment": ["T1486"],
    "encryption": ["T1486"],
    "inhibit system recovery": ["T1490"],
    "service stop": ["T1489"],
    "process injection": ["T1055"],
    "dll side-loading": ["T1574.002"],
    "living off the land": ["T1218"],
    "lolbas": ["T1218"],
    "certutil": ["T1140", "T1105"],
    "bitsadmin": ["T1197"],
    "mshta": ["T1218.005"],
    "rundll32": ["T1218.011"],
}


def map_observations_to_mitre(observations: list[str]) -> list[str]:
    """Map forensic observations to MITRE ATT&CK technique IDs.

    Args:
        observations: List of observed TTP descriptions or LOLBAS usage.

    Returns:
        List of unique MITRE ATT&CK technique IDs.
    """
    mitre_ids: set[str] = set()

    for obs in observations:
        obs_lower = obs.lower().strip()

        # Check if it's already a technique ID
        if re.match(r"^t\d{4}(\.\d{3})?$", obs_lower, re.IGNORECASE):
            mitre_ids.add(obs_lower.upper())
            continue

        # Map via the observation lookup
        for keyword, techniques in OBSERVATION_TO_MITRE.items():
            if keyword in obs_lower:
                mitre_ids.update(techniques)

    return sorted(mitre_ids)


# Known TTP profiles for major ransomware groups (MITRE ATT&CK technique IDs).
# Used for offline correlation when no live TTP API is available.
GROUP_TTP_PROFILES: dict[str, set[str]] = {
    "lockbit3": {
        "T1021.001", "T1021.002", "T1047", "T1053.005", "T1059.001",
        "T1486", "T1490", "T1567.002", "T1003.001", "T1190",
        "T1569.002", "T1218.011", "T1489",
    },
    "alphv": {
        "T1021.001", "T1047", "T1059.001", "T1486", "T1490",
        "T1003.001", "T1190", "T1055", "T1574.002", "T1218",
    },
    "blackbasta": {
        "T1021.001", "T1021.002", "T1059.001", "T1486", "T1490",
        "T1567.002", "T1003.001", "T1566.001", "T1071.001",
    },
    "clop": {
        "T1190", "T1486", "T1567", "T1059.001", "T1041",
        "T1105", "T1490",
    },
    "royal": {
        "T1021.001", "T1059.001", "T1486", "T1490", "T1566.001",
        "T1003.001", "T1071.001", "T1197",
    },
    "play": {
        "T1021.001", "T1021.002", "T1486", "T1490", "T1059.001",
        "T1003.001", "T1047", "T1569.002",
    },
    "akira": {
        "T1021.001", "T1190", "T1486", "T1490", "T1059.001",
        "T1567.002", "T1003.001",
    },
    "rhysida": {
        "T1021.001", "T1059.001", "T1486", "T1490", "T1003.001",
        "T1566.001",
    },
    "bianlian": {
        "T1021.001", "T1190", "T1567.002", "T1059.001", "T1003.001",
        "T1041",
    },
    "medusa": {
        "T1021.001", "T1486", "T1490", "T1059.001", "T1190",
        "T1003.001", "T1567",
    },
}


async def correlate_ttps(
    observed_ttps: list[str],
    candidate_groups: list[str] | None = None,
    top_k: int = 5,
) -> dict[str, Any]:
    """Correlate observed TTPs against known group TTP profiles.

    Maps observed techniques (descriptions, LOLBAS, MITRE IDs) against
    known group TTP profiles, returning ranked matches.

    Args:
        observed_ttps: List of TTP descriptions, technique IDs, or
            LOLBAS observations from the incident.
        candidate_groups: Optional list of groups to check. If None,
            checks all groups with known TTP profiles.
        top_k: Number of top-matching groups to return.

    Returns:
        Dict with:
            - mitre_ids: mapped MITRE technique IDs from observations
            - group_scores: list of (group, score, matched_ttps) ranked by score
            - top_match: name of the highest-scoring group
    """
    # Map observations to MITRE IDs
    mitre_ids = map_observations_to_mitre(observed_ttps)
    mitre_set = set(mitre_ids)
    logger.info("Mapped %d observations to %d MITRE techniques", len(observed_ttps), len(mitre_ids))

    if not mitre_ids:
        return {"mitre_ids": [], "group_scores": [], "top_match": None}

    # Determine which groups to check
    if candidate_groups:
        groups_to_check = candidate_groups
    else:
        groups_to_check = list(GROUP_TTP_PROFILES.keys())

    # Score each group
    group_scores: list[dict[str, Any]] = []

    for group_name in groups_to_check:
        group_techniques = GROUP_TTP_PROFILES.get(group_name, set())
        if not group_techniques:
            continue

        overlap = mitre_set & group_techniques
        if not overlap:
            continue

        # Score = fraction of observed techniques that match this group
        score = len(overlap) / max(len(mitre_set), 1)

        matched_details = [
            {"technique_id": tid} for tid in sorted(overlap)
        ]

        group_scores.append({
            "group": group_name,
            "score": round(score, 4),
            "overlap_count": len(overlap),
            "total_observed": len(mitre_set),
            "total_group_ttps": len(group_techniques),
            "matched_ttps": matched_details,
        })

    # Sort by score descending
    group_scores.sort(key=lambda x: x["score"], reverse=True)
    top_matches = group_scores[:top_k]

    return {
        "mitre_ids": mitre_ids,
        "group_scores": top_matches,
        "top_match": top_matches[0]["group"] if top_matches else None,
    }
