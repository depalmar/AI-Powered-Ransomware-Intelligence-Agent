"""Weighted multi-signal confidence scoring for ransomware group attribution.

Combines multiple forensic signals (ransom note similarity, IOC overlap,
TTP alignment, file extension patterns) into a single confidence score
with a full breakdown showing each signal's contribution.
"""

from __future__ import annotations

import logging
import re

from mcp_server.models import (
    ConfidenceResult,
    GroupTTP,
    IOCRecord,
    RansomNoteMatch,
    SignalScore,
)

logger = logging.getLogger("ransomware_intel.scoring")

# Signal weights — must sum to 1.0
WEIGHT_RANSOM_NOTE = 0.35
WEIGHT_IOC_OVERLAP = 0.30
WEIGHT_TTP_ALIGNMENT = 0.20
WEIGHT_FILE_EXTENSION = 0.15

# Known file extensions mapped to ransomware groups
KNOWN_EXTENSIONS: dict[str, list[str]] = {
    "lockbit": [".lockbit", ".lock", ".abcd"],
    "alphv": [".alphv", ".sykffle"],
    "clop": [".clop", ".cl0p", ".ciop"],
    "blackbasta": [".basta"],
    "royal": [".royal"],
    "akira": [".akira"],
    "play": [".play"],
    "rhysida": [".rhysida"],
    "medusa": [".medusa", ".medusalocker", ".encrypted"],
    "bianlian": [".bianlian"],
    "hunters": [".locked"],
    "ransomhub": [".ransomhub"],
    "8base": [".8base"],
}


def score_ransom_note(
    note_matches: list[RansomNoteMatch],
    group_name: str,
) -> SignalScore:
    """Score the ransom note signal for a specific group.

    Args:
        note_matches: Top matches from embedding similarity search.
        group_name: The group to score for.

    Returns:
        SignalScore for the ransom note signal.
    """
    raw_score = 0.0
    detail = "No ransom note match"

    for match in note_matches:
        if match.group_name.lower() == group_name.lower():
            raw_score = match.similarity_score
            detail = (
                f"{match.similarity_score:.0%} similarity via {match.match_method} "
                f"matching to known {group_name} notes"
            )
            break

    return SignalScore(
        signal_name="ransom_note",
        raw_score=raw_score,
        weight=WEIGHT_RANSOM_NOTE,
        weighted_score=raw_score * WEIGHT_RANSOM_NOTE,
        detail=detail,
    )


def score_ioc_overlap(
    submitted_iocs: list[str],
    known_iocs: list[IOCRecord],
    group_name: str,
) -> SignalScore:
    """Score the IOC overlap signal.

    Compares submitted IOCs against known IOCs for the group.

    Args:
        submitted_iocs: List of IOC values from the incident.
        known_iocs: Known IOCs for the candidate group.
        group_name: The group to score for.

    Returns:
        SignalScore for the IOC overlap signal.
    """
    if not submitted_iocs or not known_iocs:
        return SignalScore(
            signal_name="ioc_overlap",
            raw_score=0.0,
            weight=WEIGHT_IOC_OVERLAP,
            weighted_score=0.0,
            detail="No IOCs to compare" if not submitted_iocs else "No known IOCs for group",
        )

    known_values = {r.value.lower().strip() for r in known_iocs}
    submitted_values = {v.lower().strip() for v in submitted_iocs}
    overlap = submitted_values & known_values
    match_count = len(overlap)

    if match_count == 0:
        raw_score = 0.0
        detail = f"0/{len(submitted_values)} submitted IOCs match known {group_name} infrastructure"
    else:
        # Score based on fraction of submitted IOCs that match
        raw_score = min(match_count / max(len(submitted_values), 1), 1.0)
        detail = (
            f"{match_count}/{len(submitted_values)} submitted IOCs match "
            f"known {group_name} infrastructure"
        )

    return SignalScore(
        signal_name="ioc_overlap",
        raw_score=raw_score,
        weight=WEIGHT_IOC_OVERLAP,
        weighted_score=raw_score * WEIGHT_IOC_OVERLAP,
        detail=detail,
    )


def score_ttp_alignment(
    observed_ttps: list[str],
    known_ttps: list[GroupTTP],
    group_name: str,
) -> SignalScore:
    """Score the TTP alignment signal.

    Maps observed TTPs (descriptions or MITRE IDs) against the group's
    known ATT&CK mappings.

    Args:
        observed_ttps: Observed TTP descriptions or MITRE technique IDs.
        known_ttps: Known TTPs for the candidate group.
        group_name: The group to score for.

    Returns:
        SignalScore for the TTP alignment signal.
    """
    if not observed_ttps or not known_ttps:
        return SignalScore(
            signal_name="ttp_alignment",
            raw_score=0.0,
            weight=WEIGHT_TTP_ALIGNMENT,
            weighted_score=0.0,
            detail="No TTPs to compare" if not observed_ttps else "No known TTPs for group",
        )

    # Build lookup sets from known TTPs
    known_ids = {t.technique_id.upper() for t in known_ttps if t.technique_id}
    known_names = {t.technique_name.lower() for t in known_ttps if t.technique_name}
    known_tactics = {t.tactic.lower() for t in known_ttps if t.tactic}

    matches = 0
    for ttp in observed_ttps:
        ttp_upper = ttp.upper().strip()
        ttp_lower = ttp.lower().strip()

        # Check if it's a MITRE technique ID
        if re.match(r"T\d{4}(\.\d{3})?", ttp_upper):
            if ttp_upper in known_ids:
                matches += 1
                continue

        # Check by technique name or keyword
        if ttp_lower in known_names:
            matches += 1
            continue

        # Partial match against technique names and descriptions
        for known in known_ttps:
            combined = f"{known.technique_name} {known.description}".lower()
            if ttp_lower in combined or any(
                word in combined for word in ttp_lower.split() if len(word) > 3
            ):
                matches += 0.5
                break

    total_observed = len(observed_ttps)
    raw_score = min(matches / max(total_observed, 1), 1.0)
    detail = (
        f"{matches:.0f}/{total_observed} observed techniques align "
        f"with known {group_name} playbook"
    )

    return SignalScore(
        signal_name="ttp_alignment",
        raw_score=raw_score,
        weight=WEIGHT_TTP_ALIGNMENT,
        weighted_score=raw_score * WEIGHT_TTP_ALIGNMENT,
        detail=detail,
    )


def score_file_extension(
    observed_extension: str,
    group_name: str,
) -> SignalScore:
    """Score the file extension signal.

    Checks if the observed encrypted file extension matches known
    extensions for the candidate group.

    Args:
        observed_extension: The file extension found on encrypted files.
        group_name: The group to score for.

    Returns:
        SignalScore for the file extension signal.
    """
    if not observed_extension:
        return SignalScore(
            signal_name="file_extension",
            raw_score=0.0,
            weight=WEIGHT_FILE_EXTENSION,
            weighted_score=0.0,
            detail="No file extension observed",
        )

    ext = observed_extension.lower().strip()
    if not ext.startswith("."):
        ext = f".{ext}"

    group_key = group_name.lower().strip()
    known = KNOWN_EXTENSIONS.get(group_key, [])

    if ext in known:
        raw_score = 0.95
        detail = f"Extension {ext} is a known {group_name} extension"
    elif any(ext in KNOWN_EXTENSIONS.get(g, []) for g in KNOWN_EXTENSIONS):
        # Extension belongs to a different group
        raw_score = 0.0
        other = [
            g for g, exts in KNOWN_EXTENSIONS.items() if ext in exts
        ]
        detail = f"Extension {ext} associated with {', '.join(other)}, not {group_name}"
    else:
        # Generic extension — doesn't help or hurt
        raw_score = 0.3
        detail = f"Extension {ext} is not group-specific (generic)"

    return SignalScore(
        signal_name="file_extension",
        raw_score=raw_score,
        weight=WEIGHT_FILE_EXTENSION,
        weighted_score=raw_score * WEIGHT_FILE_EXTENSION,
        detail=detail,
    )


def calculate_confidence(
    group_name: str,
    note_matches: list[RansomNoteMatch] | None = None,
    submitted_iocs: list[str] | None = None,
    known_iocs: list[IOCRecord] | None = None,
    observed_ttps: list[str] | None = None,
    known_ttps: list[GroupTTP] | None = None,
    file_extension: str = "",
) -> ConfidenceResult:
    """Calculate composite attribution confidence for a candidate group.

    Combines all available signals into a weighted score with a full
    breakdown.

    Args:
        group_name: Candidate ransomware group name.
        note_matches: Ransom note similarity matches.
        submitted_iocs: IOC values from the incident.
        known_iocs: Known IOCs for this group.
        observed_ttps: Observed TTP descriptions or MITRE IDs.
        known_ttps: Known TTPs for this group.
        file_extension: Observed encrypted file extension.

    Returns:
        ConfidenceResult with composite score and signal breakdown.
    """
    signals: list[SignalScore] = []

    # Score each signal
    signals.append(score_ransom_note(note_matches or [], group_name))
    signals.append(score_ioc_overlap(submitted_iocs or [], known_iocs or [], group_name))
    signals.append(score_ttp_alignment(observed_ttps or [], known_ttps or [], group_name))
    signals.append(score_file_extension(file_extension, group_name))

    # Compute composite
    total = sum(s.weighted_score for s in signals)
    total = min(total, 1.0)

    return ConfidenceResult(
        group_name=group_name,
        total_score=round(total, 4),
        confidence_pct=round(total * 100, 1),
        confidence_label=ConfidenceResult.label_from_score(total),
        signals=signals,
    )
