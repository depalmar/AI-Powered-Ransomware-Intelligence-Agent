"""lookup_iocs tool — queries ransomware.live IOC database for hashes,
IPs, and domains. Returns matches and flags unknown IOCs.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from mcp_server.api.client import APIClient
from mcp_server.api.free_api import FreeAPI
from mcp_server.api.pro_api import ProAPI
from mcp_server.models import IOCRecord, IOCType

logger = logging.getLogger("ransomware_intel.tools.ioc_lookup")

# Regex patterns for IOC type detection
_HASH_PATTERNS = {
    IOCType.MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
    IOCType.SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
    IOCType.SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
}
_IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def classify_ioc(value: str) -> IOCType | None:
    """Detect what type of IOC a value is.

    Args:
        value: Raw IOC value string.

    Returns:
        IOCType enum or None if unrecognized.
    """
    cleaned = value.strip()

    # Strip hash type prefix if present (e.g. "sha256:abc123...")
    if ":" in cleaned:
        parts = cleaned.split(":", 1)
        prefix = parts[0].lower()
        if prefix in ("md5", "sha1", "sha256"):
            cleaned = parts[1]

    for hash_type, pattern in _HASH_PATTERNS.items():
        if pattern.match(cleaned):
            return hash_type
    if _IP_PATTERN.match(cleaned):
        return IOCType.IP
    if _DOMAIN_PATTERN.match(cleaned):
        return IOCType.DOMAIN
    return None


def extract_ioc_value(raw: str) -> str:
    """Extract the actual IOC value, stripping type prefixes."""
    if ":" in raw:
        parts = raw.split(":", 1)
        if parts[0].lower() in ("md5", "sha1", "sha256"):
            return parts[1].strip()
    return raw.strip()


async def lookup_iocs(
    ioc_values: list[str],
    candidate_groups: list[str] | None = None,
) -> dict[str, Any]:
    """Look up IOCs against the ransomware.live database.

    Classifies each IOC by type, queries known group IOC databases,
    and returns matches plus a list of unknown/unmatched IOCs.

    Args:
        ioc_values: List of raw IOC strings (hashes, IPs, domains).
        candidate_groups: Optional list of groups to check against.
            If None, checks all groups with known IOCs.

    Returns:
        Dict with keys:
            - matched: list of IOCRecord matches
            - unmatched: list of IOC values with no matches
            - classified: dict mapping each IOC to its type
            - groups_checked: list of group names that were queried
    """
    if not ioc_values:
        return {"matched": [], "unmatched": [], "classified": {}, "groups_checked": []}

    # Classify all IOCs
    classified: dict[str, str] = {}
    clean_values: list[str] = []
    for raw in ioc_values:
        clean = extract_ioc_value(raw)
        clean_values.append(clean)
        ioc_type = classify_ioc(clean)
        classified[clean] = ioc_type.value if ioc_type else "unknown"

    matched: list[IOCRecord] = []
    matched_values: set[str] = set()
    groups_checked: list[str] = []

    async with APIClient() as client:
        pro = ProAPI(client)
        free = FreeAPI(client)

        # Determine which groups to check
        groups_to_check = candidate_groups or []
        if not groups_to_check:
            # Get all groups and check a reasonable set
            all_groups = await free.get_groups()
            groups_to_check = [
                g.get("name", "") for g in all_groups if g.get("name")
            ]

        for group_name in groups_to_check:
            if not group_name:
                continue
            groups_checked.append(group_name)

            group_iocs = await pro.get_group_iocs(group_name)
            if not group_iocs:
                continue

            known_values = {r.value.lower().strip() for r in group_iocs}
            for clean_val in clean_values:
                if clean_val.lower() in known_values and clean_val not in matched_values:
                    matched_values.add(clean_val)
                    matched.append(
                        IOCRecord(
                            group=group_name,
                            ioc_type=classified.get(clean_val, ""),
                            value=clean_val,
                            source="ransomware.live",
                        )
                    )

    unmatched = [v for v in clean_values if v not in matched_values]

    return {
        "matched": matched,
        "unmatched": unmatched,
        "classified": classified,
        "groups_checked": groups_checked,
    }
