"""Ransomware.live PRO API client.

Wraps endpoints that require a PRO API key. These provide deeper intelligence:
IOCs, TTPs, negotiations, SEC filings, and ransom note text.

If no PRO key is configured, methods return empty results and log a warning.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_server.api.client import APIClient
from mcp_server.config import settings
from mcp_server.models import (
    GroupTTP,
    IOCRecord,
    NegotiationEntry,
    SECFiling,
)

logger = logging.getLogger("ransomware_intel.api.pro")

_NO_KEY_MSG = "PRO API key not configured — skipping %s"


class ProAPI:
    """Client for ransomware.live PRO API endpoints."""

    def __init__(self, client: APIClient) -> None:
        self._client = client

    def _has_key(self, endpoint: str) -> bool:
        """Check if a PRO key is available; log a warning if not."""
        if not settings.has_pro_api:
            logger.warning(_NO_KEY_MSG, endpoint)
            return False
        return True

    # ------------------------------------------------------------------
    # Ransom Notes
    # ------------------------------------------------------------------

    async def get_ransom_note_text(self, group_name: str) -> str:
        """Get the known ransom note text for a group.

        Args:
            group_name: Ransomware group name.

        Returns:
            Ransom note text, or empty string if unavailable.
        """
        if not self._has_key("ransomnotestext"):
            return ""
        data = await self._client.get_or_none(f"/ransomnotes/{group_name}")
        if not data:
            return ""
        if isinstance(data, list) and data:
            return data[0].get("text", data[0].get("content", str(data[0])))
        if isinstance(data, dict):
            return data.get("text", data.get("content", str(data)))
        return str(data)

    async def get_all_ransom_notes(self) -> dict[str, str]:
        """Get ransom note text for all groups.

        Returns:
            Dict mapping group name → ransom note text.
        """
        if not self._has_key("ransomnotestext"):
            return {}
        data = await self._client.get_or_none("/ransomnotes")
        if not data:
            return {}
        notes: dict[str, str] = {}
        if isinstance(data, list):
            for item in data:
                group = item.get("group_name", item.get("group", ""))
                text = item.get("text", item.get("content", ""))
                if group and text:
                    notes[group] = text
        return notes

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    async def get_group_iocs(self, group_name: str) -> list[IOCRecord]:
        """Get IOCs associated with a ransomware group.

        Args:
            group_name: Ransomware group name.

        Returns:
            List of IOC records.
        """
        if not self._has_key("iocs"):
            return []
        data = await self._client.get_or_none(f"/iocs/{group_name}")
        if not data:
            return []
        records = data if isinstance(data, list) else [data]
        return [
            IOCRecord(
                group=r.get("group_name", r.get("group", group_name)),
                ioc_type=r.get("type", r.get("ioc_type", "")),
                value=r.get("value", r.get("ioc", "")),
                source=r.get("source", ""),
                date_added=r.get("date_added", r.get("date", "")),
            )
            for r in records
        ]

    # ------------------------------------------------------------------
    # TTPs
    # ------------------------------------------------------------------

    async def get_group_ttps(self, group_name: str) -> list[GroupTTP]:
        """Get MITRE ATT&CK TTPs for a ransomware group.

        Args:
            group_name: Ransomware group name.

        Returns:
            List of TTP records.
        """
        if not self._has_key("ttps"):
            return []
        # TTPs may be embedded in the group profile from /groups/{name}
        data = await self._client.get_or_none(f"/groups/{group_name}")
        if not data:
            return []
        # Extract TTPs from group data if present
        record = data[0] if isinstance(data, list) else data
        ttp_data = record.get("ttps", record.get("mitre_attack", []))
        if not ttp_data:
            return []
        records = ttp_data if isinstance(ttp_data, list) else [ttp_data]
        return [
            GroupTTP(
                tactic=r.get("tactic", ""),
                technique_id=r.get("technique_id", r.get("id", "")),
                technique_name=r.get("technique_name", r.get("name", "")),
                description=r.get("description", ""),
            )
            for r in records
        ]

    # ------------------------------------------------------------------
    # Negotiations
    # ------------------------------------------------------------------

    async def get_negotiations(self, group_name: str) -> list[NegotiationEntry]:
        """Get negotiation transcripts for a ransomware group.

        Args:
            group_name: Ransomware group name.

        Returns:
            List of negotiation entries.
        """
        if not self._has_key("negotiations"):
            return []
        data = await self._client.get_or_none(f"/negotiations/{group_name}")
        if not data:
            return []
        records = data if isinstance(data, list) else [data]
        return [
            NegotiationEntry(
                group=r.get("group_name", r.get("group", group_name)),
                title=r.get("title", ""),
                content=r.get("content", r.get("text", "")),
                url=r.get("url", ""),
            )
            for r in records
        ]

    # ------------------------------------------------------------------
    # SEC 8-K Filings
    # ------------------------------------------------------------------

    async def get_8k_filings(
        self,
        ticker: str | None = None,
        cik: str | None = None,
    ) -> list[SECFiling]:
        """Get SEC cybersecurity 8-K incident disclosures.

        Args:
            ticker: Filter by stock ticker symbol.
            cik: Filter by SEC CIK number.

        Returns:
            List of SEC filing records.
        """
        if not self._has_key("8k"):
            return []

        # Build the endpoint path based on filters
        path = "/8k"

        data = await self._client.get_or_none(path)
        if not data:
            return []
        records = data if isinstance(data, list) else [data]
        return [
            SECFiling(
                company=r.get("company", r.get("company_name", "")),
                ticker=r.get("ticker", ""),
                cik=r.get("cik", ""),
                filed=r.get("filed", r.get("date", "")),
                url=r.get("url", r.get("link", "")),
                description=r.get("description", r.get("title", "")),
            )
            for r in records
        ]
