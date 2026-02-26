"""Ransomware.live Free API v2 client.

Wraps the public (no key required) endpoints. These are always available
and form the baseline intelligence capability.

API docs: https://api.ransomware.live
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_server.api.client import APIClient
from mcp_server.models import GroupProfile, GroupYaraRule, VictimRecord

logger = logging.getLogger("ransomware_intel.api.free")


class FreeAPI:
    """Client for ransomware.live free API v2 endpoints."""

    def __init__(self, client: APIClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    async def get_groups(self) -> list[dict[str, Any]]:
        """Get all known ransomware groups.

        Returns:
            List of group data dicts.
        """
        result = await self._client.get("/groups")
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            # API may wrap groups in a key like "data" or "groups"
            for key in ("data", "groups", "results"):
                if key in result and isinstance(result[key], list):
                    return result[key]
            # API may return a dict keyed by group name
            # Check if values look like group objects
            first_val = next(iter(result.values()), None) if result else None
            if isinstance(first_val, dict):
                return list(result.values())
            return [result] if result else []
        return []

    async def get_group(self, name: str) -> GroupProfile | None:
        """Get profile for a specific ransomware group.

        Args:
            name: Group name (e.g. "lockbit3", "alphv").

        Returns:
            GroupProfile or None if not found.
        """
        data = await self._client.get_or_none(f"/groups/{name}")
        if not data:
            return None
        # API may return a list with one item or a dict
        record = data[0] if isinstance(data, list) else data
        return GroupProfile(
            name=record.get("name", name),
            description=record.get("description", ""),
            url=record.get("url", ""),
            first_seen=record.get("first_seen", ""),
            last_seen=record.get("last_seen", ""),
            locations=record.get("locations", []),
            profiles=record.get("profile", []),
            meta=record.get("meta"),
        )

    # ------------------------------------------------------------------
    # Victims
    # ------------------------------------------------------------------

    async def search_victims(self, keyword: str) -> list[VictimRecord]:
        """Search victims by keyword.

        Args:
            keyword: Search term (company name, keyword, etc.).

        Returns:
            List of matching victim records.
        """
        data = await self._client.get_or_none(f"/victims/search/{keyword}")
        if not data:
            return []
        items = self._unwrap_list(data)
        return [r for v in items if (r := self._parse_victim(v)) is not None]

    async def get_sector_victims(self, sector: str) -> list[VictimRecord]:
        """Get victims filtered by sector.

        Args:
            sector: Industry sector name.

        Returns:
            List of victim records in that sector.
        """
        data = await self._client.get_or_none("/victims/", params={"sector": sector})
        if not data:
            return []
        items = self._unwrap_list(data)
        return [r for v in items if (r := self._parse_victim(v)) is not None]

    async def get_victims_by_month(self, year: int, month: int) -> list[VictimRecord]:
        """Get victims for a specific month.

        Args:
            year: Four-digit year.
            month: Month number (1-12).

        Returns:
            List of victim records for that period.
        """
        data = await self._client.get_or_none("/victims/", params={"year": year, "month": month})
        if not data:
            return []
        items = self._unwrap_list(data)
        return [r for v in items if (r := self._parse_victim(v)) is not None]

    async def get_recent_victims(self) -> list[VictimRecord]:
        """Get the most recent victims across all groups.

        Returns:
            List of recent victim records.
        """
        data = await self._client.get_or_none("/victims/recent")
        if not data:
            return []
        items = self._unwrap_list(data)
        return [r for v in items if (r := self._parse_victim(v)) is not None]

    # ------------------------------------------------------------------
    # YARA
    # ------------------------------------------------------------------

    async def get_group_yara(self, group_name: str) -> list[GroupYaraRule]:
        """Get YARA rules for a ransomware group.

        Args:
            group_name: Group name.

        Returns:
            List of YARA rules.
        """
        data = await self._client.get_or_none(f"/yara/{group_name}")
        if not data:
            return []
        rules = data if isinstance(data, list) else [data]
        return [
            GroupYaraRule(
                rule_name=r.get("rule_name", r.get("name", "")),
                rule_content=r.get("rule_content", r.get("yara", r.get("content", ""))),
                source=r.get("source", ""),
            )
            for r in rules
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _unwrap_list(data: Any) -> list:
        """Unwrap API response into a list of items.

        Handles both direct lists and dict-wrapped responses.
        """
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Check for common wrapper keys
            for key in ("data", "results", "victims", "items"):
                if key in data and isinstance(data[key], list):
                    return data[key]
            # If values look like victim records, return them
            first_val = next(iter(data.values()), None) if data else None
            if isinstance(first_val, dict):
                return list(data.values())
        return []

    @staticmethod
    def _parse_victim(data: Any) -> VictimRecord | None:
        """Parse a raw victim dict into a VictimRecord."""
        if not isinstance(data, dict):
            return None
        return VictimRecord(
            group=data.get("group_name", data.get("group", "")),
            victim=data.get("post_title", data.get("victim", data.get("name", ""))),
            country=data.get("country", ""),
            sector=data.get("activity", data.get("sector", "")),
            published=data.get("discovered", data.get("published", "")),
            url=data.get("post_url", data.get("url", "")),
            description=data.get("description", ""),
        )
