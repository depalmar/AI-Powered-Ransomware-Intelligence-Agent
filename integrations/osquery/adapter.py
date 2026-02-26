"""osquery → Ransomware Intelligence Agent adapter.

Takes osquery JSON output (from Fleet, Kolide, or direct osqueryi),
normalizes it into IncidentArtifacts, and feeds to the agent for
enrichment and attribution.

Usage:
    from integrations.osquery.adapter import OsqueryAdapter

    adapter = OsqueryAdapter()
    result = await adapter.process_query_results(osquery_json)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from mcp_server.models import (
    HashArtifact,
    IOCType,
    IncidentArtifacts,
    NetworkIOC,
    PersistenceMechanism,
    PersistenceType,
    VictimInfo,
)

logger = logging.getLogger("ransomware_intel.integrations.osquery")


class OsqueryAdapter:
    """Adapter that bridges osquery results to the ransomware intelligence agent."""

    async def process_query_results(
        self,
        results: dict[str, list[dict[str, Any]]],
        incident_id: str = "",
        hostname: str = "",
    ) -> dict[str, Any]:
        """Process osquery results through the agent.

        Args:
            results: Dict mapping query name → list of result rows.
                Keys should match the query names in ransomware_pack.conf.
            incident_id: Optional incident ID.
            hostname: Optional hostname of the queried endpoint.

        Returns:
            Enriched analysis results.
        """
        if not incident_id:
            incident_id = f"OQ-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

        artifacts = self._normalize(results, incident_id, hostname)

        from mcp_server.tools.ir_brief import generate_ir_brief
        result = await generate_ir_brief(artifacts)

        return {
            "incident_id": incident_id,
            "hostname": hostname,
            "brief": result["brief"],
            "attribution": result["attribution"].model_dump(),
            "source": "osquery",
        }

    async def process_file(
        self,
        file_path: str,
        incident_id: str = "",
        hostname: str = "",
    ) -> dict[str, Any]:
        """Process an osquery JSON export file.

        Args:
            file_path: Path to JSON file with osquery results.
            incident_id: Optional incident ID.
            hostname: Optional hostname.

        Returns:
            Enriched analysis results.
        """
        with open(file_path) as f:
            data = json.load(f)
        return await self.process_query_results(data, incident_id, hostname)

    async def process_bulk(
        self,
        fleet_results: list[dict[str, Any]],
        incident_id: str = "",
    ) -> list[dict[str, Any]]:
        """Process results from multiple hosts (fleet-wide query).

        Args:
            fleet_results: List of per-host result dicts, each with
                "hostname" and "results" keys.
            incident_id: Base incident ID (host suffix added).

        Returns:
            List of enriched results, one per host.
        """
        all_results = []
        for i, host_data in enumerate(fleet_results):
            hostname = host_data.get("hostname", f"host-{i}")
            host_incident_id = f"{incident_id or 'OQ'}-{hostname}"
            result = await self.process_query_results(
                host_data.get("results", {}),
                incident_id=host_incident_id,
                hostname=hostname,
            )
            all_results.append(result)
        return all_results

    def _normalize(
        self,
        results: dict[str, list[dict[str, Any]]],
        incident_id: str,
        hostname: str,
    ) -> IncidentArtifacts:
        """Normalize osquery results into IncidentArtifacts."""
        hashes: list[HashArtifact] = []
        network_iocs: list[NetworkIOC] = []
        persistence: list[PersistenceMechanism] = []
        lolbas: list[str] = []

        # Process suspicious executables
        for row in results.get("suspicious_executables", []):
            sha256 = row.get("sha256", "")
            if sha256:
                hashes.append(HashArtifact(
                    hash_type=IOCType.SHA256,
                    value=sha256,
                    filename=row.get("filename", row.get("path", "")),
                ))

        # Process scheduled tasks
        for row in results.get("ransomware_scheduled_tasks", []):
            persistence.append(PersistenceMechanism(
                persistence_type=PersistenceType.SCHEDULED_TASK,
                name=row.get("name", ""),
                command=row.get("action", row.get("path", "")),
            ))

        # Process registry run keys
        for row in results.get("ransomware_registry_run_keys", []):
            persistence.append(PersistenceMechanism(
                persistence_type=PersistenceType.REGISTRY_RUN_KEY,
                name=row.get("name", ""),
                path=row.get("key", ""),
                value=row.get("data", ""),
            ))

        # Process network connections
        for row in results.get("suspicious_network_connections", []):
            remote_ip = row.get("remote_address", "")
            if remote_ip:
                network_iocs.append(NetworkIOC(
                    ioc_type=IOCType.IP,
                    value=remote_ip,
                    port=int(row.get("remote_port", 0)) or None,
                    note=f"Connection from {row.get('name', 'unknown')} ({row.get('path', '')})",
                ))

        # Process services from suspicious paths
        for row in results.get("recently_created_services", []):
            persistence.append(PersistenceMechanism(
                persistence_type=PersistenceType.SERVICE,
                name=row.get("name", ""),
                command=row.get("path", ""),
            ))

        # Detect file extension from ransomware_file_extensions query
        file_extension = ""
        ext_results = results.get("ransomware_file_extensions", [])
        if ext_results:
            first_file = ext_results[0].get("filename", "")
            if "." in first_file:
                file_extension = "." + first_file.rsplit(".", 1)[-1]

        return IncidentArtifacts(
            incident_id=incident_id,
            victim=VictimInfo(company=hostname),
            hashes=hashes,
            file_extension=file_extension,
            network_iocs=network_iocs,
            persistence=persistence,
            lolbas=lolbas,
        )
