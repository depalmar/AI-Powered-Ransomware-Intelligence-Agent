"""Velociraptor → Ransomware Intelligence Agent adapter.

Takes Velociraptor API output (hunt results or flow results),
normalizes the data into IncidentArtifacts format, feeds it to
the agent, and returns enriched results.

Usage:
    from integrations.velociraptor.adapter import VelociraptorAdapter

    adapter = VelociraptorAdapter(api_url="https://velociraptor:8001")
    result = await adapter.process_hunt("H.abc123")
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp_server.models import (
    HashArtifact,
    IOCType,
    IncidentArtifacts,
    NetworkIOC,
    PersistenceMechanism,
    PersistenceType,
    RansomNoteArtifact,
    VictimInfo,
)

logger = logging.getLogger("ransomware_intel.integrations.velociraptor")


class VelociraptorAdapter:
    """Adapter that bridges Velociraptor artifact data to the agent."""

    def __init__(self, api_url: str = "", api_key: str = "") -> None:
        self.api_url = api_url
        self.api_key = api_key

    async def process_hunt_results(
        self,
        hunt_results: dict[str, Any],
        incident_id: str = "",
    ) -> dict[str, Any]:
        """Process Velociraptor hunt results through the agent.

        Args:
            hunt_results: Raw JSON output from a Velociraptor hunt
                containing results from the RansomwareIndicatorCollector
                artifact.
            incident_id: Optional incident ID. Auto-generated if not provided.

        Returns:
            Dict with the enriched IR brief and attribution data.
        """
        if not incident_id:
            incident_id = f"VR-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

        # Normalize the hunt results into IncidentArtifacts
        artifacts = self._normalize(hunt_results, incident_id)

        # Run through the agent
        from mcp_server.tools.ir_brief import generate_ir_brief
        result = await generate_ir_brief(artifacts)

        return {
            "incident_id": incident_id,
            "brief": result["brief"],
            "attribution": result["attribution"].model_dump(),
            "source": "velociraptor",
        }

    async def process_file(
        self,
        file_path: str,
        incident_id: str = "",
    ) -> dict[str, Any]:
        """Process a Velociraptor JSON export file.

        Args:
            file_path: Path to the JSON export from Velociraptor.
            incident_id: Optional incident ID.

        Returns:
            Enriched analysis results.
        """
        with open(file_path) as f:
            data = json.load(f)
        return await self.process_hunt_results(data, incident_id)

    def _normalize(
        self,
        data: dict[str, Any],
        incident_id: str,
    ) -> IncidentArtifacts:
        """Normalize Velociraptor output into IncidentArtifacts."""
        # Extract ransom notes
        ransom_note = None
        notes = data.get("RansomNotes", data.get("ransom_notes", []))
        if isinstance(notes, list) and notes:
            first_note = notes[0]
            ransom_note = RansomNoteArtifact(
                filename=first_note.get("Name", first_note.get("name", "ransom_note.txt")),
                content=first_note.get("Content", first_note.get("content", "")),
            )

        # Extract hashes
        hashes: list[HashArtifact] = []
        suspicious = data.get("SuspiciousHashes", data.get("suspicious_hashes", []))
        if isinstance(suspicious, list):
            for item in suspicious:
                hash_data = item.get("Hash", item.get("hash", {}))
                if isinstance(hash_data, dict):
                    sha256 = hash_data.get("SHA256", hash_data.get("sha256", ""))
                    if sha256:
                        hashes.append(HashArtifact(
                            hash_type=IOCType.SHA256,
                            value=sha256,
                            filename=item.get("Name", item.get("name", "")),
                        ))

        # Extract persistence mechanisms
        persistence: list[PersistenceMechanism] = []

        # Scheduled tasks
        tasks = data.get("ScheduledTasks", data.get("scheduled_tasks", []))
        if isinstance(tasks, list):
            for task in tasks:
                persistence.append(PersistenceMechanism(
                    persistence_type=PersistenceType.SCHEDULED_TASK,
                    name=task.get("Name", task.get("name", "")),
                    command=str(task.get("Actions", task.get("actions", ""))),
                ))

        # Registry run keys
        reg_keys = data.get("RegistryRunKeys", data.get("registry_run_keys", []))
        if isinstance(reg_keys, list):
            for key in reg_keys:
                persistence.append(PersistenceMechanism(
                    persistence_type=PersistenceType.REGISTRY_RUN_KEY,
                    name=key.get("Name", key.get("name", "")),
                    path=key.get("RegistryPath", key.get("path", "")),
                    value=key.get("Value", key.get("value", "")),
                ))

        # Extract network IOCs
        network_iocs: list[NetworkIOC] = []
        connections = data.get("NetworkConnections", data.get("network_connections", []))
        if isinstance(connections, list):
            for conn in connections:
                remote_ip = conn.get("RemoteIP", conn.get("remote_ip", ""))
                if remote_ip and not remote_ip.startswith(("10.", "172.", "192.168.", "127.")):
                    network_iocs.append(NetworkIOC(
                        ioc_type=IOCType.IP,
                        value=remote_ip,
                        port=conn.get("RemotePort", conn.get("remote_port")),
                        note=f"Connection from {conn.get('Name', 'unknown')} (PID {conn.get('Pid', '?')})",
                    ))

        return IncidentArtifacts(
            incident_id=incident_id,
            ransom_note=ransom_note,
            hashes=hashes,
            persistence=persistence,
            network_iocs=network_iocs,
        )
