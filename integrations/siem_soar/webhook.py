"""SIEM/SOAR webhook endpoint for the Ransomware Intelligence Agent.

Provides a REST API that accepts alert payloads from SIEMs and SOAR
platforms, extracts artifacts, runs the agent, and returns enrichment.

Supports generic JSON format as well as specific formats for common
open-source platforms (Wazuh, Elastic/OpenSearch).

Usage:
    uvicorn integrations.siem_soar.webhook:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from mcp_server.models import (
    HashArtifact,
    IOCType,
    IncidentArtifacts,
    NetworkIOC,
    RansomNoteArtifact,
    VictimInfo,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ransomware_intel.integrations.webhook")

app = FastAPI(
    title="Ransomware Intelligence Webhook",
    description="Accepts SIEM/SOAR alert payloads and returns ransomware intelligence enrichment.",
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class AlertPayload(BaseModel):
    """Generic alert payload accepted by the webhook."""
    alert_id: str = Field(default="", description="Alert identifier from the SIEM")
    source: str = Field(
        default="generic",
        description="Alert source (wazuh, elastic, generic)",
    )
    severity: str = Field(default="", description="Alert severity level")
    description: str = Field(default="", description="Alert description")
    hostname: str = Field(default="", description="Affected hostname")
    victim_company: str = Field(default="", description="Victim organization")
    victim_sector: str = Field(default="", description="Industry sector")

    # Artifacts
    hashes: list[str] = Field(default_factory=list, description="File hashes")
    ips: list[str] = Field(default_factory=list, description="IP addresses")
    domains: list[str] = Field(default_factory=list, description="Domain names")
    ransom_note_text: str = Field(default="", description="Ransom note content")
    file_extension: str = Field(default="", description="Encrypted file extension")
    observed_ttps: list[str] = Field(default_factory=list, description="Observed TTPs")

    # Raw payload for platform-specific parsing
    raw: dict[str, Any] = Field(default_factory=dict, description="Raw alert payload")


class EnrichmentResponse(BaseModel):
    """Response from the webhook endpoint."""
    incident_id: str
    primary_group: str
    confidence_pct: float
    confidence_label: str
    brief: str
    ioc_matches: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/enrich", response_model=EnrichmentResponse)
async def enrich_alert(payload: AlertPayload) -> EnrichmentResponse:
    """Enrich a SIEM/SOAR alert with ransomware intelligence.

    Accepts a generic or platform-specific alert payload, extracts
    artifacts, runs the attribution pipeline, and returns enrichment.
    """
    logger.info("Received alert from %s: %s", payload.source, payload.alert_id)

    # Parse platform-specific formats if raw payload is provided
    if payload.raw and payload.source != "generic":
        payload = _parse_platform_payload(payload)

    # Build IncidentArtifacts
    incident_id = payload.alert_id or f"SIEM-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    artifacts = _build_artifacts(payload, incident_id)

    # Run the agent
    try:
        from mcp_server.tools.ir_brief import generate_ir_brief
        result = await generate_ir_brief(artifacts)
    except Exception as exc:
        logger.error("Agent pipeline failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc

    attribution = result["attribution"]

    return EnrichmentResponse(
        incident_id=incident_id,
        primary_group=attribution.primary_group,
        confidence_pct=attribution.confidence.confidence_pct,
        confidence_label=attribution.confidence.confidence_label,
        brief=result["brief"],
        ioc_matches=[m.model_dump() for m in attribution.matched_iocs],
        mitre_techniques=[t.technique_id for t in attribution.matched_ttps],
    )


@app.post("/api/v1/enrich/raw")
async def enrich_raw(request: Request) -> EnrichmentResponse:
    """Accept a raw JSON payload and attempt to auto-detect the format.

    Useful for direct webhook integration where the SIEM sends its
    native format without wrapping.
    """
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

    # Try to detect the format
    source = _detect_source(body)
    payload = AlertPayload(source=source, raw=body)
    payload = _parse_platform_payload(payload)

    return await enrich_alert(payload)


@app.get("/api/v1/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "ransomware-intel-webhook"}


# ---------------------------------------------------------------------------
# Platform-specific parsers
# ---------------------------------------------------------------------------

def _detect_source(body: dict[str, Any]) -> str:
    """Try to auto-detect the SIEM source from the payload structure."""
    # Wazuh alerts have a "rule" object and "agent" object
    if "rule" in body and "agent" in body:
        return "wazuh"
    # Elastic Security alerts use the ECS format with "event" and "kibana" keys
    if "event" in body and ("kibana" in body or "signal" in body or "_source" in body):
        return "elastic"
    return "generic"


def _parse_platform_payload(payload: AlertPayload) -> AlertPayload:
    """Parse platform-specific raw payload into the generic format."""
    raw = payload.raw
    if not raw:
        return payload

    if payload.source == "wazuh":
        return _parse_wazuh(payload, raw)
    elif payload.source == "elastic":
        return _parse_elastic(payload, raw)
    return payload


def _parse_wazuh(payload: AlertPayload, raw: dict[str, Any]) -> AlertPayload:
    """Parse Wazuh alert payload.

    Wazuh alerts follow a standard structure with rule, agent, and data fields.
    Reference: https://documentation.wazuh.com/current/user-manual/ruleset/rules.html
    """
    rule = raw.get("rule", {})
    agent = raw.get("agent", {})
    data = raw.get("data", {})
    syscheck = raw.get("syscheck", {})

    payload.alert_id = payload.alert_id or str(raw.get("id", ""))
    payload.severity = str(rule.get("level", ""))
    payload.description = rule.get("description", "")
    payload.hostname = agent.get("name", agent.get("ip", ""))

    # Extract hashes from syscheck (file integrity monitoring)
    for field in ["sha256_after", "sha256", "md5_after", "md5"]:
        value = syscheck.get(field, "")
        if value:
            payload.hashes.append(value)

    # Extract hashes from data fields
    for field in ["file_hash", "sha256", "md5", "hash"]:
        if data.get(field):
            payload.hashes.append(data[field])

    # Extract network IOCs from data
    for field in ["srcip", "dstip", "src_ip", "dst_ip"]:
        value = data.get(field, "")
        if value and not value.startswith(("10.", "172.", "192.168.", "127.")):
            payload.ips.append(value)

    # MITRE ATT&CK IDs from Wazuh rule metadata
    mitre = rule.get("mitre", {})
    technique_ids = mitre.get("id", [])
    if isinstance(technique_ids, list):
        payload.observed_ttps.extend(technique_ids)

    return payload


def _parse_elastic(payload: AlertPayload, raw: dict[str, Any]) -> AlertPayload:
    """Parse Elastic Security / OpenSearch alert payload.

    Supports Elastic Common Schema (ECS) format used by Elastic Security
    and OpenSearch Security Analytics.
    Reference: https://www.elastic.co/guide/en/ecs/current/index.html
    """
    # Handle both direct alert and _source wrapper
    source = raw.get("_source", raw)
    event = source.get("event", {})
    host = source.get("host", {})
    process = source.get("process", {})
    file_info = source.get("file", {})
    network = source.get("destination", {})
    signal = source.get("signal", source.get("kibana.alert", {}))
    threat = source.get("threat", {})

    payload.alert_id = payload.alert_id or source.get("_id", event.get("id", ""))
    payload.severity = str(event.get("severity", signal.get("severity", "")))
    payload.description = signal.get("rule", {}).get("name", event.get("reason", ""))
    payload.hostname = host.get("name", host.get("hostname", ""))

    # Extract file hashes (ECS file.hash.*)
    file_hash = file_info.get("hash", {})
    for algo in ["sha256", "sha1", "md5"]:
        value = file_hash.get(algo, "")
        if value:
            payload.hashes.append(value)

    # Extract process hash
    proc_hash = process.get("hash", {})
    for algo in ["sha256", "sha1", "md5"]:
        value = proc_hash.get(algo, "")
        if value:
            payload.hashes.append(value)

    # Extract network IOCs (ECS destination.ip, source.ip)
    for section in ["destination", "source"]:
        ip = source.get(section, {}).get("ip", "")
        if ip and not ip.startswith(("10.", "172.", "192.168.", "127.")):
            payload.ips.append(ip)

    domain = source.get("destination", {}).get("domain", "")
    if domain:
        payload.domains.append(domain)

    # Extract MITRE ATT&CK from threat.technique
    techniques = threat.get("technique", [])
    if isinstance(techniques, list):
        for tech in techniques:
            tid = tech.get("id", "")
            if tid:
                payload.observed_ttps.append(tid)

    return payload


def _build_artifacts(payload: AlertPayload, incident_id: str) -> IncidentArtifacts:
    """Build IncidentArtifacts from the parsed alert payload."""
    hashes = [
        HashArtifact(hash_type=IOCType.SHA256, value=h)
        for h in payload.hashes
    ]

    network_iocs = []
    for ip in payload.ips:
        network_iocs.append(NetworkIOC(ioc_type=IOCType.IP, value=ip))
    for domain in payload.domains:
        network_iocs.append(NetworkIOC(ioc_type=IOCType.DOMAIN, value=domain))

    ransom_note = None
    if payload.ransom_note_text:
        ransom_note = RansomNoteArtifact(
            filename="from_alert",
            content=payload.ransom_note_text,
        )

    return IncidentArtifacts(
        incident_id=incident_id,
        victim=VictimInfo(
            company=payload.victim_company or payload.hostname,
            sector=payload.victim_sector,
        ),
        ransom_note=ransom_note,
        hashes=hashes,
        file_extension=payload.file_extension,
        network_iocs=network_iocs,
        lolbas=payload.observed_ttps,
    )
