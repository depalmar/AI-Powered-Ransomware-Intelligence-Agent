"""SIEM/SOAR webhook endpoint for the Ransomware Intelligence Agent.

Provides a REST API that accepts alert payloads from SIEMs and SOAR
platforms, extracts artifacts, runs the agent, and returns enrichment.

Supports generic JSON format as well as specific formats for common
platforms (Splunk, Cortex XSIAM).

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
    source: str = Field(default="generic", description="Alert source (splunk, cortex, generic)")
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
    if "result" in body and "search_name" in body:
        return "splunk"
    if "alert_id" in body and "alert_source" in body:
        return "cortex"
    return "generic"


def _parse_platform_payload(payload: AlertPayload) -> AlertPayload:
    """Parse platform-specific raw payload into the generic format."""
    raw = payload.raw
    if not raw:
        return payload

    if payload.source == "splunk":
        return _parse_splunk(payload, raw)
    elif payload.source == "cortex":
        return _parse_cortex(payload, raw)
    return payload


def _parse_splunk(payload: AlertPayload, raw: dict[str, Any]) -> AlertPayload:
    """Parse Splunk alert payload."""
    result = raw.get("result", {})
    payload.alert_id = payload.alert_id or raw.get("sid", "")
    payload.description = raw.get("search_name", "")
    payload.hostname = result.get("host", result.get("src_host", ""))

    # Extract IOCs from Splunk fields
    for field in ["file_hash", "sha256", "md5", "hash"]:
        if result.get(field):
            payload.hashes.append(result[field])

    for field in ["src_ip", "dest_ip", "remote_ip"]:
        if result.get(field):
            payload.ips.append(result[field])

    for field in ["domain", "dest_host", "url_domain"]:
        if result.get(field):
            payload.domains.append(result[field])

    return payload


def _parse_cortex(payload: AlertPayload, raw: dict[str, Any]) -> AlertPayload:
    """Parse Cortex XSIAM alert payload."""
    payload.alert_id = payload.alert_id or raw.get("alert_id", "")
    payload.severity = raw.get("severity", "")
    payload.description = raw.get("alert_name", raw.get("description", ""))
    payload.hostname = raw.get("hostname", raw.get("host_name", ""))

    # Extract IOCs
    artifacts = raw.get("artifacts", [])
    for artifact in artifacts:
        art_type = artifact.get("type", "")
        value = artifact.get("value", "")
        if art_type in ("hash", "sha256", "md5"):
            payload.hashes.append(value)
        elif art_type in ("ip", "ip_address"):
            payload.ips.append(value)
        elif art_type == "domain":
            payload.domains.append(value)

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
