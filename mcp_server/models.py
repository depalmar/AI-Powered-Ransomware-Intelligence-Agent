"""Pydantic models for all data structures in the ransomware intelligence agent.

Covers: forensic artifacts, API responses, confidence scoring, and report output.
Every piece of data flowing through the system has a typed schema here.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IOCType(str, Enum):
    """Types of Indicators of Compromise."""
    IP = "ip"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    URL = "url"


class LateralMovementMethod(str, Enum):
    """Known lateral movement methods."""
    RDP = "RDP"
    PSEXEC = "PsExec"
    WMI = "WMI"
    WMIC = "WMIC"
    SMB = "SMB"
    SSH = "SSH"
    DCOM = "DCOM"
    WINRM = "WinRM"
    OTHER = "Other"


class PersistenceType(str, Enum):
    """Known persistence mechanism types."""
    SCHEDULED_TASK = "scheduled_task"
    REGISTRY_RUN_KEY = "registry_run_key"
    SERVICE = "service"
    STARTUP_FOLDER = "startup_folder"
    WMI_SUBSCRIPTION = "wmi_subscription"
    OTHER = "other"


# ---------------------------------------------------------------------------
# Forensic Artifact Models (input data from incidents)
# ---------------------------------------------------------------------------

class RansomNoteArtifact(BaseModel):
    """A ransom note found on a compromised system."""
    filename: str = Field(description="Name of the ransom note file")
    content: str = Field(description="Full text content of the ransom note")


class HashArtifact(BaseModel):
    """A file hash collected from a compromised system."""
    hash_type: IOCType = Field(description="Hash algorithm (md5, sha1, sha256)")
    value: str = Field(description="The hash value")
    filename: str = Field(default="", description="Original filename if known")
    note: str = Field(default="", description="Analyst notes about this file")


class NetworkIOC(BaseModel):
    """A network indicator of compromise."""
    ioc_type: IOCType = Field(description="Type: ip, domain, or url")
    value: str = Field(description="The indicator value")
    port: int | None = Field(default=None, description="Port number if applicable")
    note: str = Field(default="", description="Context about this indicator")


class PersistenceMechanism(BaseModel):
    """A persistence mechanism found on a compromised system."""
    persistence_type: PersistenceType = Field(description="Type of persistence")
    name: str = Field(default="", description="Name/identifier")
    command: str = Field(default="", description="Command or path")
    path: str = Field(default="", description="Registry path or file path")
    value: str = Field(default="", description="Registry value or argument")


class LateralMovement(BaseModel):
    """An observed lateral movement event."""
    method: LateralMovementMethod
    source: str = Field(description="Source hostname")
    destination: str = Field(description="Destination hostname")
    timestamp: datetime | None = None


class VictimInfo(BaseModel):
    """Information about the victim organization."""
    company: str = ""
    sector: str = ""
    size: str = ""
    geography: str = ""


class IncidentArtifacts(BaseModel):
    """All forensic artifacts collected from an incident.

    This is the primary input to the attribution pipeline.
    """
    incident_id: str = Field(description="Unique incident identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    victim: VictimInfo = Field(default_factory=VictimInfo)
    ransom_note: RansomNoteArtifact | None = None
    hashes: list[HashArtifact] = Field(default_factory=list)
    file_extension: str = Field(default="", description="Encrypted file extension")
    network_iocs: list[NetworkIOC] = Field(default_factory=list)
    persistence: list[PersistenceMechanism] = Field(default_factory=list)
    lateral_movement: list[LateralMovement] = Field(default_factory=list)
    lolbas: list[str] = Field(
        default_factory=list,
        description="Living-off-the-land binaries observed",
    )


# ---------------------------------------------------------------------------
# API Response Models (data from ransomware.live)
# ---------------------------------------------------------------------------

class GroupProfile(BaseModel):
    """Ransomware group profile from the API."""
    name: str
    description: str = ""
    url: str = ""
    first_seen: str = ""
    last_seen: str = ""
    locations: list[Any] = Field(default_factory=list)
    profiles: list[dict[str, Any]] = Field(default_factory=list)
    meta: str | None = None


class GroupTTP(BaseModel):
    """A single TTP mapped to a ransomware group."""
    tactic: str = Field(description="MITRE ATT&CK tactic")
    technique_id: str = Field(description="MITRE technique ID (e.g. T1486)")
    technique_name: str = Field(description="Human-readable technique name")
    description: str = ""


class GroupYaraRule(BaseModel):
    """A YARA rule associated with a ransomware group."""
    rule_name: str = ""
    rule_content: str = Field(description="Full YARA rule text")
    source: str = ""


class VictimRecord(BaseModel):
    """A victim record from ransomware.live."""
    group: str = ""
    victim: str = ""
    country: str = ""
    sector: str = ""
    published: str = ""
    url: str = ""
    description: str = ""


class NegotiationEntry(BaseModel):
    """A negotiation transcript entry."""
    group: str = ""
    title: str = ""
    content: str = ""
    url: str = ""


class IOCRecord(BaseModel):
    """An IOC record from the PRO API."""
    group: str = ""
    ioc_type: str = ""
    value: str = ""
    source: str = ""
    date_added: str = ""


class SECFiling(BaseModel):
    """An SEC 8-K cybersecurity incident filing."""
    company: str = ""
    ticker: str = ""
    cik: str = ""
    filed: str = ""
    url: str = ""
    description: str = ""


# ---------------------------------------------------------------------------
# Confidence Scoring Models
# ---------------------------------------------------------------------------

class SignalScore(BaseModel):
    """A single signal's contribution to attribution confidence."""
    signal_name: str = Field(description="Name of the signal (e.g. 'ransom_note')")
    raw_score: float = Field(description="Raw score from 0.0 to 1.0")
    weight: float = Field(description="Weight in the composite score")
    weighted_score: float = Field(description="raw_score * weight")
    detail: str = Field(default="", description="Human-readable explanation")


class ConfidenceResult(BaseModel):
    """Composite confidence score for group attribution."""
    group_name: str
    total_score: float = Field(description="Weighted composite score 0.0-1.0")
    confidence_pct: float = Field(description="Score as a percentage 0-100")
    confidence_label: str = Field(
        description="Human label: High, Medium, Low, Insufficient"
    )
    signals: list[SignalScore] = Field(default_factory=list)

    @staticmethod
    def label_from_score(score: float) -> str:
        """Convert a 0-1 score to a human-readable confidence label."""
        if score >= 0.80:
            return "High"
        if score >= 0.60:
            return "Medium"
        if score >= 0.40:
            return "Low"
        return "Insufficient"


# ---------------------------------------------------------------------------
# Ransom Note Match Models
# ---------------------------------------------------------------------------

class RansomNoteMatch(BaseModel):
    """A candidate ransom note match from embedding similarity."""
    group_name: str
    similarity_score: float = Field(description="Cosine similarity 0.0-1.0")
    matched_note_preview: str = Field(
        default="", description="First 200 chars of the matched note"
    )
    match_method: str = Field(
        default="embedding", description="'embedding' or 'keyword'"
    )


# ---------------------------------------------------------------------------
# Report Output Models
# ---------------------------------------------------------------------------

class AttributionResult(BaseModel):
    """Full attribution result combining all signals."""
    primary_group: str
    confidence: ConfidenceResult
    alternative_groups: list[ConfidenceResult] = Field(default_factory=list)
    ransom_note_matches: list[RansomNoteMatch] = Field(default_factory=list)
    matched_iocs: list[IOCRecord] = Field(default_factory=list)
    matched_ttps: list[GroupTTP] = Field(default_factory=list)
    group_profile: GroupProfile | None = None


class NegotiationAdvisory(BaseModel):
    """Negotiation intelligence summary."""
    typical_demand_range: str = ""
    avg_discount_pct: float = 0.0
    response_window: str = ""
    decryptor_reliability: str = ""
    reliability_detail: str = ""
    recommendation: str = ""


class IRBriefData(BaseModel):
    """All data needed to render the IR brief template."""
    incident_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    artifacts: IncidentArtifacts
    attribution: AttributionResult
    negotiation: NegotiationAdvisory | None = None
    yara_rules: list[GroupYaraRule] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    executive_summary: str = ""


class ThreatLandscapeEntry(BaseModel):
    """A single entry in a threat landscape assessment."""
    group_name: str
    risk_level: str = ""
    recent_victim_count: int = 0
    primary_sectors: list[str] = Field(default_factory=list)
    recent_iocs: list[str] = Field(default_factory=list)
    summary: str = ""


class ThreatLandscapeReport(BaseModel):
    """Proactive threat landscape assessment output."""
    sector: str
    geography: str = ""
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    threat_actors: list[ThreatLandscapeEntry] = Field(default_factory=list)
    summary: str = ""
