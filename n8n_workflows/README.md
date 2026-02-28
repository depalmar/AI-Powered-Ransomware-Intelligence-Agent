# n8n Workflows — SANS Webinar: AI-Powered Ransomware Intelligence

Three progressive n8n workflows demonstrating automated ransomware intelligence pipelines, built for the **SANS webinar "Stay Ahead of Ransomware"**.

Each workflow increases in complexity, teaching new automation concepts while building on the capabilities of the AI-Powered Ransomware Intelligence Agent.

> **Recording Safe:** All workflows automatically redact real victim names and replace them with fabricated company names. Threat group names and TTPs (public intelligence) are displayed as-is.

---

## Prerequisites

| Requirement | 101 | 201 | 300 |
|-------------|-----|-----|-----|
| [n8n](https://n8n.io/) instance (self-hosted or cloud) | Required | Required | Required |
| Network access to `https://api.ransomware.live` | Required | Required | Required |
| ransomware.live PRO API key | - | Optional | Optional |
| Ransomware Intelligence Agent running on `localhost:8080` | - | - | Required |
| Slack workspace + n8n credentials | Optional | Optional | Optional |
| SMTP credentials for email | Optional | - | Optional |

---

## Quick Start

1. **Import** — In n8n, go to **Workflows > Import from File** and select a JSON file
2. **Configure** — Set up any credentials (Slack, email) in **Settings > Credentials**
3. **Test** — Click **Manual Trigger** (101) or send a curl request (201, 300)

---

## Workflow Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  101 - Threat Monitor          Simple polling + notifications   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Schedule  │→│ Fetch    │→│ Filter   │→│ Notify   │       │
│  │ Trigger   │  │ Victims  │  │ & Enrich │  │ (Slack)  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                 │
│  201 - IOC Enrichment          Webhook + MITRE + YARA          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Webhook  │→│ Classify │→│ Enrich   │→│ Report + │       │
│  │ (IOCs)   │  │ IOCs     │  │ + MITRE  │  │ Respond  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                 │
│  300 - Full IR Pipeline        Agent + Parallel + Escalation   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Webhook  │→│ AI Agent │→│ Parallel │→│ Confidence│       │
│  │(Incident)│  │ Attrib.  │  │ Enrich   │  │ Routing  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 101 — Ransomware Group Threat Monitor

**File:** `101_ransomware_threat_monitor.json`
**Difficulty:** Beginner | **Nodes:** ~12 | **API:** Free (no key required)

### What It Does

Scheduled workflow that monitors ransomware activity targeting your sectors of interest. Every 6 hours (or on-demand), it fetches recent victim postings, filters by sector, fetches group profiles, and sends a formatted threat brief.

### Learning Concepts

- Schedule triggers for automated polling
- HTTP Request nodes for REST API calls
- Code nodes for JavaScript data transformation
- IF conditions for flow control
- Notification patterns (Slack / email)

### Customization

Edit the `targetSectors` array in the **"Filter by Sector"** node to match your industry:

```javascript
const targetSectors = [
  'manufacturing', 'healthcare', 'finance',
  'technology', 'energy', 'government'
];
```

### Demo Steps

1. Click **Manual Trigger** to run immediately
2. Watch data flow through each node
3. Review the formatted threat summary in the **Format Threat Summary** node
4. (Optional) Enable the Slack node and configure credentials

---

## 201 — IOC Enrichment & MITRE Mapping Pipeline

**File:** `201_ioc_enrichment_pipeline.json`
**Difficulty:** Intermediate | **Nodes:** ~18 | **API:** Free + PRO (optional)

### What It Does

Webhook-triggered pipeline that receives IOCs from an analyst or SIEM, classifies them by type, searches ransomware.live for matches, maps observations to MITRE ATT&CK techniques, fetches YARA rules, and returns a structured enrichment report.

### Learning Concepts

- Webhook triggers (SIEM-to-n8n pattern)
- IOC classification with regex
- Batch API enrichment with rate limiting
- MITRE ATT&CK observation-to-technique mapping
- Conditional escalation (critical group detection)
- Structured webhook responses

### Test It

```bash
curl -X POST http://localhost:5678/webhook/ioc-enrich \
  -H "Content-Type: application/json" \
  -d '{
    "hashes": [
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "f4d2c8a1b3e5d7f9a0c2e4b6d8f0a1c3e5b7d9f1a3c5e7b9d0f2a4c6e8b0d2"
    ],
    "ips": ["185.220.101.42", "91.243.44.178"],
    "domains": [],
    "observed_ttps": [
      "RDP lateral movement",
      "vssadmin shadow copy deletion",
      "schtasks persistence",
      "cobalt strike beacon"
    ]
  }'
```

### MITRE Mapping

The workflow includes a full JavaScript implementation of the observation-to-MITRE mapping from the agent's `ttp_correlation.py`, covering 30+ observation keywords mapped to MITRE ATT&CK technique IDs, plus TTP-based group correlation against 10 major ransomware families.

---

## 300 — Full Incident Response Intelligence Pipeline

**File:** `300_full_ir_pipeline.json`
**Difficulty:** Advanced | **Nodes:** ~30 | **API:** Agent + Free + PRO

### What It Does

Comprehensive workflow replicating the full AI-powered attribution pipeline:

1. **Receives** full incident artifacts via webhook (ransom notes, hashes, IPs, TTPs)
2. **Calls** the Ransomware Intelligence Agent for confidence-scored attribution
3. **Enriches** in parallel: group profile, YARA rules, sector context, SEC 8-K filings
4. **Generates** a full Markdown IR brief matching the `ir_brief.md.j2` template
5. **Routes** by confidence level (High >= 80%, Medium >= 60%, Low < 60%)
6. **Notifies** via Slack, email, and SIEM webhook based on escalation level

### Learning Concepts

- Complex orchestration (30+ nodes)
- Calling external AI agents (agent-as-a-service)
- Parallel execution branches
- Switch-based confidence routing
- Multi-channel notification strategy
- Graceful degradation (fallback when agent unavailable)
- Markdown report generation

### Prerequisites

Start the ransomware intelligence agent:

```bash
uvicorn integrations.siem_soar.webhook:app --host 0.0.0.0 --port 8080
```

### Test with Demo Scenario

```bash
curl -X POST http://localhost:5678/webhook/ir-pipeline \
  -H "Content-Type: application/json" \
  -d @demo/scenario.json
```

### Confidence-Based Escalation

| Confidence | Level | Actions | SLA |
|-----------|-------|---------|-----|
| >= 80% (High) | CRITICAL | Slack `#incident-response` @here + Email IR team + SIEM | 1 hour |
| 60-79% (Medium) | HIGH | Slack `#soc-queue` + SIEM | 4 hours |
| < 60% (Low) | MEDIUM | SIEM log only | 24 hours |

These thresholds match the 4-signal weighted scoring model:
- Ransom Note Match: 35%
- IOC Overlap: 30%
- TTP Alignment: 20%
- File Extension: 15%

---

## API Endpoints Used

| Endpoint | Free/PRO | Workflows |
|----------|----------|-----------|
| `GET /v2/recentvictims` | Free | 101, 300 |
| `GET /v2/groups/{name}` | Free | 101, 201, 300 |
| `GET /v2/searchvictims/{keyword}` | Free | 201 |
| `GET /v2/sectorvictims/{sector}` | Free | 300 |
| `GET /v2/yara/{group}` | Free | 201, 300 |
| `GET /v2/8k` | PRO | 300 |
| `POST localhost:8080/api/v1/enrich` | Agent | 300 |

---

## Configuration

### Slack (Optional)

1. In n8n: **Settings > Credentials > Add Credential > Slack OAuth2**
2. Create a Slack app at [api.slack.com/apps](https://api.slack.com/apps)
3. Add `chat:write` scope
4. Install to your workspace
5. Enable the disabled Slack nodes in the workflow

### Email (Optional)

1. In n8n: **Settings > Credentials > Add Credential > SMTP**
2. Configure your SMTP server details
3. Enable the disabled Email node in the 300 workflow

### ransomware.live PRO API (Optional)

If you have a PRO key, add it as an HTTP Header credential:
- Header Name: `api-key`
- Header Value: Your PRO API key

This enables IOC database lookups, TTP profiles, negotiation data, and SEC 8-K filings.

---

## Webinar Demo Flow

### Recommended presentation order:

1. **Start with 101** — Show how easy it is to poll an API and build alerts
2. **Walk through 201** — Send live IOCs via curl, show MITRE mapping in real-time
3. **Finish with 300** — Send the demo scenario, show the full IR brief and confidence routing

### Talking points per workflow:

| Workflow | Key Takeaway |
|----------|-------------|
| 101 | "You can build a threat monitor in 10 minutes with n8n" |
| 201 | "Automate what your analysts do manually — classify, enrich, map to MITRE" |
| 300 | "Connect your AI agent as a service and build a full IR pipeline with confidence-based escalation" |

---

## Repository

These workflows are part of the [AI-Powered Ransomware Intelligence Agent](https://github.com/depalmar/AI-Powered-Ransomware-Intelligence-Agent) — a defensive security system for rapid ransomware incident response and threat attribution.
