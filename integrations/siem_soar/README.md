# SIEM/SOAR Integration

## Overview

REST API webhook endpoint that accepts alert payloads from SIEMs and SOAR platforms, extracts ransomware artifacts, and returns intelligence enrichment.

## Supported Formats

| Platform | Auto-detect | Example Payload |
|---|---|---|
| Generic JSON | Yes | `example_payloads/generic.json` |
| Splunk | Yes | `example_payloads/splunk.json` |
| Cortex XSIAM | Yes | `example_payloads/cortex_xsiam.json` |

## Setup

### Start the webhook server

```bash
pip install -e ".[integrations]"
uvicorn integrations.siem_soar.webhook:app --host 0.0.0.0 --port 8080
```

### API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/enrich` | Enrich a structured alert payload |
| `POST` | `/api/v1/enrich/raw` | Enrich a raw SIEM payload (auto-detect format) |
| `GET` | `/api/v1/health` | Health check |

### Example: Generic Alert

```bash
curl -X POST http://localhost:8080/api/v1/enrich \
  -H "Content-Type: application/json" \
  -d @integrations/siem_soar/example_payloads/generic.json
```

### Example: Raw Splunk Alert

```bash
curl -X POST http://localhost:8080/api/v1/enrich/raw \
  -H "Content-Type: application/json" \
  -d @integrations/siem_soar/example_payloads/splunk.json
```

## SOAR Playbook Integration

### Splunk SOAR (Phantom)
Configure an HTTP action in your playbook:
- **Action**: HTTP POST
- **URL**: `http://ransomware-intel:8080/api/v1/enrich/raw`
- **Body**: `{{ container.raw_json }}`
- **Parse response** and use enrichment in downstream actions

### Cortex XSIAM / XSOAR
Configure an HTTP integration:
- **Base URL**: `http://ransomware-intel:8080`
- **Endpoint**: `/api/v1/enrich`
- Map alert fields to the generic payload schema

## Response Format

```json
{
  "incident_id": "ALERT-20260219-001",
  "primary_group": "lockbit3",
  "confidence_pct": 72.5,
  "confidence_label": "Medium",
  "brief": "# Ransomware Incident Intelligence Brief...",
  "ioc_matches": [...],
  "mitre_techniques": ["T1486", "T1490", ...]
}
```
