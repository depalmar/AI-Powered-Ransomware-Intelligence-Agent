# SIEM/SOAR Integration

## Overview

REST API webhook endpoint that accepts alert payloads from open-source SIEMs and SOAR platforms, extracts ransomware artifacts, and returns intelligence enrichment.

## Supported Formats

| Platform | Auto-detect | Example Payload |
|---|---|---|
| Generic JSON | Yes | `example_payloads/generic.json` |
| Wazuh | Yes | `example_payloads/wazuh.json` |
| Elastic / OpenSearch | Yes | `example_payloads/elastic.json` |

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

### Example: Wazuh Alert

```bash
curl -X POST http://localhost:8080/api/v1/enrich/raw \
  -H "Content-Type: application/json" \
  -d @integrations/siem_soar/example_payloads/wazuh.json
```

### Example: Elastic / OpenSearch Alert

```bash
curl -X POST http://localhost:8080/api/v1/enrich/raw \
  -H "Content-Type: application/json" \
  -d @integrations/siem_soar/example_payloads/elastic.json
```

## SOAR Playbook Integration

### Shuffle (Open-Source SOAR)
Configure an HTTP action in your Shuffle workflow:
- **Action**: HTTP POST
- **URL**: `http://ransomware-intel:8080/api/v1/enrich/raw`
- **Body**: Pass the raw alert JSON from the trigger
- **Parse response** and use enrichment in downstream actions

### TheHive / Cortex Analyzers
Configure as a Cortex responder or analyzer:
- **Base URL**: `http://ransomware-intel:8080`
- **Endpoint**: `/api/v1/enrich`
- Map TheHive observable fields to the generic payload schema

### Wazuh Active Response
Configure a custom active response script that POSTs high-severity alerts:
- Trigger on rule levels >= 12 (ransomware rules)
- POST to `http://ransomware-intel:8080/api/v1/enrich/raw`
- Log the enrichment response for analyst review

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
