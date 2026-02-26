# Ransomware.live API Reference

Summary of the ransomware.live API endpoints used by this agent.

**Base URL:** `https://api.ransomware.live`

## Free API (v2) — No Key Required

| Endpoint | Method | Description |
|---|---|---|
| `/api/groups` | GET | List all known ransomware groups |
| `/api/group/{name}` | GET | Get profile for a specific group |
| `/api/searchvictims/{keyword}` | GET | Search victims by keyword |
| `/api/sectorvictims/{sector}` | GET | Get victims by industry sector |
| `/api/victims/{year}/{month}` | GET | Get victims for a specific month |
| `/api/recentvictims` | GET | Get most recent victims |
| `/api/yara/{group}` | GET | Get YARA rules for a group |

## PRO API — Key Required

| Endpoint | Method | Description |
|---|---|---|
| `/api/ransomnotestext` | GET | Get all known ransom note texts |
| `/api/ransomnotestext/{group}` | GET | Get ransom note text for a group |
| `/api/iocs/{group}` | GET | Get IOCs for a group |
| `/api/ttps/{group}` | GET | Get MITRE ATT&CK TTPs for a group |
| `/api/negotiations/{group}` | GET | Get negotiation transcripts |
| `/api/8k` | GET | Get all SEC 8-K filings |
| `/api/8k/ticker/{ticker}` | GET | Filter 8-K by stock ticker |
| `/api/8k/cik/{cik}` | GET | Filter 8-K by CIK number |

## Authentication

PRO API endpoints require an API key sent via the `api-key` header:

```
api-key: your_pro_api_key_here
```

## Rate Limiting

The agent implements client-side rate limiting (default: 2 requests/second) with exponential backoff on failures. The API itself may have additional rate limits.

## Data Format

All endpoints return JSON. Response structures vary by endpoint — the agent's Pydantic models handle parsing and normalization.

## Getting a PRO API Key

Visit [ransomware.live](https://www.ransomware.live/) for information about PRO API access.
