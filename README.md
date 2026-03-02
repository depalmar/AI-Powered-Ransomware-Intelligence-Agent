# Ransomware Group Threat Monitor (n8n Workflow)

A beginner-friendly n8n workflow that automatically monitors ransomware group activity targeting your sectors of interest. Uses the free [ransomware.live](https://www.ransomware.live/) API — no API key required.

Built for the SANS podcast demo *"Stay Ahead of Ransomware"* with Ryan Chapman.

## What It Does

Every 6 hours (or on-demand via manual trigger), the workflow:

1. Fetches recent ransomware victim postings from ransomware.live
2. Filters victims by your sectors of interest (manufacturing, healthcare, finance, etc.)
3. Fetches group profiles for context (victim count, description)
4. Formats a Markdown threat summary
5. (Optional) Sends the summary to Slack or email

## Quick Start

### Prerequisites

- [n8n](https://n8n.io/) instance (self-hosted or cloud)
- Network access to `https://api.ransomware.live`
- (Optional) Slack workspace + n8n credentials for notifications

### Setup

1. **Import** — In n8n, go to **Workflows > Import from File** and select `n8n_workflows/101_ransomware_threat_monitor.json`
2. **Configure sectors** — Edit the `targetSectors` array in the **"Filter by Industry"** node:
   ```javascript
   const targetSectors = [
     'manufacturing', 'healthcare', 'finance',
     'technology', 'energy', 'government'
   ];
   ```
3. **Test** — Click **Manual Trigger** to run immediately
4. (Optional) **Enable Slack** — Configure Slack credentials in n8n and enable the Slack node

## Workflow Nodes

```
Schedule Trigger (every 6h)
  → Fetch Recent Victims (ransomware.live API)
    → Filter by Industry (JavaScript)
      → Groups Found? (IF: victim_count >= 1)
        → True: Get Group Profile → Format Threat Summary → Notify
        → False: No Activity Detected
```

## Learning Concepts

This workflow teaches:

- Schedule triggers for automated polling
- HTTP Request nodes for REST API calls
- Code nodes for JavaScript data transformation
- IF conditions for flow control
- Notification patterns (Slack / email)

## API Endpoint

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /v2/recentvictims` | Free (no key) | Recent ransomware victim postings |
| `GET /v2/groups/{name}` | Free (no key) | Group profile with victim count |

## Full Platform

For the complete ransomware intelligence platform — including MCP server, LangGraph agent, SIEM/SOAR integrations, and advanced n8n workflows (201 IOC enrichment, 300 full IR pipeline) — see:

**[AI-Powered-Ransomware-Intelligence-Platform](https://github.com/depalmar/AI-Powered-Ransomware-Intelligence-Platform)**

## License

MIT

## Disclaimer

This tool is for **defensive security operations and educational purposes only**. All demo data is fabricated. Victim names are automatically redacted in workflow output.
