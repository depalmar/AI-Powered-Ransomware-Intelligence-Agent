# n8n Ransomware Intelligence Workflows

Three-tier workflow progression from beginner automation to enterprise attribution platform.

## Workflow Progression

| Level | File | LLM | Complexity | Visibility |
|-------|------|-----|-----------|------------|
| **101** | `101_ransomware_threat_monitor.json` | Claude | Beginner | ✅ Public |
| **101 (Ollama)** | `101_ransomware_threat_monitor_ollama.json` | Ollama / Local | Beginner | ✅ Public |
| **200** | `200_ransomware_intel_advanced.json` | Claude | Intermediate | ✅ Public |
| **200 (Ollama)** | `200_ransomware_intel_advanced_ollama.json` | Ollama / Local | Intermediate | ✅ Public |
| **300** | `300_ransomware_attribution_platform.json` | Claude Opus | Advanced | 🔒 Private Repo |

> **Level 300** is available in a separate private repository for webinar attendees. See the webinar details for access instructions.

---

## 101 — Ransomware Threat Monitor (Beginner)

**What it does:** Polls ransomware.live every 6 hours, filters by industry, runs AI threat analysis, and generates a rich HTML + Slack report.

**You'll learn:**
- Connecting to the ransomware.live API
- Filtering and enriching data with Code nodes
- Using Claude or Ollama for structured threat analysis
- Generating styled HTML reports from n8n

**Required credentials:**
- Anthropic API key (Claude version) _or_ Ollama running locally (Ollama version)
- Slack webhook URL
- Google Docs OAuth (optional)

**Outputs:**
- 🛡️ Dark-themed HTML threat brief with 8 KPI cards, 5+ Chart.js charts, MITRE ATT&CK table, attack lifecycle, group profiles
- 💬 Slack alert with threat summary
- 📄 Google Doc (optional)

### Claude vs Ollama

Two variants are provided:

| Feature | Claude (101) | Ollama (101) |
|---------|-------------|--------------|
| LLM | Anthropic Claude Opus | llama3.1 / mistral / gemma2 |
| Cost | API credits | Free (local) |
| Quality | Higher, more consistent | Good, varies by model |
| Privacy | Data sent to Anthropic | Fully local |
| JSON reliability | Excellent | Good (strict schema mode) |

**Switching between them:** Replace the `Claude Model` / `Ollama Model` node with your preferred provider. The rest of the workflow is identical.

**Recommended Ollama models (JSON schema support):**
- `llama3.1` (default, recommended)
- `mistral`
- `gemma2`
- `qwen2.5`

---

## 200 — Advanced Intelligence Platform (Intermediate)

> **🔒 Available to webinar attendees. Contact for access.**

**Adds vs 101:**
- 🔍 **IOC Enrichment** — VirusTotal + AbuseIPDB lookups on observed domains/IPs
- 🛡️ **YARA Rule Generation** — AI-generated detection rules per threat group
- 📈 **Historical Trending** — Compares current 30-day window vs prior baseline
- 📧 **Multi-Channel Delivery** — Slack + Email + JIRA ticketing + Google Docs
- 🎯 **Confidence Scoring** — Multi-signal 0-100% attribution confidence
- 💰 **Negotiation Intelligence** — Demand ranges and decryptor reliability data

**Additional prerequisites:**
- VirusTotal API key (free tier: 500 req/day)
- AbuseIPDB API key (free tier available)
- SMTP or SendGrid for email delivery
- JIRA credentials (optional)

---

## 300 — Attribution Platform (Advanced)

> **🔒 Available to webinar attendees. Contact for access.**

**Adds vs 200:**
- 🧬 **Multi-Signal Attribution Engine** — Ransom note similarity + IOC overlap + TTP alignment + file extension fingerprinting
- 📚 **Threat Actor Profiling DB** — Evolving actor profiles stored in Airtable
- 🔭 **SIEM Integration** — CEF/JSON events pushed to Splunk / Elastic / Microsoft Sentinel
- 🎯 **Active Threat Hunting** — Generates Splunk SPL + KQL hunting queries
- 📋 **IR Playbook Generation** — Actor-specific incident response playbook
- 📊 **Executive Dashboard** — Auto-updates Google Sheets KPI dashboard
- 📡 **STIX/TAXII Export** — STIX 2.1 bundles for MISP/OpenCTI sharing

**Additional prerequisites:**
- SIEM API credentials (Splunk/Elastic/Sentinel)
- Airtable or Notion API for actor profiling
- Optional: MISP/OpenCTI for threat sharing

---

## Quick Start (101)

1. Import `101_ransomware_threat_monitor.json` into your n8n instance
2. Set up credentials (Anthropic API key + Slack webhook)
3. Configure the `Filter by Industry` node with your target sectors
4. Activate the workflow
5. Trigger manually to test, then let the schedule run

## Quick Start (101 Ollama)

1. Install and start Ollama: `ollama serve`
2. Pull a compatible model: `ollama pull llama3.1`
3. Import `101_ransomware_threat_monitor_ollama.json`
4. Set up Slack webhook credential
5. The Ollama node connects to `http://localhost:11434` by default

---

*Part of the [AI-Powered Ransomware Intelligence Agent](https://github.com/depalmar/AI-Powered-Ransomware-Intelligence-Agent) project*
