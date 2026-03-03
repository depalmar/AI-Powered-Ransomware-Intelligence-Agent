# Building an AI-Powered Ransomware Intelligence Agent
## SANS Stay Ahead of Ransomware — March 3, 2026
### Raymond DePalma

---

# The Problem: Intelligence at 2 AM

## The analyst's reality during a ransomware incident

- 6+ browser tabs: VirusTotal, MITRE ATT&CK, vendor blogs, ransom note databases
- Manual copy-paste into report templates
- 2–4 hours for basic attribution (experienced analyst)
- Night shift with less experience? Half a day
- The data exists — it's just not connected

> "We're not asking AI to do the forensics. We're asking it to do the library research while we focus on the crime scene."

---

# The Data Source: ransomware.live

## Community-powered ransomware intelligence — free, no auth required

### What it is
- Created by Julien Mousqueton
- Aggregates data from leak sites, CERT advisories, press, and enrichment sources
- 275+ tracked ransomware groups, thousands of victims
- Free API: group profiles, victim lists, YARA rules, sector targeting, temporal trends

### Key API endpoints used in our agent
- `GET /v2/recentvictims` — Latest postings from ransomware leak sites
- `GET /v2/groups/{name}` — Detailed threat actor profiles and intelligence

### Free vs. PRO
- Free: Everything we demo today — group profiles, victim data, keyword search, YARA rules
- PRO: Negotiation transcripts, IOCs, ransom notes, extended TTPs, 8-K filings

> "Reading a threat actor's negotiation history is like reading their Yelp reviews."

---

# Architecture: The 8-Step Pipeline

## How data flows from ransomware.live to a finished intelligence brief

### All orchestrated in n8n — visual, no-code automation

1. **Trigger** — Every 6 hours (or manual click for demo)
2. **Fetch** — Pull recent victims from ransomware.live API
3. **Redact** — Immediately replace real victim names with realistic fakes. Recording-safe from this point forward.
4. **Filter** — Drop victims outside target industries (configurable)
5. **Deduplicate** — Group victims by threat actor
6. **Enrich** — Fetch detailed group profiles for each active actor
7. **Analyze (AI)** — Claude extracts structured TTPs, targeting patterns, and recommendations via JSON output parser
8. **Distribute** — Generate four outputs: Markdown, HTML, Slack, and Google Doc

> "The barrier to entry isn't AI expertise. It's DFIR expertise."

---

# How the AI Stays Honest

## Structured output parsing prevents hallucination

### Schema-constrained JSON output
- `threat_level` — CRITICAL / HIGH / MEDIUM / LOW
- `ttps[]` — Array of {tactic, technique, description} mapped to MITRE ATT&CK
- `targeting_patterns` — Industries, regions, victim profile
- `operational_intelligence` — Narrative analysis
- `recommendations[]` — Prioritized defensive actions

### The AI writes the first draft. The human approves it.
- Claude receives actual data — victim records, group profiles, distributions
- Cannot drift into freeform hallucination because the schema constrains output
- Every TTP attribution includes the evidence from the data

---

# Demo-Safe by Design

## Real victim names never appear — anywhere

### The redaction system
- `Generate Diverse Fake Companies` node runs immediately after API fetch
- Randomized prefix/suffix combinations create unique fake names
  - "Meridian Industrial Solutions", "Cobalt Dynamics Corp", "Zenith Financial Group"
- Industries, countries, and discovery dates are also randomized
- Real names never reach the AI, the report, or the execution logs
- 100% safe for live demos, recordings, and webinars

### Mock API for guaranteed results
- Local Python server mimics ransomware.live endpoints
- Returns 24 victims across 3 groups: LockBit 3.0, Play, BlackBasta
- Zero dependency on live internet during demo
- `python mock_api/server.py` or double-click `run_demo.bat`

---

# Live Demo

## Running the full pipeline — from API call to intelligence brief

### What we're running
- n8n workflow against local mock API server
- 24 victims → 3 threat groups → Claude analysis → 4 output formats
- Same endpoints and data format as live ransomware.live

### Demo steps
1. Start mock API server
2. Import DEMO workflow into n8n
3. Click Execute Workflow
4. Walk through the four outputs

---

# Output 1: Markdown Report

## Full intelligence brief with Mermaid diagrams

### What's in the report
- Executive Dashboard with trend deltas (current vs. prior period)
- AI-generated MITRE ATT&CK mindmap
- TTP detail table with severity ratings (Critical / High)
- Pie charts for geographic and industry distribution
- Gantt timeline showing attack cadence per group
- Attack lifecycle flowchart (Initial Access → Impact)
- Weighted risk matrix — composite score 7.95/10
- Threat group profiles with per-group industry breakdowns
- Collapsible victim appendix

### Optimized for
- Internal wikis, Confluence, GitHub
- Cursor / VS Code markdown preview with dark theme

---

# Output 2: HTML Report

## Self-contained — open in any browser, no server needed

### Interactive Chart.js visualizations
- Doughnut charts for geographic and industry distribution
- Stacked bar chart for daily attack volume over 30 days
- Per-group doughnut charts for industry breakdown
- Radar chart for the weighted risk matrix
- Dark theme with responsive layout

### Designed for
- CISO briefings — just open the file
- Email attachments
- Print-friendly via CSS media queries

---

# Output 3: Slack Alert

## Condensed summary for immediate awareness

### What it includes
- Threat level with composite risk score
- MITRE TTP IDs (T1190, T1059, T1567, T1486)
- Threat scores per group
- Top targeted industries with percentages and trends
- Prioritized P1/P2 defensive actions

### Designed for
- 2 AM incident commander
- SOC channel awareness
- Quick triage decision-making

---

# The AI Section: MITRE ATT&CK Mapping

## Claude generates structured threat intelligence automatically

### What the AI produced
- 4 TTP clusters mapped to MITRE ATT&CK IDs
  - T1190 — Exploit Public-Facing Application (Citrix Bleed) — Critical
  - T1059 — Command & Scripting Interpreter (PowerShell LotL) — High
  - T1567 — Exfiltration Over Web Service (Rclone, StealBit) — High
  - T1486 — Data Encrypted for Impact (double extortion) — Critical
- Targeting analysis: Healthcare, Manufacturing, Financial Services
- Operational intelligence narrative
- 4 prioritized defensive recommendations with effort estimates

### Rendered as
- Mermaid mindmap in Markdown
- Severity-rated table with P1/P2 priority actions
- Radar chart in HTML

---

# Risk Matrix: One Number for Leadership

## Six weighted factors → composite risk rating

| Factor | Score | Weight |
|--------|:-----:|:------:|
| Attack Frequency | 7 | 20% |
| Industry Criticality | 9 | 25% |
| Geographic Spread | 6 | 10% |
| Actor Sophistication | 8 | 20% |
| Time-to-Encrypt | 8 | 15% |
| Double Extortion | 9 | 10% |

### Composite Risk: HIGH — 7.95 / 10

- Healthcare drives the criticality score up
- Time-to-encrypt compressed from ~72 hrs to < 48 hrs
- 100% of observed incidents used double extortion

---

# Threat Group Spotlight

## Three active groups in this reporting period

### LockBit 3.0 — Threat Score: 9.2/10
- 11 victims (46% of total) across 5 countries
- Most prolific ransomware variant globally
- Affiliate-driven RaaS model
- Known TTPs: Citrix Bleed (CVE-2023-4966), StealBit, ESXi encryptors

### Play — Threat Score: 7.8/10
- 8 victims (33%) — sharp pivot to healthcare (+75%)
- Exploits ProxyNotShell, unpatched remote access
- Semi-closed RaaS model

### BlackBasta — Threat Score: 7.1/10
- 5 victims (21%) — financial services focus
- Conti syndicate ties, invite-only affiliate model
- Qakbot initial access, Cobalt Strike lateral movement

---

# Advanced Use Cases

## Taking the agent beyond basic monitoring

### Proactive Threat Hunting
- Change industry filter to match your sector
- "Who's targeting manufacturing in the US this week?"
- Output: prioritized threat actor watchlist with detection rules

### Multi-Source Enrichment
- n8n has 400+ integrations
- Add VirusTotal, Shodan, MITRE ATT&CK nodes
- Pipe to Teams, SIEM webhook, Jira — each source is just another node

### Four Formats, One Execution
- SOC analyst → Markdown with Mermaid diagrams
- CISO → HTML report with charts
- Incident commander → Slack alert at 2 AM
- Legal → Google Doc for distribution

> "This isn't the ceiling. This is the floor."

---

# Build It This Weekend

## Minimum viable version — under 30 minutes

### Four steps to a working agent
1. Install n8n: `docker run -it --rm -p 5678:5678 n8nio/n8n`
2. Import `101_ransomware_threat_monitor.json` from the repo
3. Add your Anthropic API key to the Claude node
4. Click Execute

### No Python. No ML. No infrastructure.

### Want to go deeper?
- `mock_api/` — Local API server for safe testing (Python stdlib, zero dependencies)
- `examples/` — Golden Sample outputs showing exactly what the workflow produces
- `101_ransomware_threat_monitor_DEMO.json` — Pre-wired to mock API
- Fork it. Customize. Extend. The architecture is modular by design.

---

# Call to Action

## One thing to do this week

1. Go to `api.ransomware.live/v2/recentvictims` in your browser
2. Look at the data
3. Clone the repo — import the workflow — run it
4. You'll have a working AI-powered ransomware intelligence agent before your next coffee break

### The intel exists. The APIs exist. The workflow exists.
### The only missing piece is you clicking Import.

> "AI doesn't replace expertise — it amplifies it."

---

# Find Me

## Raymond DePalma

- **LinkedIn:** linkedin.com/in/raymond-depalma
- **This repo:** github.com/depalmar/AI-Powered-Ransomware-Intelligence-Agent
- **Labs (40+):** github.com/depalmar/ai_for_the_win

### License: CC BY-NC 4.0
Free to use for educational and defensive purposes.

---

# Thank You

## SANS Stay Ahead of Ransomware — March 3, 2026

### Building an AI-Powered Ransomware Intelligence Agent

*Powered by ransomware.live API + Anthropic Claude + n8n Workflow Automation*
