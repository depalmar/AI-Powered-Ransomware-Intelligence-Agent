# SANS Webinar Presentation Outline
## "Stay Ahead of Ransomware: AI-Powered Intelligence Automation with n8n"

> **Paste this into Gamma (gamma.app) to generate your slide deck.**
> Use "Paste in document" or "Generate from outline" mode.

---

## Slide 1: Title

**Stay Ahead of Ransomware**
AI-Powered Intelligence Automation with n8n

SANS Webinar | 2026
Presented by [Your Name]

---

## Slide 2: The Problem

**Ransomware response is a race against the clock**

- Average time from initial access to encryption: **4-8 hours**
- Manual threat intel gathering: **2-4 hours per incident**
- Multiple data sources to query (VirusTotal, MITRE, OSINT, vendor feeds)
- Attribution is critical for response decisions (negotiation, decryptor availability, data leak risk)

**What if we could automate the intelligence pipeline?**

---

## Slide 3: What We Built

**AI-Powered Ransomware Intelligence Agent**

Three deployment options, one intelligence engine:

| Option | Interface | Use Case |
|--------|-----------|----------|
| MCP Server | Claude Desktop/Code | Interactive analyst queries |
| LangGraph Agent | CLI / CI/CD | Automated batch processing |
| n8n Workflows | Visual automation | SOAR-style orchestration |

**Data source:** ransomware.live — real-time ransomware group tracking

---

## Slide 4: Intelligence Capabilities

**12 specialized tools working together:**

- Ransom note matching (embedding similarity via Ollama)
- IOC enrichment (hash, IP, domain lookup)
- MITRE ATT&CK TTP mapping (30+ observation keywords)
- Confidence-scored attribution (4-signal weighted model)
- Threat landscape assessment (sector/geography)
- Negotiation intelligence (demand ranges, discount curves)
- YARA rule retrieval (deployable detection rules)
- SEC 8-K filing correlation (public incident disclosures)

---

## Slide 5: The Scoring Model

**4-Signal Weighted Attribution**

| Signal | Weight | What It Measures |
|--------|--------|-----------------|
| Ransom Note Match | 35% | Embedding similarity to known notes |
| IOC Overlap | 30% | Infrastructure reuse (hashes, IPs, domains) |
| TTP Alignment | 20% | MITRE technique overlap with group playbooks |
| File Extension | 15% | Known encryption extension patterns |

**Confidence Labels:**
- >= 80%: High — Immediate escalation
- 60-79%: Medium — SOC review
- < 60%: Low — Log and monitor

---

## Slide 6: Why n8n?

**Visual workflow automation for security teams**

- **No-code to low-code** — drag-and-drop nodes with optional JavaScript
- **Self-hosted** — your data stays in your environment
- **400+ integrations** — Slack, Teams, SMTP, webhooks, databases
- **Webhook triggers** — SIEM → n8n → response in seconds
- **Parallel execution** — multiple API calls simultaneously
- **Free & open source** — no vendor lock-in

---

## Slide 7: Demo — 101 Threat Monitor

**Beginner: Automated Ransomware Activity Monitor**

`Schedule Trigger → Fetch Victims → Filter by Sector → Enrich Groups → Slack Alert`

- Polls ransomware.live every 6 hours
- Filters for your industry sectors
- Fetches group profiles for context
- Sends formatted Markdown threat brief to Slack

**8 nodes. No API key required. 10 minutes to build.**

---

## Slide 8: Demo — 201 IOC Enrichment

**Intermediate: IOC Enrichment & MITRE Mapping Pipeline**

`Webhook → Classify IOCs → Search API → Map MITRE → YARA Rules → Report`

- Receives IOCs from analyst or SIEM via webhook
- Classifies by type (SHA256, IP, domain) using regex
- Searches ransomware.live for group matches
- Maps observations to MITRE ATT&CK technique IDs
- Fetches YARA rules for matched groups
- Returns structured enrichment report via webhook response

**18 nodes. Webhook-driven. SIEM-ready.**

---

## Slide 9: Demo — 300 Full IR Pipeline

**Advanced: Complete Incident Response Intelligence Pipeline**

`Webhook → AI Agent → Parallel Enrichment → IR Brief → Confidence Routing → Multi-Channel Alerts`

- Receives full incident artifacts (ransom note, hashes, IPs, TTPs)
- Calls the AI-powered attribution agent
- Parallel enrichment: profile, YARA, sector context, SEC filings
- Generates executive-ready Markdown IR brief
- Routes by confidence level:
  - HIGH: Slack @here + email IR team + SIEM
  - MEDIUM: SOC queue
  - LOW: Log only

**30 nodes. Agent-as-a-service. Confidence-based escalation.**

---

## Slide 10: Architecture Diagram

```
                    ┌─────────────┐
                    │   n8n        │
                    │  Workflows   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──┐  ┌──────▼──┐  ┌──────▼──┐
       │   101   │  │   201   │  │   300   │
       │ Monitor │  │ Enrich  │  │ Full IR │
       └────┬────┘  └────┬────┘  └────┬────┘
            │            │            │
            ▼            ▼            ▼
    ┌───────────────────────────────────────┐
    │         ransomware.live API           │
    │  Groups | Victims | IOCs | YARA | TTPs│
    └───────────────────────────────────────┘
                                      │
                               ┌──────▼──────┐
                               │  AI Agent   │
                               │ (MCP/Lang   │
                               │  Graph)     │
                               └─────────────┘
```

---

## Slide 11: Graceful Degradation

**The system works at every capability level**

| Available Resources | Capabilities |
|--------------------|-------------|
| No API keys, no Ollama | Keyword matching, MITRE mapping, report structure |
| Free API only | + Group profiles, YARA rules, victim search |
| Free + PRO API | + IOC lookup, TTP correlation, negotiations, SEC filings |
| Free + PRO + Ollama + Agent | Full embedding-based attribution with confidence scoring |

**No single point of failure. Always provides value.**

---

## Slide 12: Key Takeaways

1. **Automate the repetitive** — Let machines do the API queries, classification, and enrichment
2. **Confidence-based routing** — Don't alert on everything; route by confidence to reduce fatigue
3. **Progressive complexity** — Start with monitoring (101), add enrichment (201), build full IR (300)
4. **Agent-as-a-service** — Wrap your AI in an API, call it from any automation platform
5. **Graceful degradation** — Design systems that work at every capability level

---

## Slide 13: Resources

- **Repository:** github.com/depalmar/AI-Powered-Ransomware-Intelligence-Agent
- **n8n:** n8n.io (open source workflow automation)
- **ransomware.live:** Real-time ransomware group intelligence
- **MITRE ATT&CK:** attack.mitre.org

**Questions?**

---

## Slide 14: Q&A

**Contact:**
- [Your contact info]
- [Twitter/LinkedIn]

**All demo data is fabricated. No real victims were displayed.**
