# Presenter Demo Guide — n8n Ransomware Intelligence Workflows

## SANS Webinar: Stay Ahead of Ransomware

This is your step-by-step walkthrough for demoing the three n8n workflows during the webinar. Follow this guide in order. Estimated demo time: **20-25 minutes**.

---

## Pre-Demo Setup Checklist

- [ ] n8n running locally or in the cloud
- [ ] All three workflows imported and visible in n8n
- [ ] Terminal open for curl commands
- [ ] The ransomware intelligence agent running (`uvicorn integrations.siem_soar.webhook:app --port 8080`)
- [ ] (Optional) Slack workspace connected for live notification demo
- [ ] Browser tabs open:
  - n8n dashboard
  - [ransomware.live](https://www.ransomware.live) (for context)
  - [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (for 201/300 visuals)
- [ ] This guide open on your second screen

### Quick Test Before Going Live

```bash
# Verify n8n is running
curl -s http://localhost:5678/healthz

# Verify agent is running (for 300 demo)
curl -s http://localhost:8080/api/v1/health

# Verify ransomware.live API is responding
curl -s https://api.ransomware.live/v2/groups | head -c 100
```

---

## Demo 1: 101 — Ransomware Group Threat Monitor (~5 min)

### Narrative

> "Let's start simple. Imagine you want to know which ransomware groups are actively targeting your industry — and you want that information delivered to Slack every 6 hours. With n8n, you can build this in under 10 minutes."

### Steps

1. **Open the 101 workflow** in n8n
   - Show the visual canvas — point out the left-to-right flow
   - Read the sticky notes aloud (they explain each section)

2. **Walk through the nodes** (don't execute yet):
   - "Here's our **Schedule Trigger** — every 6 hours"
   - "This **HTTP Request** node calls the ransomware.live API — a free, public API that tracks ransomware group activity"
   - "The **Code node** filters victims by sector — I've set it to Manufacturing, Healthcare, Finance"
   - "We **extract unique groups** and fetch their profiles"
   - "Finally, we **format a Markdown summary** and send it to Slack"

3. **Execute manually** — Click the Manual Trigger
   - Watch data flow through each node (n8n shows green checkmarks)
   - Click on the **"Filter by Sector"** node to show the filtered results
   - "Notice the victim names are redacted — we replace them with fabricated names since this is being recorded"
   - Click on the **"Format Threat Summary"** node to show the Markdown output

4. **Key takeaway:**
   > "That's it. 8 nodes. No code beyond some JavaScript filtering. You now have an automated ransomware threat monitor for your sector."

---

## Demo 2: 201 — IOC Enrichment & MITRE Mapping Pipeline (~8 min)

### Narrative

> "Now let's go a step further. Your SOC analyst finds suspicious hashes and IPs during an investigation. Instead of manually searching VirusTotal, looking up MITRE techniques, and writing up findings — let's automate all of that."

### Steps

1. **Open the 201 workflow** in n8n
   - Show the visual canvas — point out the webhook trigger, the loop, the parallel branches
   - "This workflow is **triggered by a webhook** — meaning your SIEM or an analyst can send IOCs directly to it"

2. **Walk through the key sections:**
   - **IOC Classification:** "It uses regex to automatically classify each IOC — is this a SHA256 hash? An IP address? A domain?"
   - **Batch Enrichment:** "Each IOC is searched against ransomware.live's database"
   - **MITRE ATT&CK Mapping:** "The observed TTPs are mapped to MITRE technique IDs using the same mapping from our Python agent"
   - **Conditional Escalation:** "If we match a high-priority group like LockBit or ALPHV, it triggers a critical alert"

3. **Execute via curl** — Switch to terminal:

```bash
curl -X POST http://localhost:5678/webhook/ioc-enrich \
  -H "Content-Type: application/json" \
  -d '{
    "hashes": [
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ],
    "ips": ["185.220.101.42", "91.243.44.178"],
    "domains": [],
    "observed_ttps": [
      "RDP lateral movement",
      "vssadmin shadow copy deletion",
      "schtasks persistence",
      "cobalt strike beacon",
      "powershell encoded command"
    ]
  }'
```

4. **Show the results:**
   - Switch back to n8n — click on the execution to see data flow
   - Click on **"Map to MITRE ATT&CK"** — show the technique mapping
     - "RDP lateral movement mapped to T1021.001"
     - "vssadmin mapped to T1490 — Inhibit System Recovery"
     - "cobalt strike mapped to T1059.001 and T1071.001"
   - Click on **"Build Enrichment Report"** — show the structured JSON + Markdown
   - Show the curl response in terminal

5. **Key takeaway:**
   > "We just automated IOC classification, API enrichment, MITRE mapping, and report generation — all triggered by a single webhook call. This is the pattern you'd use to connect your SIEM to automated enrichment."

---

## Demo 3: 300 — Full Incident Response Intelligence Pipeline (~10 min)

### Narrative

> "Now for the main event. Let's simulate a real ransomware incident. We have a fabricated scenario — 'Pinnacle Manufacturing Corp' got hit. We have the ransom note, hashes, C2 IPs, persistence mechanisms, lateral movement evidence, and LOLBAS usage. Let's run the full pipeline."

### Steps

1. **Open the 300 workflow** in n8n
   - "This is our **30-node** workflow. Let me walk you through the architecture."
   - Point out the major sections using the sticky notes:
     1. Artifact parsing
     2. AI Agent attribution call
     3. Parallel enrichment (4 branches)
     4. IR brief generation
     5. Confidence-based routing (Switch node)
     6. Multi-channel notifications

2. **Explain the AI Agent integration:**
   - "This workflow calls our **AI-Powered Ransomware Intelligence Agent** — the Python application we built. It performs embedding-based ransom note matching, IOC correlation, and a 4-signal weighted confidence score."
   - "If the agent is down, the workflow **gracefully degrades** — it still runs basic MITRE mapping locally."

3. **Explain confidence-based routing:**
   - "The Switch node routes based on confidence:"
   - ">= 80% — CRITICAL: Immediate Slack alert with @here, email to IR team, SIEM webhook"
   - "60-79% — HIGH: Queue for SOC review"
   - "< 60% — MEDIUM: Log only — reduces alert fatigue"

4. **Execute via curl** — Switch to terminal:

```bash
curl -X POST http://localhost:5678/webhook/ir-pipeline \
  -H "Content-Type: application/json" \
  -d @demo/scenario.json
```

5. **Show the results** (while it processes):
   - Switch to n8n — watch the execution flow in real-time
   - "See how the **parallel enrichment branches** all fire at once — group profile, YARA rules, sector victims, SEC filings"
   - Click on **"Parse Attribution / Fallback"** — show the confidence score and attributed group
   - Click on **"Generate IR Brief"** — show the full Markdown report
     - Walk through: Executive Summary, Threat Actor Profile, MITRE Techniques, Recommended Actions
   - Click on **"Route by Confidence"** — show which path was taken
   - Show the curl response in terminal — structured JSON with everything

6. **Key takeaway:**
   > "We just took a complete ransomware incident — ransom note, hashes, network IOCs, observed TTPs — and in seconds produced an executive-ready IR brief with threat actor attribution, MITRE mapping, YARA rules for deployment, and confidence-scored escalation routing. This is what AI-powered incident response looks like in practice."

---

## Wrap-Up Talking Points

After the demos, summarize:

1. **Progressive complexity** — Start with monitoring (101), add enrichment (201), build full IR pipelines (300)
2. **No-code to low-code** — n8n handles orchestration; the AI agent handles intelligence
3. **API-driven** — ransomware.live provides the data; your agent provides the analysis
4. **Confidence-based automation** — Don't alert on everything; route by confidence to reduce fatigue
5. **Graceful degradation** — The pipeline works at every capability level (no API key? Still works. Agent down? Falls back.)
6. **Recording safe** — All victim names redacted automatically

---

## Troubleshooting During Demo

| Issue | Quick Fix |
|-------|-----------|
| n8n not responding | `npx n8n start` or check Docker container |
| Agent endpoint fails | Workflows fall back to local analysis automatically |
| API rate limited | Wait 30 seconds, re-run (token bucket: 2 req/sec) |
| Slack not sending | Expected — Slack nodes are disabled by default. Mention this. |
| No victims in sector filter | Change sector to broader categories or remove filter temporarily |
| curl hangs | Check that webhook path matches (`/webhook/ioc-enrich`, `/webhook/ir-pipeline`) |

---

## Post-Demo Resources

Share with attendees:
- Repository: `https://github.com/depalmar/AI-Powered-Ransomware-Intelligence-Agent`
- n8n workflows: In the `n8n_workflows/` directory
- ransomware.live: `https://www.ransomware.live`
- MITRE ATT&CK: `https://attack.mitre.org`
