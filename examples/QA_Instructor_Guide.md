# Q&A + Instructor Guide

**SANS Stay Ahead of Ransomware — March 3, 2026**
**Building an AI-Powered Ransomware Intelligence Agent**

> **Last Updated:** 2026-03-02
> **Repo:** [github.com/depalmar/AI-Powered-Ransomware-Intelligence-Agent](https://github.com/depalmar/AI-Powered-Ransomware-Intelligence-Agent)

---

## Suggested Questions for Ryan & Mari

These map to the segment flow and are designed to feel conversational while hitting the key teaching moments. Ryan and Mari can pick, skip, or riff — this is a menu, not a script.

---

### Segment 2 — The Problem (after ~5:00)

**Ryan:** "So Raymond, last time you were on we talked about the AI arms race at a high level. What made you go from 'defenders need AI' to 'here's an actual agent you can build'?"

> **Ray's anchor points:** Bridge from Feb episode. The gap between "AI is important" and "here's how to use it" is where most practitioners stall. Wanted to close that gap with something buildable, not theoretical. Built an n8n workflow anyone can import and run in under an hour — no ML expertise needed.

**Mari:** "Walk us through what the current workflow actually looks like when an analyst gets called at 2 AM with encrypted endpoints. What are they doing manually right now?"

> **Ray's anchor points:** 6+ browser tabs open, VirusTotal, MITRE ATT&CK, vendor blogs, ransom note repos. Copy-paste into report templates. 2–4 hours for basic attribution. Night shift analyst with less experience — half a day. Frame the time tax.

**Ryan:** "So the data is out there, it's just not connected. And you're saying an AI agent is the glue?"

> **Ray's anchor points:** Exactly. The intel exists — ransomware.live alone has 275+ tracked groups, thousands of victims, YARA rules, negotiation transcripts. No analyst can query all of that during an active incident. The n8n workflow fetches, filters, enriches, and passes everything to Claude for structured TTP extraction. The agent does the library research while you focus on the crime scene.

---

### Segment 3 — Ransomware.live API (after ~13:00)

**Ryan:** "For people who haven't used ransomware.live before — what is it, and why is it the backbone of this agent?"

> **Ray's anchor points:** Created by Julien Mousqueton. Aggregates data from leak sites, CERT advisories, press, enrichment sources. Not commercial — community intelligence. Free API, no auth required. The n8n workflow hits two key endpoints: `/v2/recentvictims` for the latest postings and `/v2/groups/{name}` for detailed threat actor profiles.

**Mari:** "You mentioned a PRO API with negotiation transcripts. The negotiation data — that's something most defenders never see. What does it actually tell you?"

> **Ray's anchor points:** Negotiation transcripts reveal operational patterns — typical opening demands, discount percentages (often 50–70% off), response timing windows, communication style, whether they actually have a reliable decryptor. This directly informs whether to engage and what to expect. "Reading a threat actor's negotiation history is like reading their Yelp reviews."

**Ryan:** "What about the free tier vs. PRO? Can someone build something useful without paying?"

> **Ray's anchor points:** Absolutely. The entire workflow in this repo runs on the free API. It gives you group profiles, victim lists, keyword search, YARA rules, sector targeting, temporal trends. PRO adds negotiations, IOCs, ransom notes, TTPs, and 8-K filings. Start free, upgrade when the value is proven. Everything I'm demoing today is free-tier.

---

### Segment 4 — Architecture (after ~23:00)

**Ryan:** "Walk us through the actual architecture. How does data flow from ransomware.live to a finished intelligence brief?"

> **Ray's anchor points:** Eight-step pipeline, all orchestrated in n8n:
>
> 1. **Trigger** — every 6 hours (or manual click for demo)
> 2. **Fetch** — pulls recent victims from `ransomware.live/v2/recentvictims`
> 3. **Redact** — immediately replaces real victim names with realistic fakes. No real names ever appear in execution logs. Recording-safe from this point forward.
> 4. **Filter** — drops victims outside your target industries (configurable array)
> 5. **Deduplicate** — groups victims by threat actor
> 6. **Enrich** — fetches detailed group profiles for each active actor
> 7. **Analyze (AI)** — Claude receives the consolidated dataset and returns structured TTPs, targeting patterns, and recommendations using a JSON output parser
> 8. **Distribute** — generates four outputs: Markdown report with Mermaid diagrams, self-contained HTML with Chart.js charts, Slack alert summary, and Google Doc
>
> The whole thing runs in n8n — visual, no-code, but with full JavaScript code nodes where we need custom logic.

**Mari:** "For someone who's never built an AI agent before, what's the actual skill barrier here?"

> **Ray's anchor points:** If you can import a JSON file and click a button, you can run this. The n8n workflow handles all the plumbing — API calls, data transformation, deduplication, report formatting. Claude handles the reasoning and TTP extraction. You're configuring, not coding from scratch. "The barrier to entry isn't AI expertise. It's DFIR expertise."

**Ryan:** "The confidence scoring piece is interesting. How do you avoid the agent just hallucinating an attribution?"

> **Ray's anchor points:** Claude receives the actual data — victim records, group profiles, industry distributions, geographic patterns — and produces structured JSON output via a schema-constrained output parser. It can't drift into freeform hallucination because the schema requires specific fields: `threat_level`, `ttps` (array with tactic/technique/description), `targeting_patterns`, `operational_intelligence`, `recommendations`. The analyst reviews the final brief. The AI writes the first draft; the human approves it.

**Ryan:** "And the redaction piece — that's critical for a live demo. How does that work?"

> **Ray's anchor points:** The `Generate Diverse Fake Companies` node runs immediately after the API fetch — before any other processing. It generates unique fake company names from randomized prefix/suffix combinations (e.g., "Meridian Industrial Solutions", "Cobalt Dynamics Corp"), randomizes industries, countries, and discovery dates. Real victim names never reach the AI, the report, or the execution logs. 100% recording-safe.

---

### Segment 5 — Live Demo (after ~35:00)

**Ryan:** "Before you start — set the scene for us. What are we about to see?"

> **Ray's anchor points:** I'm going to run the full n8n workflow — but against a local mock API server, not the live ransomware.live feed. This guarantees predictable output that matches our Golden Sample report. The mock server returns 24 victims across 3 groups: LockBit 3.0 (11 victims), Play (8 victims), and BlackBasta (5 victims). Same data format, same endpoints, zero dependency on live internet.
>
> *[Start mock API: `python mock_api/server.py` — or double-click `run_demo.bat`]*
> *[Import `101_ransomware_threat_monitor_DEMO.json` into n8n]*
> *[Click Execute Workflow]*

**Mari:** (After the workflow executes) "That report is... substantial. Walk us through what we're looking at."

> **Ray's anchor points:** Four outputs just landed:
>
> 1. **Markdown report** — Executive dashboard with trend deltas, AI-generated MITRE ATT&CK mapping as a Mermaid mindmap, TTP detail table with severity ratings, pie charts for geographic and industry distribution, gantt timeline, attack lifecycle flowchart, weighted risk matrix scoring 7.95/10, and threat group profiles with per-group industry breakdowns. Victim ledger is collapsed in an appendix.
> 2. **HTML report** — Same data, but self-contained with Chart.js doughnut charts, radar chart for the risk matrix, stacked bar chart for the timeline. Opens in any browser, no server needed.
> 3. **Slack alert** — Condensed summary with MITRE TTP IDs, threat scores per group, and prioritized P1/P2 actions.
> 4. **Google Doc** — Plain-text version for leadership distribution.

**Ryan:** (Looking at the AI section) "The MITRE ATT&CK mapping — Claude generated that automatically?"

> **Ray's anchor points:** Yes. Claude received the full dataset and the structured output parser forced it to return TTPs as an array of `{tactic, technique, description}` objects. The `Enhance Brief with AI Analysis` code node then renders those into a Mermaid mindmap and a severity-rated table. T1190, T1059, T1567, T1486 — all mapped automatically from the victim and group data. The defensive recommendations are prioritized P1/P2 with effort estimates.

**Mari:** "The risk matrix with the weighted scoring — where does that come from?"

> **Ray's anchor points:** Six weighted factors computed from the actual data: attack frequency (20%), target industry criticality (25% — healthcare drives this up), geographic spread (10%), threat actor sophistication (20%), time-to-encrypt compression (15%), and double-extortion prevalence (10%). The composite score is 7.95/10 — HIGH. This gives leadership a single number to react to instead of a wall of text.

**Ryan:** "That whole process just happened in — what — under two minutes? What would that normally take?"

> **Ray's anchor points:** Best case with an experienced analyst who knows where to look: 2–4 hours. Less experienced analyst on night shift: potentially half a day. And that assumes they know all the right sources. "The agent didn't do anything I couldn't do. It just did it at 2 AM without coffee, in 90 seconds, and didn't forget to check the negotiation history."

---

### Segment 6 — Advanced Use Cases (after ~53:00)

**Ryan:** "You mentioned using the agent in reverse — for proactive threat hunting. How does that work?"

> **Ray's anchor points:** Change the industry filter in the `Filter by Industry` node to match your organization's sector. The workflow then continuously monitors: "Who's targeting manufacturing in the US this week?" You get a prioritized threat actor watchlist with TTPs to pre-deploy detection rules for. Shift from reactive to proactive.

**Mari:** "The n8n approach — could someone extend this beyond ransomware.live?"

> **Ray's anchor points:** Absolutely. n8n has 400+ integrations out of the box. Add a VirusTotal node after the IOC extraction. Add a Shodan node to check if your exposed infrastructure matches known attack vectors. Pipe the output to Microsoft Teams instead of Slack. Send it to a SIEM via webhook. Each new data source is just another node on the canvas. "This isn't the ceiling. This is the floor."

**Ryan:** "What about the multi-output approach — Markdown, HTML, Slack, Google Docs. Why four formats?"

> **Ray's anchor points:** Different audiences need different formats. The SOC analyst wants the full Markdown with Mermaid diagrams in their wiki. The CISO wants the HTML report with charts they can open in a browser. The incident commander wants the Slack ping at 2 AM. Legal wants the Google Doc they can forward. One workflow execution, four deliverables, zero additional effort.

---

### Segment 7 — Build It Yourself (after ~61:00)

**Mari:** "Be honest — what's the minimum viable version someone can build this weekend?"

> **Ray's anchor points:**
>
> 1. Install n8n (Docker one-liner: `docker run -it --rm -p 5678:5678 n8nio/n8n`)
> 2. Import `101_ransomware_threat_monitor.json` from the repo
> 3. Add your Anthropic API key to the Claude node
> 4. Click Execute
>
> That's it. You'll have a working ransomware intelligence agent generating MITRE-mapped threat briefs in under 30 minutes. No Python, no ML, no infrastructure. Everything else — Slack, Google Docs, industry filters — is optional configuration.

**Ryan:** "And if someone wants to go deeper — extend it, customize it?"

> **Ray's anchor points:** The repo has everything:
>
> - `mock_api/` — Local API server for safe development and testing. Python stdlib only, no dependencies.
> - `examples/` — Golden Sample outputs (Markdown, HTML, Slack) showing exactly what the workflow produces
> - `101_ransomware_threat_monitor_DEMO.json` — Pre-wired to the mock API for safe demos
> - `run_demo.bat` — One-click launcher for Windows
>
> Fork it, customize the industry filter, swap Claude for GPT-4 if you want, add your own enrichment nodes. The architecture is modular by design.

**Ryan:** "Your AI for the Win repo — 40+ labs. Where does this agent fit in?"

> **Ray's anchor points:** New lab module specifically for this. Designed for practitioners — DFIR fundamentals assumed, AI/ML knowledge not required. The repo takes you from zero to building agents, with ransomware intelligence as a capstone use case.

---

### Wrap-Up (after ~66:00)

**Ryan:** "Raymond — final thoughts? One thing the audience should do this week?"

> **Ray's anchor points:** Go to `api.ransomware.live/v2/recentvictims` in your browser. Look at the data. Then clone the repo, import the workflow, and run it. You'll have a working AI-powered ransomware intelligence agent before your next coffee break. The intel exists, the APIs exist, the workflow exists. The only missing piece is you clicking Import.

**Ryan:** "Where can people find you?"

> **Ray's anchor points:**
> - **LinkedIn:** linkedin.com/in/raymond-depalma
> - **GitHub (this repo):** github.com/depalmar/AI-Powered-Ransomware-Intelligence-Agent
> - **GitHub (labs):** github.com/depalmar/ai_for_the_win
> - The ransomware intelligence agent lab will be published there.

---

## Instructor Guide

### Pre-Show Checklist (Raymond)

| Item | Status |
|------|:------:|
| n8n instance running and accessible | ☐ |
| Mock API server tested: `python mock_api/server.py` → `http://localhost:3000/v2/recentvictims` returns 24 victims | ☐ |
| DEMO workflow imported: `101_ransomware_threat_monitor_DEMO.json` in n8n | ☐ |
| Anthropic API key configured in the `Claude Model` node | ☐ |
| Full workflow executed end-to-end — all 4 outputs generated (Markdown, HTML, Slack, Google Doc) | ☐ |
| Golden Sample outputs ready as fallback: `examples/Ransomware_Threat_Brief_Sample.md` and `.html` | ☐ |
| Ransomware.live live API verified working (for discussion, not demo): `api.ransomware.live/v2/recentvictims` | ☐ |
| Screen share tested in StreamYard (use Firefox per Ryan's note) | ☐ |
| GitHub repo public and up-to-date: all commits pushed to `main` | ☐ |
| Cursor IDE ready with `Ransomware_Threat_Brief_Sample.md` open for Mermaid preview (dark theme) | ☐ |
| HTML report pre-opened in browser tab for quick switch | ☐ |
| Bitdefender exclusion added for workspace folder (prevents false-positive interruptions during demo) | ☐ |

### Pre-Show Checklist (Ryan & Mari)

| Item | Status |
|------|:------:|
| Review Q&A questions above — pick favorites, add your own | ☐ |
| Audience engagement prompts ready (geo check-in, "who's built an AI agent before?") | ☐ |
| YouTube chat monitored for audience questions | ☐ |
| Timestamps for show notes confirmed against segment overview | ☐ |

---

### Demo Failure Contingencies

| Failure | Pivot |
|---------|-------|
| **ransomware.live API down** | Not an issue — demo uses local mock API server (`mock_api/server.py`). Completely offline-capable. |
| **Mock API server won't start** | Open `examples/Ransomware_Threat_Brief_Sample.html` in browser and `examples/Ransomware_Threat_Brief_Sample.md` in Cursor preview. Walk through the Golden Sample outputs as if they were just generated. |
| **n8n instance crashes** | Same as above — show the Golden Sample outputs. The HTML report has Chart.js charts that are interactive. |
| **Claude API rate limit or timeout** | The workflow will still generate the base report (Executive Dashboard, geo/industry analysis, group profiles, risk matrix) — only the AI section (MITRE mapping, TTP extraction, recommendations) will be missing. Show the Golden Sample for the AI section. |
| **Anthropic API key invalid** | Import the production workflow (`101_ransomware_threat_monitor.json`) and point it at the live `ransomware.live` API. Skip the AI enrichment step and show the pre-generated AI output from the Golden Sample. |
| **StreamYard screen share issues** | Have the HTML report open in a browser — it's self-contained and screenshot-friendly. |
| **Internet drops entirely** | Mock API is local, n8n is local. The only thing that needs internet is Claude. Fall back to Golden Sample outputs for the AI section. |

---

### Repo Structure Reference

```
AI-Powered-Ransomware-Intelligence-Agent/
├── n8n_workflows/
│   ├── 101_ransomware_threat_monitor.json        ← Production (live API)
│   └── 101_ransomware_threat_monitor_DEMO.json   ← Demo (localhost mock API)
├── mock_api/
│   ├── server.py                                  ← Python mock API server (port 3000)
│   ├── README.md
│   └── data/
│       ├── recentvictims.json                     ← 24 victims (3 groups)
│       └── groups/
│           ├── lockbit3.json
│           ├── play.json
│           └── blackbasta.json
├── examples/
│   ├── Ransomware_Threat_Brief_Sample.md          ← Golden Sample (Markdown + Mermaid)
│   ├── Ransomware_Threat_Brief_Sample.html        ← Golden Sample (HTML + Chart.js)
│   └── Slack_Alert_Sample.txt                     ← Golden Sample (Slack)
├── run_demo.bat                                    ← One-click demo launcher (Windows)
├── README.md
└── LICENSE                                         ← CC BY-NC 4.0
```

### Workflow Nodes Reference (for discussion)

| Node | Purpose |
|------|---------|
| Every 6 Hours | Schedule trigger (or manual click) |
| Fetch Recent Victims | `GET /v2/recentvictims` |
| Generate Diverse Fake Companies | Replaces real names with fake data |
| Filter by Industry | Configurable industry keyword filter |
| Extract Unique Groups | Deduplicates by threat actor |
| Groups Found? | Conditional branch |
| Get Group Profile | `GET /v2/groups/{name}` |
| Build Consolidated Brief | Generates full Markdown + Slack (v2 — Mermaid, risk matrix, appendix) |
| Threat Intelligence AI Agent | LangChain agent → Claude with structured output parser |
| Claude Model | Anthropic Claude Opus 4.6 (with extended thinking) |
| Structured TTP Output | JSON schema: threat_level, ttps[], targeting_patterns, recommendations[] |
| Enhance Brief with AI Analysis | Injects MITRE mindmap, TTP table, recommendations into report |
| Output Markdown File | Binary .md file output |
| Output HTML File | Self-contained .html with Chart.js |
| Slack Alert | Slack message with MITRE TTPs and priority actions |
| Google Doc Report | Google Docs API output (disabled by default) |

---

### Pacing Notes

- **Segments 1–4** (slides + discussion): ~35 min. Keep conversational. Ryan and Mari's questions are the transitions — don't wait for awkward pauses.
- **Segment 5** (live demo): ~18 min. This is the centerpiece. Raymond drives, Ryan narrates/asks questions between steps. Mari can jump in on the AI analysis and report output portions.
  - **Demo flow:** Start mock API → show it serving data → switch to n8n → execute workflow → watch nodes light up → show Markdown output with Mermaid diagrams in Cursor → switch to HTML report in browser → show Slack alert → highlight AI section
- **Segments 6–8** (advanced + wrap): ~17 min. Shift energy from "watch me build" to "now you build." Call to action is critical — give them something concrete to do this week.

---

### Audience Engagement Touchpoints

| When | Prompt |
|------|--------|
| 00:02 | "Where's everyone joining from today?" (geo check-in) |
| 05:00 | "How many of you have manually correlated ransomware intel during an incident? Drop a 1 in chat." |
| 13:00 | "Who's used ransomware.live before? Drop a Y or N." |
| 23:00 | "n8n, Python script, or SIEM integration — which would you build first? Drop A, B, or C." |
| 35:00 | "Buckle up — live demo time. Drop your predictions: how fast will the agent generate the full brief?" |
| 53:00 | "What other data sources would you plug into this? Drop your ideas." |
| 66:00 | "Who's going to build this? Drop a 🔥 if you're in." |

---

### Key Soundbites to Hit

These are pre-planned for social media clips. Raymond should aim to land these naturally during the relevant segments:

| Segment | Soundbite |
|---------|-----------|
| 2 — The Problem | "We're not asking AI to do the forensics. We're asking it to do the library research while we focus on the crime scene." |
| 3 — Ransomware.live | "Reading a threat actor's negotiation history is like reading their Yelp reviews." |
| 4 — Architecture | "The barrier to entry isn't AI expertise. It's DFIR expertise." |
| 5 — Live Demo | "The agent didn't do anything I couldn't do. It just did it at 2 AM without coffee, in 90 seconds." |
| 6 — Advanced | "This isn't the ceiling. This is the floor." |
| Wrap-up | "AI doesn't replace expertise — it amplifies it." |

---

### Post-Show Actions

| Action | Owner | Timeline |
|--------|-------|----------|
| Verify GitHub repo is public with all demo artifacts | Raymond | Pre-show |
| Share recording link + show notes with timestamps | Ryan | Same day |
| LinkedIn post with key takeaways + repo link | Raymond | Same day |
| Clip 3–4 soundbite moments for social | Ryan/SANS | Within 1 week |
| Collect audience questions that weren't answered live | Mari | Same day |
| Follow-up thread in SANS community with setup walkthrough | Raymond | Within 1 week |
| Publish ransomware intelligence lab module to ai_for_the_win repo | Raymond | Within 48 hours |
