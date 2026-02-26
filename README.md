# Ransomware Intelligence Agent

AI-powered ransomware intelligence agent that ingests host-based forensic artifacts and cross-references them against [ransomware.live](https://www.ransomware.live/)'s real-time intelligence database to attribute threat actors, surface IOCs, pull negotiation transcripts, and generate actionable IR briefs.

Built for the SANS podcast demo *"Stay Ahead of Ransomware"* with Ryan Chapman and as a lab module for the [ai_for_the_win](https://github.com/depalmar/ai_for_the_win) training repository.

## Architecture

Three deployment options — use what fits your workflow:

| Option | Description | Best For |
|---|---|---|
| **A. MCP Server** | FastMCP server exposing tools for Claude Desktop / Claude Code | Interactive investigation with AI |
| **B. LangGraph Agent** | Standalone agent with Ollama or Claude API backend | Automated pipeline, CI/CD integration |
| **C. Integration Layer** | Adapters for Velociraptor, osquery, SIEM/SOAR | Existing IR toolchain integration |

## Quick Start

### Prerequisites
- Python 3.11+
- (Optional) [Ollama](https://ollama.com/) for local embedding + LLM
- (Optional) [ransomware.live PRO API key](https://www.ransomware.live/) for full intelligence

### Install

```bash
git clone https://github.com/depalmar/ransomware-intel-agent.git
cd ransomware-intel-agent
pip install -e ".[all]"
cp .env.example .env
# Edit .env with your API keys
```

### Option A: MCP Server (Claude Desktop)

```bash
# Start the server
ransomware-mcp
```

Add to Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "ransomware-intel": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/path/to/ransomware-intel-agent",
      "env": {
        "RANSOMWARE_LIVE_PRO_KEY": "your_key_here"
      }
    }
  }
}
```

Then ask Claude: *"Match this ransom note against known groups..."* or *"Generate a full IR brief for incident IR-2026-0219"*

### Option B: LangGraph Agent (Standalone)

```bash
# With Claude API
python -m langgraph_agent.agent --scenario demo/scenario.json

# With Ollama (local)
python -m langgraph_agent.agent --backend ollama --scenario demo/scenario.json
```

### Option C: Integration Adapters

```bash
# SIEM/SOAR webhook
pip install -e ".[integrations]"
uvicorn integrations.siem_soar.webhook:app --host 0.0.0.0 --port 8080

# Send an alert
curl -X POST http://localhost:8080/api/v1/enrich \
  -H "Content-Type: application/json" \
  -d @integrations/siem_soar/example_payloads/generic.json
```

See `integrations/` for Velociraptor and osquery setup.

## MCP Tools

| Tool | Description | API |
|---|---|---|
| `match_ransom_note` | Embedding similarity matching against known ransom notes | PRO + Ollama |
| `lookup_iocs` | Query hashes, IPs, domains against IOC database | PRO |
| `get_negotiation_intel` | Negotiation transcripts with demand/discount analysis | PRO |
| `get_group_profile` | Group description, locations, victim count | Free |
| `get_group_ttps` | MITRE ATT&CK mappings for a group | PRO |
| `get_group_yara` | YARA detection rules | Free |
| `search_victims` | Keyword/sector/temporal victim search | Free |
| `get_recent_victims` | Recent victims with trend analysis | Free |
| `correlate_ttps` | Map observed TTPs to ranked group matches | PRO |
| `generate_ir_brief` | Full attribution pipeline → leadership-ready report | Composite |
| `assess_threat_landscape` | Proactive hunting by sector/geography | Free + PRO |
| `get_8k_filings` | SEC cybersecurity incident disclosures | PRO |

## Confidence Scoring

Multi-signal weighted attribution model:

| Signal | Weight | Description |
|---|---|---|
| Ransom Note Match | 35% | Embedding similarity or keyword match |
| IOC Overlap | 30% | Hash/IP/domain matches against known infrastructure |
| TTP Alignment | 20% | MITRE ATT&CK technique overlap with group playbook |
| File Extension | 15% | Encrypted file extension pattern matching |

Output: percentage confidence + per-signal breakdown.

## Demo

Run the simulated incident walkthrough:

```bash
# Full pipeline
python demo/run_demo.py

# Step by step with explanations
python demo/run_demo.py --step-by-step
```

The demo uses a completely fabricated incident at *Pinnacle Manufacturing Corp* — no real victim data.

## Graceful Degradation

The agent works at every capability level:

| Available | Capability |
|---|---|
| No API keys, no Ollama | Keyword matching, TTP mapping, report structure |
| Free API only | + Group profiles, YARA rules, victim search |
| Free + PRO API | + IOC lookup, TTP correlation, negotiations, SEC filings |
| Free + PRO + Ollama | + Embedding-based ransom note matching |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .
```

## Project Structure

```
ransomware-intel-agent/
├── mcp_server/           # Option A: FastMCP Server
│   ├── server.py         # MCP server entry point
│   ├── tools/            # Individual tool implementations
│   ├── api/              # Ransomware.live API client
│   ├── embeddings/       # Ollama + ChromaDB vector store
│   ├── scoring/          # Weighted confidence scoring
│   ├── models.py         # Pydantic data schemas
│   └── config.py         # Configuration management
├── langgraph_agent/      # Option B: LangGraph Agent
│   ├── agent.py          # Agent entry point
│   ├── graph.py          # State graph definition
│   ├── nodes/            # Graph node implementations
│   └── llm_backends.py   # Ollama + Claude abstraction
├── integrations/         # Option C: Integration Adapters
│   ├── velociraptor/     # VQL artifact + adapter
│   ├── osquery/          # Query pack + adapter
│   └── siem_soar/        # Webhook endpoint
├── demo/                 # Podcast demo materials
├── templates/            # Jinja2 report templates
├── tests/                # Test suite
└── docs/                 # Documentation
```

## License

MIT

## Disclaimer

This tool is for **defensive security operations and educational purposes only**. All demo data is fabricated. This tool does not facilitate ransomware attacks — it helps defenders respond to them.
