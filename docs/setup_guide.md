# Setup Guide

## Prerequisites

- **Python 3.11+** (3.12 recommended)
- **pip** or **uv** for package management
- **Git** for version control

### Optional (but recommended)
- **Ollama** — for local embedding generation and LLM inference
- **ransomware.live PRO API key** — for full intelligence capabilities

## Step 1: Clone and Install

```bash
git clone https://github.com/depalmar/ransomware-intel-agent.git
cd ransomware-intel-agent

# Install with all optional dependencies
pip install -e ".[all]"

# Or install specific extras:
pip install -e "."                # Core MCP server only
pip install -e ".[langgraph]"     # + LangGraph agent
pip install -e ".[integrations]"  # + SIEM/SOAR webhook
pip install -e ".[dev]"           # + Testing tools
```

## Step 2: Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# Required for full intelligence (optional — agent works without it)
RANSOMWARE_LIVE_PRO_KEY=your_pro_api_key_here

# Required for LangGraph agent with Claude (optional)
ANTHROPIC_API_KEY=your_anthropic_key_here

# Everything else has sensible defaults
```

## Step 3: Set Up Ollama (Optional)

Ollama enables local embedding-based ransom note matching.

```bash
# Install Ollama (macOS)
brew install ollama

# Install Ollama (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Pull the embedding model
ollama pull nomic-embed-text

# Start Ollama (if not auto-started)
ollama serve
```

### Pre-index ransom notes (requires PRO API key + Ollama)

```python
import asyncio
from mcp_server.embeddings.note_index import build_note_index

asyncio.run(build_note_index())
```

## Step 4: Verify Installation

```bash
# Run tests
pytest

# Run the demo (works without any API keys)
python demo/run_demo.py
```

## Step 5: Choose Your Deployment

### Option A: MCP Server for Claude Desktop

See [MCP Setup Guide](mcp_setup.md).

### Option B: Standalone LangGraph Agent

```bash
# With Claude API
python -m langgraph_agent.agent --scenario demo/scenario.json

# With Ollama
python -m langgraph_agent.agent --backend ollama --scenario demo/scenario.json
```

### Option C: SIEM/SOAR Integration

```bash
# Start the webhook server
uvicorn integrations.siem_soar.webhook:app --host 0.0.0.0 --port 8080

# Test with a sample alert
curl -X POST http://localhost:8080/api/v1/enrich \
  -H "Content-Type: application/json" \
  -d @integrations/siem_soar/example_payloads/generic.json
```

## Troubleshooting

### "Ollama embedding failed" warnings
- Ollama is not running or nomic-embed-text is not pulled
- The agent falls back to keyword matching — this is expected behavior
- Fix: `ollama serve` and `ollama pull nomic-embed-text`

### "PRO API key not configured" warnings
- PRO endpoints return empty results without a key
- Free API endpoints still work for group profiles, YARA, victims
- Fix: Add your key to `.env`

### ChromaDB permission errors
- The vector store directory (`chroma_data/`) needs write permissions
- Fix: `chmod 755 chroma_data/` or set `CHROMA_PERSIST_DIR` to a writable path

### Import errors for LangGraph
- LangGraph dependencies are optional
- Fix: `pip install -e ".[langgraph]"`
