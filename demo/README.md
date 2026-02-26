# Demo — SANS Podcast Walkthrough

## Overview

This demo simulates a ransomware incident at **Pinnacle Manufacturing Corp** and runs the full attribution pipeline to demonstrate the agent's capabilities.

## Setup

1. Install the project:
   ```bash
   pip install -e ".[all]"
   ```

2. (Optional) Start Ollama for embedding-based matching:
   ```bash
   ollama pull nomic-embed-text
   ollama serve
   ```

3. (Optional) Set your ransomware.live PRO API key:
   ```bash
   cp .env.example .env
   # Edit .env and add your key
   ```

## Running the Demo

### Full pipeline (single run):
```bash
python demo/run_demo.py
```

### Step-by-step with explanations:
```bash
python demo/run_demo.py --step-by-step
```

### JSON output:
```bash
python demo/run_demo.py --format json
```

## The Scenario

- **Incident ID**: IR-2026-0219
- **Victim**: Pinnacle Manufacturing Corp (Manufacturing, US Midwest)
- **Attack Timeline**: ~4 hours from initial access to ransomware deployment
- **Key Artifacts**:
  - Ransom note with TOR payment portal
  - 3 file hashes (ransomware binary, batch script, renamed rclone)
  - 3 C2 IP addresses
  - 3 persistence mechanisms (scheduled tasks, registry)
  - 6 lateral movement events (RDP, PsExec, WMI)
  - 6 LOLBAS observations

**All data is completely fabricated. No real victim or threat actor data is used.**

## MCP Server Demo

To demo via Claude Desktop:

1. Start the MCP server:
   ```bash
   ransomware-mcp
   ```

2. In Claude Desktop, use tools like:
   - "Match this ransom note against known groups"
   - "Correlate these TTPs: RDP lateral movement, vssadmin shadow copies deleted"
   - "Generate a full IR brief for this incident"
   - "What's the current threat landscape for Manufacturing in the US?"
