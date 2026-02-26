# MCP Server Setup for Claude Desktop

## Overview

The MCP (Model Context Protocol) server exposes all ransomware intelligence tools to Claude Desktop and Claude Code, allowing natural language interaction with the intelligence database.

## Claude Desktop Configuration

### macOS

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ransomware-intel": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/path/to/ransomware-intel-agent",
      "env": {
        "RANSOMWARE_LIVE_PRO_KEY": "your_pro_api_key_here",
        "OLLAMA_BASE_URL": "http://localhost:11434"
      }
    }
  }
}
```

### Windows

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ransomware-intel": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "C:\\path\\to\\ransomware-intel-agent",
      "env": {
        "RANSOMWARE_LIVE_PRO_KEY": "your_pro_api_key_here"
      }
    }
  }
}
```

### Linux

Edit `~/.config/Claude/claude_desktop_config.json` with the same format as macOS.

## Claude Code Configuration

Add to your project's `.mcp.json` or global MCP config:

```json
{
  "mcpServers": {
    "ransomware-intel": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/path/to/ransomware-intel-agent"
    }
  }
}
```

## Verify It Works

After restarting Claude Desktop, you should see the ransomware tools available. Try these prompts:

### Basic queries (Free API — no key needed)
- "Get the profile of the lockbit3 ransomware group"
- "Search for manufacturing sector victims"
- "Get YARA rules for the akira ransomware group"
- "What are the most recent ransomware victims?"

### Advanced queries (PRO API key required)
- "Match this ransom note against known groups: [paste note text]"
- "Look up these IOCs: 185.220.101.42, sha256:abc123..."
- "What TTPs does the alphv group use?"
- "Get negotiation intelligence for lockbit3"

### Full pipeline
- "Generate an IR brief for incident IR-2026-0219 with these artifacts: [provide details]"
- "Assess the ransomware threat landscape for the Healthcare sector in the United States"

## Available Tools

Once connected, Claude has access to 12 tools:

1. **match_ransom_note** — Embedding similarity matching
2. **lookup_iocs** — Hash/IP/domain database lookup
3. **get_negotiation_intel** — Demand and discount analysis
4. **get_group_profile** — Group intelligence
5. **get_group_ttps** — MITRE ATT&CK mappings
6. **get_group_yara** — Detection rules
7. **search_victims** — Filtered victim search
8. **get_recent_victims** — Trend analysis
9. **correlate_ttps** — TTP-based attribution
10. **generate_ir_brief** — Full attribution pipeline
11. **assess_threat_landscape** — Proactive hunting
12. **get_8k_filings** — SEC disclosure search
