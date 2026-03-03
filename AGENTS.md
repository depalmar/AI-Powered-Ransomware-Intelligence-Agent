# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

This is an **n8n workflow project** (not a traditional app). There is no source code to lint, compile, or unit-test in the conventional sense. The product is a set of n8n workflow JSON files plus a Python mock API server.

See `README.md` for full architecture and prerequisites.

### Services

| Service | Command | Port | Notes |
|---------|---------|------|-------|
| **Mock API** | `python3 mock_api/server.py` | 3000 | Python stdlib only; no pip install needed |
| **n8n** | `n8n start` | 5678 | Install globally: `npm install -g n8n` |

### Running the demo workflow

1. Start the mock API server: `python3 mock_api/server.py &`
2. Start n8n: `N8N_DIAGNOSTICS_ENABLED=false n8n start &`
3. Open `http://localhost:5678`, create an owner account, and import `n8n_workflows/101_ransomware_threat_monitor_DEMO.json`.
4. The workflow connects to the mock API at `localhost:3000`.

### Known caveats

- **IPv6 / IPv4 mismatch:** n8n resolves `localhost` to `::1` (IPv6), but Python's `socketserver.TCPServer` binds to IPv4 only. After importing the DEMO workflow into n8n, change URLs from `localhost:3000` to `127.0.0.1:3000` inside the HTTP Request nodes, or the requests will fail with "connection refused."
- **Anthropic API key required for full run:** The "Claude Model" node needs a valid Anthropic API key configured in n8n credentials. Without it, the workflow succeeds through data fetch/redact/filter/group/enrich stages but fails at the AI analysis step.
- **Slack and Google Docs nodes are deactivated** by default in both workflow files — they won't block execution.
- **No lint/test/build commands exist.** There are no `package.json`, `requirements.txt`, test frameworks, or CI pipelines in this repo.
