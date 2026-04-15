# CLAUDE.md

Guidance for AI assistants (Claude Code and others) working in this repository.

## What This Project Is

**AI-Powered Ransomware Intelligence Agent** — a collection of **n8n workflows** (distributed as JSON) that automate ransomware threat intelligence: poll leak-site feeds, run LLM-backed analysis, and emit rich HTML/Slack/Google Doc reports. It is a companion to the SANS Ransomware Intelligence Webinar.

This repository is **not a traditional application**. It is primarily:

1. **n8n workflow JSON** (the product)
2. A **mock API server** used for offline demos
3. **Python tests** that validate the workflow JSON files
4. **Sample outputs** and documentation

There is no build step, no package manager manifest, no installable library. "Running" the project means importing a workflow into n8n.

## Repository Layout

```
.
├── n8n_workflows/          # The product — workflow JSON files
│   ├── 101_ransomware_threat_monitor.json         # 101 (Claude Sonnet)
│   ├── 101_ransomware_threat_monitor_ollama.json  # 101 (local LLM via Ollama)
│   ├── 101_ransomware_threat_monitor_DEMO.json    # 101 wired to mock_api
│   ├── 200_ransomware_intel_advanced.json         # 200 (Claude, IOC enrichment, YARA, email)
│   ├── 200_ransomware_intel_advanced_ollama.json  # 200 (Ollama variant)
│   └── README.md
├── mock_api/               # Offline demo API (stdlib-only Python)
│   ├── server.py           # http.server on port 3000
│   ├── data/recentvictims.json
│   └── data/groups/{lockbit3,play,blackbasta}.json
├── tests/
│   └── test_workflows.py   # pytest suite that validates all workflow JSON
├── scripts/
│   └── validate_workflows.py  # Standalone validator (usable as pre-commit hook)
├── examples/               # Sample outputs (HTML, Markdown, Slack text, PDF)
├── screenshots/            # README imagery
├── .github/workflows/
│   └── validate-workflows.yml  # CI: runs pytest on workflow-related changes
├── run_demo.bat            # Windows shortcut that launches mock_api/server.py
├── README.md
└── LICENSE                 # CC BY-NC 4.0
```

## Workflow Tiers (101 vs 200)

| Level | LLM | Adds over prior tier |
|-------|-----|----------------------|
| 101   | Claude Sonnet OR Ollama | Fetch → filter → AI analysis → HTML + Slack + optional Google Doc |
| 200   | Claude Sonnet OR Ollama | + IOC enrichment (VirusTotal, AbuseIPDB), YARA rule generation, historical trending, email, JIRA, confidence scoring |

**101 pipeline shape:**
```
Schedule (6h) → Fetch Victims API → Redact Identities → Filter by Industry
   → Deduplicate by Group → Fetch Group Profiles → Build Consolidated Brief
   → AI Threat Analysis → Enhance Brief → HTML + Slack + Google Doc
```

**"DEMO" variant** of 101 points at `http://localhost:3000` (the mock API in `mock_api/`) instead of `https://api.ransomware.live`.

**Do not introduce "300-level" workflows.** That tier was removed and `test_no_300_level_references` will fail if `"300"` appears in a workflow `name`.

## Development Workflows

### Validating workflow JSON (the main dev loop)

Any change to `n8n_workflows/*.json` MUST pass the test suite. The GitHub Actions workflow `.github/workflows/validate-workflows.yml` runs pytest on every push/PR that touches workflow or test files.

```bash
pip install pytest
pytest tests/ -v
```

Or the standalone validator (no pytest dependency, can be installed as `.git/hooks/pre-commit`):

```bash
python scripts/validate_workflows.py
```

Both check: valid JSON, required top-level keys (`name`, `nodes`, `connections`), no duplicate node names, no dead-end nodes, no orphan nodes, connection targets/sources exist.

### Running the mock API

```bash
python mock_api/server.py
# serves on :3000, no dependencies — stdlib only
```

Endpoints:
- `GET /v2/recentvictims` — returns 24 canned victims (LockBit 3.0, Play, BlackBasta)
- `GET /v2/groups/{name}` — returns static profile if `mock_api/data/groups/{name}.json` exists, otherwise a generic placeholder

Use with `101_ransomware_threat_monitor_DEMO.json` for offline demos. Windows users can run `run_demo.bat`.

### Running n8n workflows

There is no automated harness — workflows run inside n8n. Manual flow:

1. Import the JSON into an n8n instance (`Workflows → Add Workflow → Import from File`)
2. Configure credentials (Anthropic / Ollama / Slack / Google Docs / VirusTotal / AbuseIPDB / SMTP / JIRA depending on tier)
3. Customize the `Filter by Industry` node with target sectors
4. Trigger manually to test

## Invariants the Test Suite Enforces

When editing workflow JSON, these rules WILL break CI if violated. Each exists because a past bug hit it.

### Structural
- **`name`, `nodes`, `connections` top-level keys required.**
- **No duplicate node names** (excluding sticky notes).
- **No empty node names.**
- **Connection targets and sources must reference real node names.**

### Connectivity
- **No dead-end nodes** — a node that is a connection target but never a source. Exceptions (allowed to be terminal):
  - Types: `slack`, `gmail`, `emailSend`, `googleDocs`, `httpRequest`, `respondToWebhook`, `noOp`
  - AI sub-node types: `lmChatAnthropic`, `lmChatOllama`, `lmChatOpenAi`, `outputParserStructured` (they connect via `ai_*` ports, not main flow)
  - Name starts with: `Output HTML File`, `Output Markdown File`, `No Activity Detected`
- **No orphan nodes** — non-trigger nodes that are neither sources nor targets. Triggers (`scheduleTrigger`, `manualTrigger`, `webhook`, `cronTrigger`) and AI sub-nodes are exempt.

### Credentials
- **No empty credential IDs.** Any node's `credentials.<type>.id` must be non-empty. n8n rejects execution when this breaks — check `test_no_empty_credential_ids`.

### Models
- **No banned / deprecated model strings** anywhere in the JSON:
  - `claude-opus-4-20250514`
  - `claude-3-opus`, `claude-3-sonnet`, `claude-3-haiku`
- Project standard is **Claude Sonnet** (current ID). Keep Claude/Ollama variants in sync on structure; only swap the LLM sub-node.

### Content hygiene
- **No `"PRIVATE WEBINAR"` strings** — past leaks of sticky-note labels meant for private builds.
- **No `"300"` in workflow names** — that tier was removed.

### JavaScript Code-node integrity
Historical bugs came from bash interpolation eating JS source when workflows were built via shell heredocs. These checks prevent recurrence:
- **No `\.all()` or `\.first()`** — these are corrupted `$input.all()` / `$input.first()` references.
- **No empty assignments** like `const x = ;` / `let x = ;` — template literals were swallowed.
- **Backticks must be balanced** (even count) in every Code node's `jsCode`.

When writing new JS for Code nodes, use `$input.all()` / `$input.first()` and template literals normally — just make sure whatever generated the JSON preserved them.

## Conventions

- **Commit messages** follow conventional-commit-ish style: `feat:`, `fix:`, `docs:`, `chore:`. See `git log` for examples (`fix: resolve AI Agent empty prompt…`, `feat: add workflow test suite…`).
- **Workflow JSON is human-edited in n8n and exported.** Prefer editing inside n8n and re-exporting over hand-patching JSON, unless the fix is surgical (renaming, removing a banned string, fixing a typo in `jsCode`).
- **Keep Claude and Ollama variants parallel.** If you add a node to `101_ransomware_threat_monitor.json`, mirror it in `101_ransomware_threat_monitor_ollama.json` (and the DEMO variant when relevant). Same for 200-level.
- **Python in `mock_api/` uses only the standard library.** Do not add dependencies — the point is zero-setup demos.
- **Tests use pytest with parameterized fixtures** (`tests/test_workflows.py`). New validation rules should be added as test methods there, not as separate scripts, so CI picks them up automatically. Mirror new rules into `scripts/validate_workflows.py` when they're cheap to port, since that script doubles as a pre-commit hook.

## Things NOT to Do

- **Do not create documentation files unprompted.** README, workflow READMEs, and this file are sufficient. No new `*.md` unless requested.
- **Do not add features or refactor workflows beyond the task.** The workflows are tuned for webinar demos — incidental "improvements" can break the golden sample match with `mock_api/` data.
- **Do not add a package manager, build system, or dependency on non-stdlib Python** for anything in `mock_api/` or `scripts/`.
- **Do not reintroduce deprecated model IDs** or 300-level references.
- **Do not commit `.env` files, API keys, or the files listed in `.gitignore`** (e.g. `examples/Gamma_Presentation_Recipe_v2.md`, `examples/QA_Instructor_Guide.md` — these are intentionally local-only).

## License

CC BY-NC 4.0 — educational / defensive use with attribution. Non-commercial.
