# Architecture

## System Overview

The Ransomware Intelligence Agent is built as three complementary components that share a common core:

```
                    ┌─────────────────┐
                    │  Claude Desktop  │
                    │  / Claude Code   │
                    └────────┬────────┘
                             │ MCP Protocol
                    ┌────────▼────────┐
                    │  Option A:       │
                    │  FastMCP Server  │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼──────┐   ┌────────▼───────┐   ┌───────▼──────┐
│  Tool Layer  │   │  API Client    │   │  Embedding   │
│  (12 tools)  │   │  (free + PRO)  │   │  Layer       │
└───────┬──────┘   └────────────────┘   └──────────────┘
        │
┌───────▼──────────────┐
│  Confidence Scoring  │
│  (4-signal weighted) │
└──────────────────────┘
```

## Data Flow

### Attribution Pipeline

```
Input Artifacts
    │
    ├── Ransom Note ──→ Embedding Match ──→ Top 3 Group Candidates
    │
    ├── Hashes/IPs ───→ IOC Lookup ──────→ Matched/Unmatched IOCs
    │
    ├── TTPs/LOLBAS ──→ MITRE Mapping ──→ Technique-Based Group Ranking
    │
    └── File Extension → Extension Match → Group Association
                │
                ▼
        Confidence Scoring (weighted composite)
                │
                ▼
        Enrichment (profile, negotiations, YARA)
                │
                ▼
        IR Brief Generation (Jinja2 template)
```

### Confidence Scoring Model

Each signal produces a raw score (0.0-1.0) that is multiplied by its weight:

| Signal | Weight | Rationale |
|---|---|---|
| Ransom Note | 0.35 | Strongest individual indicator — directly tied to group identity |
| IOC Overlap | 0.30 | Infrastructure reuse is a strong signal but can be shared/sold |
| TTP Alignment | 0.20 | Techniques overlap between groups; useful but not definitive |
| File Extension | 0.15 | Many groups use generic extensions; custom ones are informative |

**Composite Score** = Σ(raw_score × weight), capped at 1.0

**Labels:**
- ≥ 80%: High
- ≥ 60%: Medium
- ≥ 40%: Low
- < 40%: Insufficient

## Component Details

### API Client (`mcp_server/api/`)

- `client.py`: Base async HTTP client with rate limiting (token bucket) and exponential backoff retries
- `free_api.py`: Public endpoints (groups, victims, YARA) — no key required
- `pro_api.py`: PRO endpoints (IOCs, TTPs, negotiations, ransom notes, SEC filings) — key required

### Embedding Layer (`mcp_server/embeddings/`)

- `embed.py`: Ollama nomic-embed-text integration with cosine similarity + keyword fallback
- `vector_store.py`: ChromaDB persistence for pre-embedded ransom notes
- `note_index.py`: Batch indexing of all known ransom notes from the API

### LangGraph Agent (`langgraph_agent/`)

Linear state graph with 7 nodes:

```
parse_artifacts → match_note → search_iocs → correlate_ttps →
attribute_group → enrich_intel → generate_brief
```

Each node:
- Reads from and writes to a shared `AgentState` TypedDict
- Can be called independently as an async function
- Handles errors gracefully and appends to the `errors` list

### Integration Adapters (`integrations/`)

Each adapter follows the same pattern:
1. Accept platform-specific input (VQL results, osquery JSON, SIEM alert)
2. Normalize to `IncidentArtifacts` Pydantic model
3. Feed to the attribution pipeline
4. Return enriched results in the platform's expected format

## Technology Choices

| Choice | Rationale |
|---|---|
| FastMCP | Official MCP framework; direct Claude Desktop integration |
| httpx | Modern async HTTP; better than requests for concurrent API calls |
| Pydantic v2 | Type safety for all data flowing through the system |
| ChromaDB | Simple embedded vector store; no external service needed |
| Ollama | Local inference; works offline; no API costs for embeddings |
| Jinja2 | Industry-standard templating; readable templates |
| LangGraph | Explicit state graph; better than chain-of-thought for pipeline |
