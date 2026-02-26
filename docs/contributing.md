# Contributing

This project is part of the [ai_for_the_win](https://github.com/depalmar/ai_for_the_win) training repository. Contributions from DFIR practitioners are welcome.

## Development Setup

```bash
git clone https://github.com/depalmar/ransomware-intel-agent.git
cd ransomware-intel-agent
pip install -e ".[all]"
```

## Running Tests

```bash
pytest
pytest -v  # verbose
pytest tests/test_confidence_scoring.py  # specific file
```

## Code Standards

- **Python 3.11+** with type hints on all public functions
- **Pydantic v2** models for all data structures
- **Google-style docstrings** on all public functions
- **No print statements** — use `logging` module
- **Async** for all I/O operations
- **Lint** with `ruff check .`

## Adding a New Tool

1. Create the tool implementation in `mcp_server/tools/new_tool.py`
2. Add any new Pydantic models to `mcp_server/models.py`
3. Register the tool in `mcp_server/server.py` with `@mcp.tool()`
4. Add a corresponding node in `langgraph_agent/nodes/` if needed
5. Write tests in `tests/test_new_tool.py`
6. Update `README.md` tool table

## Adding a New Integration

1. Create a directory under `integrations/`
2. Include an `adapter.py` that normalizes to `IncidentArtifacts`
3. Include a `README.md` with setup instructions
4. Add example configurations/payloads

## Important Guidelines

- **No real victim data** in any test fixtures, demos, or examples
- **All demo data must be fabricated** — fake companies, fake hashes, fake IPs
- **Graceful degradation** — every feature must work without PRO API or Ollama
- **Keep it simple** — this is educational tooling for DFIR practitioners
