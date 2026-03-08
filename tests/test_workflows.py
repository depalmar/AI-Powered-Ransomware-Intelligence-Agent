"""
n8n Workflow Validation Test Suite
===================================
Catches structural bugs in workflow JSON files:
- Invalid JSON
- Missing required n8n keys
- Dead-end nodes (nodes that receive data but send nothing)
- Orphan nodes (no connections at all, excluding sticky notes)
- Duplicate node names
- Empty node names
- Invalid connection targets (point to non-existent nodes)
- Model reference checks (no deprecated or wrong model IDs)

Run:  pytest tests/ -v
"""

import json
import glob
import os
import re
import pytest

WORKFLOW_DIR = os.path.join(os.path.dirname(__file__), "..", "n8n_workflows")

# Terminal nodes that are legitimate dead ends (output-only)
TERMINAL_NODE_TYPES = {
    "n8n-nodes-base.slack",
    "n8n-nodes-base.gmail",
    "n8n-nodes-base.emailSend",
    "n8n-nodes-base.googleDocs",
    "n8n-nodes-base.httpRequest",       # can be terminal for webhooks
    "n8n-nodes-base.respondToWebhook",
    "n8n-nodes-base.noOp",
}

# Node name patterns that are legitimate dead ends (code nodes acting as outputs)
TERMINAL_NODE_NAME_PATTERNS = {
    "Output HTML File",
    "Output Markdown File",
    "No Activity Detected",  # "else" branch of IF — nothing to do
}

# Sub-node types that connect via ai_* ports (not main flow)
AI_SUB_NODE_TYPES = {
    "@n8n/n8n-nodes-langchain.lmChatAnthropic",
    "@n8n/n8n-nodes-langchain.lmChatOllama",
    "@n8n/n8n-nodes-langchain.outputParserStructured",
    "@n8n/n8n-nodes-langchain.lmChatOpenAi",
}

# Node types to skip in connection analysis
SKIP_NODE_TYPES = {
    "n8n-nodes-base.stickyNote",
}

# Deprecated or invalid model strings
BANNED_MODEL_STRINGS = [
    "claude-opus-4-20250514",       # old Opus — project uses Sonnet now
    "claude-3-opus",
    "claude-3-sonnet",
    "claude-3-haiku",
]


def get_workflow_files():
    """Discover all workflow JSON files."""
    pattern = os.path.join(WORKFLOW_DIR, "*.json")
    files = sorted(glob.glob(pattern))
    assert files, f"No workflow JSON files found in {WORKFLOW_DIR}"
    return files


def load_workflow(path):
    """Load and parse a workflow JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(params=get_workflow_files(), ids=lambda p: os.path.basename(p))
def workflow_file(request):
    """Parameterized fixture: yields (path, data) for each workflow."""
    path = request.param
    data = load_workflow(path)
    return path, data


# ---------------------------------------------------------------------------
# Test: Valid JSON and required keys
# ---------------------------------------------------------------------------

class TestBasicStructure:

    def test_has_required_keys(self, workflow_file):
        path, data = workflow_file
        for key in ("name", "nodes", "connections"):
            assert key in data, f"{os.path.basename(path)}: missing required key '{key}'"

    def test_has_at_least_one_node(self, workflow_file):
        path, data = workflow_file
        nodes = data.get("nodes", [])
        assert len(nodes) > 0, f"{os.path.basename(path)}: workflow has zero nodes"

    def test_no_empty_node_names(self, workflow_file):
        path, data = workflow_file
        for node in data.get("nodes", []):
            name = node.get("name", "")
            assert name.strip(), (
                f"{os.path.basename(path)}: node has empty name (type={node.get('type')})"
            )

    def test_no_duplicate_node_names(self, workflow_file):
        path, data = workflow_file
        names = [n["name"] for n in data.get("nodes", []) if n.get("type") not in SKIP_NODE_TYPES]
        dupes = [n for n in names if names.count(n) > 1]
        assert not dupes, (
            f"{os.path.basename(path)}: duplicate node names: {set(dupes)}"
        )


# ---------------------------------------------------------------------------
# Test: Connection integrity
# ---------------------------------------------------------------------------

class TestConnections:

    def _get_non_skip_nodes(self, data):
        """Return dict of name -> type for non-sticky nodes."""
        return {
            n["name"]: n["type"]
            for n in data.get("nodes", [])
            if n.get("type") not in SKIP_NODE_TYPES
        }

    def _get_connection_sources(self, data):
        """Return set of all node names that appear as connection sources."""
        return set(data.get("connections", {}).keys())

    def _get_connection_targets(self, data):
        """Return set of all node names that appear as connection targets."""
        targets = set()
        for src, type_map in data.get("connections", {}).items():
            for conn_type, outputs in type_map.items():
                for output_arr in outputs:
                    for conn in output_arr:
                        targets.add(conn["node"])
        return targets

    def test_no_dead_end_nodes(self, workflow_file):
        """
        Dead-end = node receives data (is a target) but never sends data
        (not a source). Excludes terminal outputs and AI sub-nodes.
        THIS IS THE TEST THAT WOULD HAVE CAUGHT THE BUG WE JUST FIXED.
        """
        path, data = workflow_file
        nodes = self._get_non_skip_nodes(data)
        sources = self._get_connection_sources(data)
        targets = self._get_connection_targets(data)

        dead_ends = []
        for name, ntype in nodes.items():
            if ntype in TERMINAL_NODE_TYPES:
                continue
            if ntype in AI_SUB_NODE_TYPES:
                continue
            # Check name-based terminal patterns (e.g. "No Activity Detected1")
            if any(name.startswith(pat) for pat in TERMINAL_NODE_NAME_PATTERNS):
                continue
            # Node is a target but NOT a source → dead end
            if name in targets and name not in sources:
                dead_ends.append(name)

        assert not dead_ends, (
            f"{os.path.basename(path)}: dead-end nodes (receive data but send nothing): "
            f"{dead_ends}"
        )

    def test_no_orphan_nodes(self, workflow_file):
        """
        Orphan = non-trigger node that is neither a source nor a target.
        Trigger nodes (Schedule, Webhook, Manual) are allowed to have no incoming.
        """
        path, data = workflow_file
        nodes = self._get_non_skip_nodes(data)
        sources = self._get_connection_sources(data)
        targets = self._get_connection_targets(data)

        trigger_types = {
            "n8n-nodes-base.scheduleTrigger",
            "n8n-nodes-base.manualTrigger",
            "n8n-nodes-base.webhook",
            "n8n-nodes-base.cronTrigger",
        }

        orphans = []
        for name, ntype in nodes.items():
            if ntype in trigger_types:
                continue
            if ntype in AI_SUB_NODE_TYPES:
                continue
            if name not in sources and name not in targets:
                orphans.append(name)

        assert not orphans, (
            f"{os.path.basename(path)}: orphan nodes (completely disconnected): "
            f"{orphans}"
        )

    def test_connection_targets_exist(self, workflow_file):
        """Every connection target must reference an actual node name."""
        path, data = workflow_file
        node_names = {n["name"] for n in data.get("nodes", [])}

        missing = []
        for src, type_map in data.get("connections", {}).items():
            for conn_type, outputs in type_map.items():
                for output_arr in outputs:
                    for conn in output_arr:
                        if conn["node"] not in node_names:
                            missing.append(f"{src} -> {conn['node']}")

        assert not missing, (
            f"{os.path.basename(path)}: connections point to non-existent nodes: "
            f"{missing}"
        )

    def test_connection_sources_exist(self, workflow_file):
        """Every connection source must reference an actual node name."""
        path, data = workflow_file
        node_names = {n["name"] for n in data.get("nodes", [])}
        connections = data.get("connections", {})

        missing = [src for src in connections if src not in node_names]
        assert not missing, (
            f"{os.path.basename(path)}: connection sources reference non-existent nodes: "
            f"{missing}"
        )


# ---------------------------------------------------------------------------
# Test: Model references
# ---------------------------------------------------------------------------

class TestModelReferences:

    def test_no_banned_model_strings(self, workflow_file):
        """Check that no deprecated model IDs appear in the workflow."""
        path, data = workflow_file
        raw = json.dumps(data)
        found = [m for m in BANNED_MODEL_STRINGS if m in raw]
        assert not found, (
            f"{os.path.basename(path)}: contains deprecated model references: {found}"
        )


# ---------------------------------------------------------------------------
# Test: Content checks
# ---------------------------------------------------------------------------

class TestContentChecks:

    def test_no_private_labels(self, workflow_file):
        """Ensure no 'PRIVATE' labels leaked into workflow names/descriptions."""
        path, data = workflow_file
        raw = json.dumps(data).upper()
        assert "PRIVATE WEBINAR" not in raw, (
            f"{os.path.basename(path)}: contains 'PRIVATE WEBINAR' label"
        )

    def test_no_300_level_references(self, workflow_file):
        """300-level workflows were removed; no references should remain."""
        path, data = workflow_file
        name = data.get("name", "")
        assert "300" not in name, (
            f"{os.path.basename(path)}: workflow name references removed 300-level"
        )

    def test_no_empty_credential_ids(self, workflow_file):
        """
        Credentials with empty IDs cause n8n to reject the workflow at execution time.
        THIS TEST CATCHES THE BUG WHERE n8n REFUSED TO EXECUTE DUE TO EMPTY CRED IDS.
        """
        path, data = workflow_file
        broken = []
        for node in data.get("nodes", []):
            name = node.get("name", "?")
            creds = node.get("credentials", {})
            for cred_type, cred_val in creds.items():
                if isinstance(cred_val, dict) and not cred_val.get("id"):
                    broken.append(f"{name}: credential '{cred_type}' has empty id")
        assert not broken, (
            f"{os.path.basename(path)}: empty credential IDs block execution: {broken}"
        )


# ---------------------------------------------------------------------------
# Test: JavaScript code node integrity
# ---------------------------------------------------------------------------

class TestJsCodeIntegrity:
    """Catch corrupted JavaScript in Code nodes (e.g. bash eating $input)."""

    def _get_code_nodes(self, data):
        """Return list of (name, jsCode) for all Code nodes."""
        result = []
        for node in data.get("nodes", []):
            if node.get("type") == "n8n-nodes-base.code":
                code = node.get("parameters", {}).get("jsCode", "")
                result.append((node.get("name", "?"), code))
        return result

    def test_no_corrupted_input_refs(self, workflow_file):
        """
        Bash interpolation can eat $input, leaving \\.all() or \\.first().
        THIS TEST CATCHES THE BUG WHERE BASH CONSUMED $input REFERENCES.
        """
        path, data = workflow_file
        broken = []
        for name, code in self._get_code_nodes(data):
            if "\\.all()" in code:
                broken.append(f"{name}: has '\\.all()' (should be '$input.all()')")
            if "\\.first()" in code:
                broken.append(f"{name}: has '\\.first()' (should be '$input.first()')")
        assert not broken, (
            f"{os.path.basename(path)}: corrupted $input references: {broken}"
        )

    def test_no_empty_assignments(self, workflow_file):
        """
        Bash interpolation can eat template literals, leaving 'const x = ;'.
        THIS TEST CATCHES THE BUG WHERE BASH CONSUMED TEMPLATE LITERALS.
        """
        path, data = workflow_file
        broken = []
        for name, code in self._get_code_nodes(data):
            for line in code.split("\\n"):
                stripped = line.strip()
                if stripped.startswith("const ") and stripped.endswith("= ;"):
                    broken.append(f"{name}: empty assignment '{stripped}'")
                if stripped.startswith("let ") and stripped.endswith("= ;"):
                    broken.append(f"{name}: empty assignment '{stripped}'")
        assert not broken, (
            f"{os.path.basename(path)}: empty assignments (template literals lost): {broken}"
        )

    def test_balanced_backticks(self, workflow_file):
        """Template literals need matched backticks."""
        path, data = workflow_file
        broken = []
        for name, code in self._get_code_nodes(data):
            count = code.count("`")
            if count % 2 != 0:
                broken.append(f"{name}: {count} backticks (odd = unmatched)")
        assert not broken, (
            f"{os.path.basename(path)}: unbalanced backticks in Code nodes: {broken}"
        )
