#!/usr/bin/env python3
"""
Quick local workflow validator — run before committing.

Usage:
    python scripts/validate_workflows.py
    # or as a pre-commit hook:
    #   cp scripts/validate_workflows.py .git/hooks/pre-commit

Exit code 0 = all checks pass, 1 = failures found.
"""

import json
import glob
import sys
import os

WORKFLOW_DIR = os.path.join(os.path.dirname(__file__), "..", "n8n_workflows")

TERMINAL_NODE_TYPES = {
    "n8n-nodes-base.slack",
    "n8n-nodes-base.gmail",
    "n8n-nodes-base.emailSend",
    "n8n-nodes-base.googleDocs",
    "n8n-nodes-base.httpRequest",
    "n8n-nodes-base.respondToWebhook",
    "n8n-nodes-base.noOp",
}

TERMINAL_NODE_NAME_PATTERNS = {
    "Output HTML File",
    "Output Markdown File",
    "No Activity Detected",
}

AI_SUB_NODE_TYPES = {
    "@n8n/n8n-nodes-langchain.lmChatAnthropic",
    "@n8n/n8n-nodes-langchain.lmChatOllama",
    "@n8n/n8n-nodes-langchain.outputParserStructured",
    "@n8n/n8n-nodes-langchain.lmChatOpenAi",
}

SKIP_NODE_TYPES = {"n8n-nodes-base.stickyNote"}

TRIGGER_TYPES = {
    "n8n-nodes-base.scheduleTrigger",
    "n8n-nodes-base.manualTrigger",
    "n8n-nodes-base.webhook",
    "n8n-nodes-base.cronTrigger",
}


def validate_file(path):
    errors = []
    fname = os.path.basename(path)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return [f"{fname}: invalid JSON — {e}"]

    # Required keys
    for key in ("name", "nodes", "connections"):
        if key not in data:
            errors.append(f"{fname}: missing required key '{key}'")

    nodes = {
        n["name"]: n["type"]
        for n in data.get("nodes", [])
        if n.get("type") not in SKIP_NODE_TYPES
    }

    # Duplicate names
    names = [n["name"] for n in data.get("nodes", []) if n.get("type") not in SKIP_NODE_TYPES]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        errors.append(f"{fname}: duplicate node names: {dupes}")

    # Connection analysis
    connections = data.get("connections", {})
    sources = set(connections.keys())
    targets = set()
    for src, type_map in connections.items():
        if src not in {n["name"] for n in data.get("nodes", [])}:
            errors.append(f"{fname}: connection source '{src}' not found in nodes")
        for conn_type, outputs in type_map.items():
            for output_arr in outputs:
                for conn in output_arr:
                    targets.add(conn["node"])
                    if conn["node"] not in {n["name"] for n in data.get("nodes", [])}:
                        errors.append(f"{fname}: connection target '{conn['node']}' not found")

    # Dead-end detection
    for name, ntype in nodes.items():
        if ntype in TERMINAL_NODE_TYPES or ntype in AI_SUB_NODE_TYPES:
            continue
        if any(name.startswith(pat) for pat in TERMINAL_NODE_NAME_PATTERNS):
            continue
        if name in targets and name not in sources:
            errors.append(f"{fname}: DEAD-END node '{name}' (receives data, sends nothing)")

    # Orphan detection
    for name, ntype in nodes.items():
        if ntype in TRIGGER_TYPES or ntype in AI_SUB_NODE_TYPES:
            continue
        if name not in sources and name not in targets:
            errors.append(f"{fname}: ORPHAN node '{name}' (completely disconnected)")

    return errors


def main():
    files = sorted(glob.glob(os.path.join(WORKFLOW_DIR, "*.json")))
    if not files:
        print("No workflow JSON files found!")
        sys.exit(1)

    all_errors = []
    for path in files:
        errs = validate_file(path)
        fname = os.path.basename(path)
        if errs:
            print(f"  FAIL  {fname}")
            for e in errs:
                print(f"        {e}")
            all_errors.extend(errs)
        else:
            nodes = json.load(open(path, encoding="utf-8"))
            nc = len([n for n in nodes.get("nodes", []) if n.get("type") not in SKIP_NODE_TYPES])
            cc = len(nodes.get("connections", {}))
            print(f"  PASS  {fname} ({nc} nodes, {cc} connections)")

    print()
    if all_errors:
        print(f"FAILED: {len(all_errors)} error(s) found across {len(files)} files")
        sys.exit(1)
    else:
        print(f"ALL PASSED: {len(files)} workflow files validated successfully")
        sys.exit(0)


if __name__ == "__main__":
    main()
