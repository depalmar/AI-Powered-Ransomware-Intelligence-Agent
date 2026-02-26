# Velociraptor Integration

## Overview

This integration connects Velociraptor's endpoint forensic collection to the Ransomware Intelligence Agent for automated analysis and enrichment.

## Components

### `artifact_collector.yaml`
A VQL artifact definition that collects ransomware indicators from endpoints:
- Ransom note files (by common filenames)
- File hashes from suspicious directories
- Scheduled tasks (persistence)
- Registry Run keys (persistence)
- Active network connections
- Process tree with hashes

### `adapter.py`
Python adapter that normalizes Velociraptor output and feeds it to the agent.

## Setup

1. **Import the artifact** into your Velociraptor server:
   - Navigate to **Server Artifacts** → **Add Custom Artifact**
   - Paste the contents of `artifact_collector.yaml`

2. **Run a hunt** using the `Custom.Ransomware.IndicatorCollector` artifact

3. **Export results** as JSON and process through the adapter:

```python
from integrations.velociraptor.adapter import VelociraptorAdapter

adapter = VelociraptorAdapter()
result = await adapter.process_file("hunt_results.json", incident_id="IR-2026-0001")
print(result["brief"])
```

## Hunt Parameters

| Parameter | Description | Default |
|---|---|---|
| `RansomNotePatterns` | Glob patterns for ransom note files | Common ransom note filenames |
| `SuspiciousDirectories` | Directories to hash for suspicious binaries | ProgramData, Temp, Public |
| `CollectProcessTree` | Include running process tree | Yes |
| `CollectNetworkConnections` | Include active network connections | Yes |
