# osquery Integration

## Overview

Fleet-wide ransomware indicator detection using osquery, with automated enrichment through the Ransomware Intelligence Agent.

## Components

### `ransomware_pack.conf`
An osquery query pack with 8 queries targeting ransomware indicators:

| Query | Interval | Description |
|---|---|---|
| `ransomware_scheduled_tasks` | 5 min | Suspicious scheduled tasks |
| `ransomware_registry_run_keys` | 5 min | Registry Run key persistence |
| `suspicious_network_connections` | 1 min | Outbound connections from non-standard paths |
| `suspicious_executables` | 10 min | Executables in suspicious directories |
| `ransomware_file_extensions` | 5 min | Files with known ransomware extensions |
| `shadow_copy_status` | 10 min | VSS service status |
| `loaded_modules_suspicious` | 10 min | Modules loaded from suspicious paths |
| `recently_created_services` | 5 min | Services running from suspicious paths |

### `adapter.py`
Python adapter that normalizes osquery JSON output and feeds it to the agent.

## Setup

### Deploy the query pack

**Fleet/Kolide:**
```bash
fleetctl apply -f integrations/osquery/ransomware_pack.conf
```

**Direct osqueryd:**
```bash
osqueryd --config_path /etc/osquery/osquery.conf \
  --pack_path integrations/osquery/ransomware_pack.conf
```

### Process results

```python
from integrations.osquery.adapter import OsqueryAdapter

adapter = OsqueryAdapter()

# Single host
result = await adapter.process_file("osquery_results.json")
print(result["brief"])

# Fleet-wide (multiple hosts)
fleet_results = [
    {"hostname": "srv-dc01", "results": {...}},
    {"hostname": "srv-file01", "results": {...}},
]
results = await adapter.process_bulk(fleet_results, incident_id="IR-2026-001")
```
