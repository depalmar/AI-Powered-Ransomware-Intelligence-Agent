# Expected Demo Output

This document shows what the demo should produce when run against the simulated incident in `scenario.json`.

## What Happens

1. **Incident Loading**: The demo loads `scenario.json` with the Pinnacle Manufacturing Corp incident.

2. **Ransom Note Analysis**: The ransom note is compared against known group notes.
   - With Ollama running: embedding similarity search returns top 3 matches
   - Without Ollama: keyword-based fallback attempts pattern matching

3. **IOC Lookup**: All hashes and network IOCs are checked against ransomware.live.
   - Note: Demo hashes are fake, so no matches are expected
   - With PRO API: checks against known group infrastructure
   - Without PRO API: skips IOC database lookup

4. **TTP Correlation**: Observed TTPs are mapped to MITRE ATT&CK:
   - RDP lateral movement → T1021.001
   - PsExec → T1021.002, T1569.002
   - WMI → T1047
   - Scheduled tasks → T1053.005
   - Registry Run key → T1547.001
   - rclone/data exfil → T1567.002
   - vssadmin → T1490
   - bcdedit → T1490
   - certutil → T1140, T1105
   - PowerShell → T1059.001

5. **Confidence Scoring**: Multi-signal weighted score is calculated:
   - Ransom note match: 35% weight
   - IOC overlap: 30% weight
   - TTP alignment: 20% weight
   - File extension: 15% weight

6. **Report Generation**: Full IR brief is rendered via Jinja2 template.

## Expected Output (Without API Keys)

Without API keys, the demo will still produce a report showing:
- The attribution pipeline workflow
- TTP mapping to MITRE ATT&CK
- Keyword-based ransom note matching (if any keywords match)
- Generic confidence scores
- Recommended actions
- Template structure

The confidence score will be low because most signals require API data, which demonstrates the graceful degradation feature.

## Expected Output (With PRO API Key)

With a valid PRO API key, the demo additionally shows:
- Embedding-based ransom note matching with similarity scores
- IOC database lookups with match/no-match results
- Full TTP correlation against known group playbooks
- Negotiation intelligence summary
- YARA rules for network sweep
- Higher-confidence attribution
