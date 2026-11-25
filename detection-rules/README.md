# Detection Rules

Initial executable rules live in `backend/app/detection/rules.py`.

Current rules:
- AUTH-001: failed authentication activity
- PRIV-001: possible privilege escalation keyword/event marker
- MAL-001: malware-related indicator
- SEV-001: source-reported critical severity

These are starter heuristics, not a comprehensive detection library. Before production use, add tested Sigma-compatible rules, event-field mappings, false-positive tuning, rule versioning, and test fixtures for each rule.
