# Windows Endpoint Collector (prototype)

This is a prototype collector for authorized Windows lab machines. It reads recent entries from the Windows Security event log and submits them to the SIEM ingestion API.

## Requirements
- Windows
- Python 3.11+
- `pip install -r requirements.txt`
- Run PowerShell as Administrator to read the Security log.

## Run
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SIEM_URL="http://127.0.0.1:8000"
$env:SIEM_API_KEY="local-dev-key"
$env:SIEM_TENANT_ID="demo-org"
py agent.py
```

The collector is intentionally a prototype: it polls recent records, does not install itself as a Windows service, and does not yet provide tamper-resistant buffering, certificate-based identity, automatic updates, or production-grade retry management.
