# Security Log Monitoring and Threat Detection System

An original, modular SIEM foundation built with Python, FastAPI, PostgreSQL-compatible SQLAlchemy models, a React dashboard, rule-based detections, and a Windows event collector prototype.

## Current implementation status

This ZIP is a runnable **MVP foundation**, not a claim that every enterprise feature is production-ready.

Implemented:
- FastAPI backend with API-key-protected event ingestion
- Event storage using SQLAlchemy (SQLite by default; PostgreSQL through `DATABASE_URL`)
- Event normalization and basic rule-based detections
- Alert listing and acknowledgement
- Tenant identifier on ingested events and tenant-filtered API queries
- React + Vite dashboard for event and alert visibility
- Windows Security Event Log collector prototype (requires Windows and `pywin32`)
- Docker Compose configuration for PostgreSQL, Redis, and backend
- Basic backend tests and setup documentation

Planned extension points / not yet production complete:
- Production-grade identity provider, JWT, RBAC and tenant isolation
- Durable queue workers and high-volume streaming
- Sysmon installation/collection and Linux agent
- Advanced correlation / Attack Story Engine
- Evidence-grounded LLM investigation
- Threat-intelligence providers
- Human-approved response playbooks
- Splunk HEC delivery
- Hardened SaaS and on-premises deployment

## Architecture

```text
Windows / Linux / Firewall / Web sources
                 |
          Secure Ingestion API
                 |
       Validation + Normalization
                 |
          SQLAlchemy storage
                 |
         Rule-based detections
                 |
          Alerts / Incidents
                 |
        React SOC Dashboard

Future modules: Attack Story Engine, evidence-backed AI, threat intel,
Splunk integration, approval-based response, multi-tenant SaaS.
```

## Quick start (Windows PowerShell)

1. Install Python 3.11+ and Node.js 20+.
2. Extract this ZIP.
3. Open PowerShell in the extracted project directory.
4. Run:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

Backend: http://127.0.0.1:8000
API docs: http://127.0.0.1:8000/docs
Health: http://127.0.0.1:8000/health

Open a second PowerShell window:

```powershell
cd frontend
npm install
npm run dev
```

Frontend: http://localhost:5173

The development API key is `local-dev-key`. Change it before exposing the service to any network.

## Send a test event

```powershell
$body = @{
  tenant_id = "demo-org"
  source = "windows"
  hostname = "LAB-PC"
  event_type = "failed_login"
  severity = "high"
  message = "Multiple failed login attempts for user administrator"
  source_ip = "192.0.2.25"
  username = "administrator"
  raw = @{ event_id = 4625; provider = "Microsoft-Windows-Security-Auditing" }
} | ConvertTo-Json -Depth 6

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/ingest" `
  -Headers @{ "X-API-Key" = "local-dev-key" } `
  -ContentType "application/json" `
  -Body $body
```

Refresh the dashboard to see the event and any generated alert.

## Run tests

```powershell
cd backend
pytest -q
```

## Docker (backend + PostgreSQL + Redis)

From the project root:

```powershell
docker compose up --build
```

The backend is exposed on port 8000. The default Docker configuration uses PostgreSQL. Redis is included as an infrastructure service; a durable queue worker is a future implementation task.

## Security notes

- Never commit real API keys, passwords, customer logs, or `.env` files.
- The included API key is for local development only.
- Tenant filtering in this MVP is a foundation, not a substitute for production-grade tenant isolation and authorization.
- Use synthetic or authorized lab logs only.
- Do not deploy this MVP directly to the public internet without security review, TLS, proper identity management, rate limiting, secret management, and operational hardening.

## License

MIT License. See `LICENSE`.
