# Product Roadmap

## Milestone 1 — SIEM MVP
- [x] API ingestion with API-key check
- [x] SQLAlchemy event and alert persistence
- [x] Basic event normalization through validated schema
- [x] Starter detection rules
- [x] React dashboard for events and alerts
- [x] Windows Security log collector prototype
- [x] Docker Compose backend/PostgreSQL/Redis foundation

## Milestone 2 — Reliability and security
- [ ] JWT identity, RBAC, organization membership
- [ ] Strict tenant authorization (derive tenant from authenticated principal)
- [ ] TLS, secret management, rate limiting and audit trail
- [ ] Database migrations with Alembic
- [ ] Queue-backed ingestion workers, retries and dead-letter handling
- [ ] Structured logging, metrics and health checks

## Milestone 3 — Detection engineering
- [ ] Sigma rule import and rule lifecycle management
- [ ] Windows/Sysmon and Linux audit event mappings
- [ ] Correlation windows and threshold detections
- [ ] ML feature pipeline and anomaly evaluation
- [ ] MITRE ATT&CK technique mapping

## Milestone 4 — Differentiating capabilities
- [ ] Attack Story Engine with explainable event relationships
- [ ] Evidence-backed AI investigation with event IDs and source excerpts
- [ ] Threat intelligence adapters and cache
- [ ] Analyst approval workflow for response actions

## Milestone 5 — Productization
- [ ] Multi-tenant security review
- [ ] Splunk HEC integration
- [ ] Cloud SaaS and on-prem deployment profiles
- [ ] CI/CD, integration tests, load tests and security tests
- [ ] Installation, upgrade, backup and recovery documentation
