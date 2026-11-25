# Architecture Notes

The initial implementation uses a modular monolith to keep local setup understandable. FastAPI exposes ingestion and query endpoints. SQLAlchemy isolates persistence. Detection rules execute synchronously after an event is persisted in the request transaction. The React dashboard polls read APIs.

For scale, move rule evaluation and enrichment into queue consumers. Keep raw source evidence immutable at the application level, store normalized fields separately, and record provenance for every derived finding. A future Attack Story Engine should link findings to exact event IDs and explain each relationship.
