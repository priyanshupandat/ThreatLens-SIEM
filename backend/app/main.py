from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import CORS_ORIGINS
from app.db.database import Base, engine
from app.api.routes import router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Security Log Monitoring and Threat Detection System",
    description="A modular SIEM MVP for authorized security monitoring and investigation.",
    version="0.1.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"]
)
app.include_router(router)

@app.get("/health")
def health():
    return {"status": "ok", "service": "siem-api", "version": "0.1.0"}
