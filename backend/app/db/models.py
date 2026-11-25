
from datetime import datetime, timezone

from sqlalchemy import (
    String,
    DateTime,
    Text,
    JSON,
    Integer,
    Boolean,
    Index
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_tenant_created", "tenant_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String(100), default="default", index=True)
    source: Mapped[str] = mapped_column(String(80), default="unknown")
    hostname: Mapped[str] = mapped_column(String(255), default="unknown", index=True)
    event_type: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="low", index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String(100), default="default", index=True)
    event_id: Mapped[int] = mapped_column(Integer, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    rule_id: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(30), default="open")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"
    __table_args__ = (
        Index("ix_notes_tenant_alert", "tenant_id", "alert_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String(100), index=True)
    alert_id: Mapped[int] = mapped_column(Integer, index=True)
    analyst: Mapped[str] = mapped_column(String(100), default="local-analyst")
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AlertActivity(Base):
    __tablename__ = "alert_activities"
    __table_args__ = (
        Index("ix_activity_tenant_alert", "tenant_id", "alert_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String(100), index=True)
    alert_id: Mapped[int] = mapped_column(Integer, index=True)
    actor: Mapped[str] = mapped_column(String(100), default="local-analyst")
    action: Mapped[str] = mapped_column(String(100))
    details: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
