
from datetime import datetime
from typing import Any, Literal

from pydantic import (
    BaseModel,
    Field,
    ConfigDict,
    computed_field
)


class EventIn(BaseModel):
    tenant_id: str = Field(default="default", min_length=1, max_length=100)
    source: str = Field(default="unknown", max_length=80)
    hostname: str = Field(default="unknown", max_length=255)
    event_type: str = Field(min_length=1, max_length=120)
    severity: str = Field(
        default="low",
        pattern="^(critical|high|medium|low|info)$"
    )
    message: str = Field(default="", max_length=10000)
    source_ip: str | None = None
    username: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: str
    source: str
    hostname: str
    event_type: str
    severity: str
    message: str
    source_ip: str | None
    username: str | None
    raw: dict
    created_at: datetime


# MITRE ATT&CK mapping by detection rule.
MITRE_MAPPING = {
    "AUTH-001": [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force"
        }
    ],
    "AUTH-BF-001": [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force"
        }
    ],
    "AUTH-CORR-001": [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force"
        },
        {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts"
        }
    ],
    "PRIV-001": [
        {
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation"
        }
    ]
}


def calculate_risk_score(severity: str, rule_id: str) -> int:
    severity_scores = {
        "critical": 90,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 10
    }

    score = severity_scores.get(severity.lower(), 10)

    if rule_id in ("AUTH-BF-001", "AUTH-CORR-001"):
        score += 10

    return min(score, 100)


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: str
    event_id: int
    title: str
    description: str
    severity: str
    rule_id: str
    status: str
    acknowledged: bool
    created_at: datetime

    @computed_field
    @property
    def risk_score(self) -> int:
        return calculate_risk_score(self.severity, self.rule_id)

    @computed_field
    @property
    def mitre_attack(self) -> list[dict[str, str]]:
        return MITRE_MAPPING.get(self.rule_id, [])


class AlertStatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


class InvestigationNoteIn(BaseModel):
    analyst: str = Field(default="local-analyst", min_length=1, max_length=100)
    note: str = Field(min_length=1, max_length=10000)


class InvestigationNoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: str
    alert_id: int
    analyst: str
    note: str
    created_at: datetime


class AlertActivityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: str
    alert_id: int
    actor: str
    action: str
    details: str
    created_at: datetime
