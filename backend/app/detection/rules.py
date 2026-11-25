
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.db.models import SecurityEvent, Alert


# Brute-force detection configuration
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5


@dataclass
class Detection:
    rule_id: str
    title: str
    description: str
    severity: str


def is_failed_login(event: SecurityEvent) -> bool:
    """Identify failed authentication events."""

    text = f"{event.event_type} {event.message}".lower()
    event_id = str((event.raw or {}).get("event_id", ""))

    return (
        "failed_login" in text
        or "4625" in event_id
    )


def detect_brute_force(
    event: SecurityEvent,
    db: Session
) -> list[Detection]:
    """Detect repeated failed logins from the same source IP."""

    # An IP address is required for correlation.
    if not event.source_ip:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(
        minutes=BRUTE_FORCE_WINDOW_MINUTES
    )

    # Retrieve recent events belonging to the same tenant and IP.
    recent_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.tenant_id == event.tenant_id,
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.created_at >= cutoff
        )
        .all()
    )

    failed_attempts = [
        item for item in recent_events
        if is_failed_login(item)
    ]

    if len(failed_attempts) < BRUTE_FORCE_THRESHOLD:
        return []

    # Avoid creating another alert for an existing active incident
    # involving the same tenant and source IP.
    ip_marker = f"Source IP: {event.source_ip}"

    existing_alert = (
        db.query(Alert)
        .filter(
            Alert.tenant_id == event.tenant_id,
            Alert.rule_id == "AUTH-BF-001",
            Alert.status.in_(["open", "acknowledged"]),
            Alert.description.contains(ip_marker)
        )
        .first()
    )

    if existing_alert:
        return []

    return [
        Detection(
            rule_id="AUTH-BF-001",
            title="Possible Brute-force Attack",
            description=(
                f"Detected {len(failed_attempts)} failed login attempts "
                f"within {BRUTE_FORCE_WINDOW_MINUTES} minutes. "
                f"Source IP: {event.source_ip}. "
                "Investigate the source IP and affected accounts."
            ),
            severity="high"
        )
    ]


def evaluate_event(
    event: SecurityEvent,
    db: Session | None = None
) -> list[Detection]:

    text = f"{event.event_type} {event.message}".lower()
    detections = []

    # Existing rule: Failed authentication
    if is_failed_login(event):
        detections.append(Detection(
            "AUTH-001",
            "Failed authentication activity",
            "A failed authentication event was received. Review the account, source and surrounding events.",
            "medium"
        ))

    # New rule: Brute-force detection
    if db is not None:
        detections.extend(detect_brute_force(event, db))

    # Existing rule: Privilege escalation
    if "privilege_escalation" in text or "privilege escalation" in text:
        detections.append(Detection(
            "PRIV-001",
            "Possible privilege escalation",
            "The event indicates possible privilege escalation. Validate the process and account context.",
            "high"
        ))

    # Existing rule: Malware
    if "malware" in text or "ransomware" in text:
        detections.append(Detection(
            "MAL-001",
            "Malware-related indicator",
            "The event contains malware-related terminology. Investigate the original event and endpoint.",
            "high"
        ))

    # Existing rule: Critical severity
    if event.severity == "critical":
        detections.append(Detection(
            "SEV-001",
            "Critical severity event",
            "The source marked this event as critical. Review immediately.",
            "critical"
        ))

    return detections
