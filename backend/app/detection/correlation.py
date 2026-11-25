
from datetime import timedelta

from sqlalchemy.orm import Session

from app.db.models import SecurityEvent, Alert
from app.detection.rules import Detection


CORRELATION_WINDOW_MINUTES = 10
FAILED_LOGIN_THRESHOLD = 5


def is_failed_login(event: SecurityEvent) -> bool:
    text = f"{event.event_type} {event.message}".lower()
    event_id = str((event.raw or {}).get("event_id", ""))

    return "failed_login" in text or event_id == "4625"


def is_successful_login(event: SecurityEvent) -> bool:
    text = f"{event.event_type} {event.message}".lower()
    event_id = str((event.raw or {}).get("event_id", ""))

    return (
        "successful_login" in text
        or "login_success" in text
        or event_id == "4624"
    )


def correlate_suspicious_login(
    event: SecurityEvent,
    db: Session
) -> list[Detection]:

    if not event.source_ip or not is_successful_login(event):
        return []

    if not event.created_at:
        return []

    # Use the successful login's timestamp as the reference.
    event_time = event.created_at

    # SQLite stores DateTime values without timezone information.
    if event_time.tzinfo is not None:
        event_time = event_time.replace(tzinfo=None)

    cutoff = event_time - timedelta(
        minutes=CORRELATION_WINDOW_MINUTES
    )

    recent_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.tenant_id == event.tenant_id,
            SecurityEvent.source_ip == event.source_ip,
            SecurityEvent.created_at >= cutoff,
            SecurityEvent.created_at <= event_time,
            SecurityEvent.id != event.id
        )
        .all()
    )

    failed_events = [
        item for item in recent_events
        if is_failed_login(item)
    ]

    if len(failed_events) < FAILED_LOGIN_THRESHOLD:
        return []

    ip_marker = f"Source IP: {event.source_ip}"

    existing_alert = (
        db.query(Alert)
        .filter(
            Alert.tenant_id == event.tenant_id,
            Alert.rule_id == "AUTH-CORR-001",
            Alert.status.in_(["open", "acknowledged"]),
            Alert.description.contains(ip_marker)
        )
        .first()
    )

    if existing_alert:
        return []

    failed_ids = sorted(item.id for item in failed_events)

    description = (
        "A successful login occurred after repeated failed "
        "login attempts from the same source IP. "
        f"Failed attempts: {len(failed_events)}. "
        f"Source IP: {event.source_ip}. "
        f"Username: {event.username or 'unknown'}. "
        f"Failed event IDs: {failed_ids}. "
        f"Successful event ID: {event.id}. "
        f"Correlation window: {CORRELATION_WINDOW_MINUTES} minutes."
    )

    return [
        Detection(
            rule_id="AUTH-CORR-001",
            title="Suspicious Login After Brute-force",
            description=description,
            severity="high"
        )
    ]
