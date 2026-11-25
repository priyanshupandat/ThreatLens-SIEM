import os, time, json, socket, datetime
import requests

SIEM_URL = os.getenv("SIEM_URL", "http://127.0.0.1:8000").rstrip("/")
API_KEY = os.getenv("SIEM_API_KEY", "local-dev-key")
TENANT = os.getenv("SIEM_TENANT_ID", "demo-org")
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "15"))

def main():
    try:
        import win32evtlog
    except ImportError:
        raise SystemExit("Install dependencies first: pip install -r requirements.txt")

    server = "localhost"
    log_type = "Security"
    handle = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    seen = set()
    print(f"Collecting recent Windows Security events from {socket.gethostname()}")

    while True:
        try:
            records = win32evtlog.ReadEventLog(handle, flags, 0) or []
            for record in records:
                key = (record.RecordNumber, record.TimeGenerated)
                if key in seen:
                    continue
                seen.add(key)
                event_id = record.EventID & 0xFFFF
                event_type = "failed_login" if event_id == 4625 else f"windows_event_{event_id}"
                payload = {
                    "tenant_id": TENANT, "source": "windows-security",
                    "hostname": socket.gethostname(), "event_type": event_type,
                    "severity": "medium" if event_id == 4625 else "info",
                    "message": f"Windows Security event {event_id}",
                    "username": None,
                    "raw": {
                        "event_id": event_id, "record_number": record.RecordNumber,
                        "source_name": record.SourceName,
                        "time_generated": str(record.TimeGenerated),
                        "event_category": record.EventCategory,
                        "strings": list(record.StringInserts or [])
                    }
                }
                try:
                    requests.post(f"{SIEM_URL}/api/v1/ingest", json=payload,
                                 headers={"X-API-Key": API_KEY}, timeout=8).raise_for_status()
                except requests.RequestException as exc:
                    print(f"Event delivery failed: {exc}")
            if len(seen) > 5000:
                seen.clear()
        except Exception as exc:
            print(f"Collector error: {exc}")
        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()
