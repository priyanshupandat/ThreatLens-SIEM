import os, requests

url = os.getenv("SIEM_URL", "http://127.0.0.1:8000")
key = os.getenv("SIEM_API_KEY", "local-dev-key")
samples = [
    {"tenant_id":"demo-org","source":"simulator","hostname":"LAB-WIN-01","event_type":"failed_login","severity":"high","message":"Repeated failed login for administrator","source_ip":"192.0.2.10","username":"administrator","raw":{"event_id":4625}},
    {"tenant_id":"demo-org","source":"simulator","hostname":"LAB-LINUX-01","event_type":"privilege_escalation","severity":"high","message":"Possible privilege escalation detected","source_ip":"192.0.2.20","username":"analyst","raw":{"scenario":"training"}},
    {"tenant_id":"demo-org","source":"simulator","hostname":"LAB-WEB-01","event_type":"malware_indicator","severity":"critical","message":"Malware indicator found in authorized test dataset","source_ip":"192.0.2.30","raw":{"scenario":"training"}}
]
for event in samples:
    response = requests.post(f"{url}/api/v1/ingest", json=event, headers={"X-API-Key":key}, timeout=10)
    print(response.status_code, response.text)
