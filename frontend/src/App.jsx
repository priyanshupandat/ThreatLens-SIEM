
import React, { useEffect, useState } from "react";

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
const TENANT = import.meta.env.VITE_TENANT_ID || "demo-org";
const ANALYST = "SOC Analyst";

function App() {
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const [selectedAlertId, setSelectedAlertId] = useState(null);

  const [notes, setNotes] = useState([]);
  const [activities, setActivities] = useState([]);
  const [noteText, setNoteText] = useState("");
  const [investigationError, setInvestigationError] = useState("");
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [noteSaving, setNoteSaving] = useState(false);

  async function refresh() {
    try {
      const [e, a] = await Promise.all([
        fetch(`${API}/api/v1/events?tenant_id=${TENANT}`),
        fetch(`${API}/api/v1/alerts?tenant_id=${TENANT}`)
      ]);

      if (!e.ok || !a.ok) {
        throw new Error("API request failed. Is the backend running?");
      }

      setEvents(await e.json());
      setAlerts(await a.json());
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }

  async function loadInvestigationData(alertId) {
    if (!alertId) return;

    setInvestigationLoading(true);
    setInvestigationError("");

    try {
      const [notesResponse, activitiesResponse] = await Promise.all([
        fetch(`${API}/api/v1/alerts/${alertId}/notes?tenant_id=${TENANT}`),
        fetch(`${API}/api/v1/alerts/${alertId}/activities?tenant_id=${TENANT}`)
      ]);

      if (!notesResponse.ok || !activitiesResponse.ok) {
        throw new Error("Could not load investigation records.");
      }

      const [notesData, activitiesData] = await Promise.all([
        notesResponse.json(),
        activitiesResponse.json()
      ]);

      setNotes(notesData);
      setActivities(activitiesData);
    } catch (err) {
      setInvestigationError(err.message);
    } finally {
      setInvestigationLoading(false);
    }
  }

  async function saveInvestigationNote() {
    const cleanedNote = noteText.trim();

    if (!cleanedNote || !selectedAlertId) return;

    setNoteSaving(true);
    setInvestigationError("");

    try {
      const response = await fetch(
        `${API}/api/v1/alerts/${selectedAlertId}/notes?tenant_id=${TENANT}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
          },
          body: JSON.stringify({
            analyst: ANALYST,
            note: cleanedNote
          })
        }
      );

      if (!response.ok) {
        throw new Error("Could not save investigation note.");
      }

      setNoteText("");
      await loadInvestigationData(selectedAlertId);
    } catch (err) {
      setInvestigationError(err.message);
    } finally {
      setNoteSaving(false);
    }
  }

  async function updateAlertStatus(id, status) {
    try {
      const response = await fetch(
        `${API}/api/v1/alerts/${id}/status?tenant_id=${TENANT}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
          },
          body: JSON.stringify({ status })
        }
      );

      if (!response.ok) {
        throw new Error("Could not update alert status.");
      }

      await refresh();

      if (selectedAlertId === id) {
        await loadInvestigationData(id);
      }
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    refresh();

    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (selectedAlertId) {
      setNotes([]);
      setActivities([]);
      setNoteText("");
      loadInvestigationData(selectedAlertId);
    } else {
      setNotes([]);
      setActivities([]);
      setNoteText("");
      setInvestigationError("");
    }
  }, [selectedAlertId]);

  const critical = alerts.filter(
    a => a.severity === "critical"
  ).length;

  const open = alerts.filter(
    a => a.status === "open"
  ).length;

  const filteredAlerts = alerts.filter(a => {
    const searchText = search.trim().toLowerCase();

    const matchesSearch =
      !searchText ||
      (a.title || "").toLowerCase().includes(searchText) ||
      (a.rule_id || "").toLowerCase().includes(searchText);

    const matchesSeverity =
      severityFilter === "all" ||
      a.severity === severityFilter;

    const matchesStatus =
      statusFilter === "all" ||
      a.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  function clearFilters() {
    setSearch("");
    setSeverityFilter("all");
    setStatusFilter("all");
  }

  const filtersActive =
    search !== "" ||
    severityFilter !== "all" ||
    statusFilter !== "all";

  const selectedAlert = alerts.find(
    a => a.id === selectedAlertId
  );

  const selectedEvent = selectedAlert
    ? events.find(e => e.id === selectedAlert.event_id)
    : null;

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
          <h1>Threat Monitoring</h1>
          <p>Security Log Monitoring and Threat Detection System</p>
        </div>

        <button onClick={refresh}>Refresh data</button>
      </header>

      {error && <div className="error">{error}</div>}

      <section className="metrics">
        <Metric label="Total events" value={events.length} />
        <Metric label="Total alerts" value={alerts.length} />
        <Metric label="Open alerts" value={open} />
        <Metric label="Critical alerts" value={critical} />
      </section>

      {/* Detection Center */}
      <section className="panel">
        <div className="section-head">
          <div>
            <span className="eyebrow">DETECTION CENTER</span>
            <h2>Recent alerts</h2>
          </div>
          <span className="live">API CONNECTED WHEN AVAILABLE</span>
        </div>

        <div className="filters">
          <input
            type="text"
            placeholder="Search by alert title or rule ID..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />

          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
          >
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
          >
            <option value="all">All statuses</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>

          <button
            className="small"
            onClick={clearFilters}
            disabled={!filtersActive}
          >
            Clear filters
          </button>
        </div>

        <div className="muted">
          Showing {filteredAlerts.length} of {alerts.length} alerts
        </div>

        {filteredAlerts.length === 0 ? (
          <Empty text="No alerts match your filters." />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Alert</th>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>

              <tbody>
                {filteredAlerts.map(a => (
                  <tr key={a.id}>
                    <td>
                      <strong>{a.title}</strong>
                      <small>{a.description}</small>
                    </td>

                    <td>{a.rule_id}</td>

                    <td>
                      <span className={`severity ${a.severity}`}>
                        {a.severity}
                      </span>
                    </td>

                    <td>
                      <strong>{a.risk_score ?? "N/A"}/100</strong>
                    </td>

                    <td>{a.status}</td>

                    <td>
                      <button
                        className="small"
                        onClick={() => setSelectedAlertId(a.id)}
                      >
                        Investigate
                      </button>

                      {a.status === "open" && (
                        <button
                          className="small"
                          onClick={() =>
                            updateAlertStatus(a.id, "acknowledged")
                          }
                        >
                          Acknowledge
                        </button>
                      )}

                      {a.status === "acknowledged" && (
                        <button
                          className="small"
                          onClick={() =>
                            updateAlertStatus(a.id, "resolved")
                          }
                        >
                          Resolve
                        </button>
                      )}

                      {a.status === "resolved" && (
                        <button
                          className="small"
                          onClick={() =>
                            updateAlertStatus(a.id, "open")
                          }
                        >
                          Reopen
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Investigation Center */}
      {selectedAlert && (
        <section className="panel">
          <div className="section-head">
            <div>
              <span className="eyebrow">INVESTIGATION CENTER</span>
              <h2>{selectedAlert.title}</h2>
            </div>

            <button
              className="small"
              onClick={() => setSelectedAlertId(null)}
            >
              Close
            </button>
          </div>

          <h3>Alert Information</h3>

          <div className="metrics">
            <Metric label="Alert ID" value={selectedAlert.id} />
            <Metric label="Rule ID" value={selectedAlert.rule_id} />
            <Metric label="Severity" value={selectedAlert.severity} />
            <Metric label="Status" value={selectedAlert.status} />
            <Metric
              label="Risk Score"
              value={`${selectedAlert.risk_score ?? "N/A"}/100`}
            />
          </div>

          <h3>MITRE ATT&CK Mapping</h3>

          {selectedAlert.mitre_attack?.length > 0 ? (
            <div>
              {selectedAlert.mitre_attack.map(technique => (
                <div
                  key={technique.technique_id}
                  style={{
                    border: "1px solid #64748b",
                    borderRadius: "8px",
                    padding: "12px",
                    marginBottom: "8px"
                  }}
                >
                  <strong>{technique.technique_id}</strong>
                  <p>{technique.technique_name}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="muted">
              No MITRE ATT&CK technique mapped to this alert.
            </p>
          )}

          <p><strong>Description:</strong> {selectedAlert.description}</p>
          <p><strong>Tenant:</strong> {selectedAlert.tenant_id}</p>
          <p><strong>Related Event ID:</strong> {selectedAlert.event_id}</p>

          <p>
            <strong>Alert Created:</strong>{" "}
            {new Date(selectedAlert.created_at).toLocaleString()}
          </p>

          <hr />

          {/* Original Event Evidence */}
          <h3>Original Event Evidence</h3>

          {selectedEvent ? (
            <>
              <p><strong>Event Type:</strong> {selectedEvent.event_type}</p>
              <p><strong>Hostname:</strong> {selectedEvent.hostname}</p>
              <p><strong>Source:</strong> {selectedEvent.source}</p>
              <p><strong>Severity:</strong> {selectedEvent.severity}</p>
              <p><strong>Username:</strong> {selectedEvent.username || "Not available"}</p>
              <p><strong>Source IP:</strong> {selectedEvent.source_ip || "Not available"}</p>
              <p><strong>Event Message:</strong> {selectedEvent.message}</p>

              <p>
                <strong>Event Created:</strong>{" "}
                {new Date(selectedEvent.created_at).toLocaleString()}
              </p>

              <h3>Raw Event Data</h3>

              <pre
                style={{
                  background: "#111827",
                  color: "#e5e7eb",
                  padding: "16px",
                  borderRadius: "8px",
                  overflowX: "auto",
                  fontSize: "13px",
                  whiteSpace: "pre-wrap",
                  overflowWrap: "anywhere"
                }}
              >
                {JSON.stringify(selectedEvent.raw ?? {}, null, 2)}
              </pre>
            </>
          ) : (
            <Empty text="The original event could not be found in the loaded event records." />
          )}

          <hr />

          {/* Investigation Notes */}
          <h3>Investigation Notes</h3>
          <p className="muted">
            Record observations, analysis, and actions taken for this alert.
          </p>

          {investigationError && (
            <div className="error">{investigationError}</div>
          )}

          <div style={{ marginBottom: "16px" }}>
            <textarea
              rows="4"
              placeholder="Write your investigation note here..."
              value={noteText}
              onChange={e => setNoteText(e.target.value)}
              maxLength={10000}
              style={{
                width: "100%",
                padding: "12px",
                borderRadius: "8px",
                resize: "vertical",
                boxSizing: "border-box",
                font: "inherit"
              }}
            />

            <div className="muted">
              {noteText.length}/10000 characters
            </div>

            <button
              onClick={saveInvestigationNote}
              disabled={!noteText.trim() || noteSaving}
            >
              {noteSaving ? "Saving..." : "Save Investigation Note"}
            </button>
          </div>

          <h3>Saved Notes</h3>

          {investigationLoading ? (
            <Empty text="Loading investigation records..." />
          ) : notes.length === 0 ? (
            <Empty text="No investigation notes have been added yet." />
          ) : (
            <div>
              {notes.map(note => (
                <div
                  key={note.id}
                  style={{
                    border: "1px solid #d1d5db",
                    borderRadius: "8px",
                    padding: "12px",
                    marginBottom: "10px"
                  }}
                >
                  <strong>{note.analyst}</strong>
                  <small>
                    {new Date(note.created_at).toLocaleString()}
                  </small>
                  <p style={{ whiteSpace: "pre-wrap" }}>{note.note}</p>
                </div>
              ))}
            </div>
          )}

          <hr />

          {/* Activity Timeline */}
          <h3>Activity Timeline</h3>
          <p className="muted">
            Recorded activities associated with this alert.
          </p>

          {investigationLoading ? (
            <Empty text="Loading activity timeline..." />
          ) : activities.length === 0 ? (
            <Empty text="No activity records are available for this alert." />
          ) : (
            <div>
              {activities.map(activity => (
                <div
                  key={activity.id}
                  style={{
                    borderLeft: "3px solid #64748b",
                    padding: "8px 12px",
                    marginBottom: "12px"
                  }}
                >
                  <strong>
                    {activity.action.replaceAll("_", " ").toUpperCase()}
                  </strong>

                  <p>{activity.details}</p>

                  <small>
                    Actor: {activity.actor} ·{" "}
                    {new Date(activity.created_at).toLocaleString()}
                  </small>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Recent Security Events */}
      <section className="panel">
        <div className="section-head">
          <div>
            <span className="eyebrow">TELEMETRY</span>
            <h2>Recent security events</h2>
          </div>
          <span className="muted">{events.length} shown</span>
        </div>

        {events.length === 0 ? (
          <Empty text="Waiting for security events." />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Event</th>
                  <th>Host</th>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>User / IP</th>
                </tr>
              </thead>

              <tbody>
                {events.map(e => (
                  <tr key={e.id}>
                    <td>
                      <strong>{e.event_type}</strong>
                      <small>{e.message}</small>
                    </td>

                    <td>{e.hostname}</td>
                    <td>{e.source}</td>

                    <td>
                      <span className={`severity ${e.severity}`}>
                        {e.severity}
                      </span>
                    </td>

                    <td>
                      {e.username || "—"}
                      <small>{e.source_ip || ""}</small>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <footer>
        Local development dashboard · Tenant: {TENANT} · Refresh interval: 5 seconds
      </footer>
    </main>
  );
}

function Metric({ label, value }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Empty({ text }) {
  return <div className="empty">{text}</div>;
}

export default App;
