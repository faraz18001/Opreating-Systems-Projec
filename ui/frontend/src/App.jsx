import { useEffect, useMemo, useRef, useState } from "react";
import DemoLab from "./components/DemoLab.jsx";
import InspectorPane from "./components/InspectorPane.jsx";
import MlComparisonPanel from "./components/MlComparisonPanel.jsx";
import MttiStrip from "./components/MttiStrip.jsx";

const VALID_FILTERS = ["all", "frozen", "alert", "allow"];
const VALID_ENGINES = ["heuristic", "ml"];

function readUrlParam(key, allowed, fallback) {
  const params = new URLSearchParams(window.location.search);
  const val = params.get(key);
  return allowed.includes(val) ? val : fallback;
}

function writeUrlParams(filter, engine) {
  const params = new URLSearchParams(window.location.search);
  params.set("filter", filter);
  params.set("engine", engine);
  const next = `${window.location.pathname}?${params.toString()}`;
  window.history.replaceState(null, "", next);
}

function formatActionLabel(action) {
  switch (action) {
    case "FROZEN":
      return "Frozen";
    case "WOULD_FREEZE":
      return "Dry-run freeze";
    case "ALERT":
      return "Alert";
    case "FREEZE_ERR":
      return "Freeze failed";
    default:
      return "Allowed";
  }
}

function actionClass(action) {
  if (action === "FROZEN" || action === "WOULD_FREEZE") return "state-word--frozen";
  if (action === "ALERT") return "state-word--alert";
  if (action === "FREEZE_ERR") return "state-word--error";
  return "state-word--allow";
}

export default function App() {
  const [engine, setEngine] = useState(() => readUrlParam("engine", VALID_ENGINES, "heuristic"));
  const [filter, setFilter] = useState(() => readUrlParam("filter", VALID_FILTERS, "all"));
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [status, setStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [quarantine, setQuarantine] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [dryRun, setDryRun] = useState(false);
  const [sensorBusy, setSensorBusy] = useState(false);
  const [busyPid, setBusyPid] = useState(null);
  const [runningDemo, setRunningDemo] = useState(null);
  const [demoResults, setDemoResults] = useState({});
  const [killTarget, setKillTarget] = useState(null);
  const [actionNotice, setActionNotice] = useState("");
  const dialogRef = useRef(null);

  useEffect(() => {
    writeUrlParams(filter, engine);
  }, [filter, engine]);

  async function fetchInitial() {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await fetch("/api/events");
      if (!res.ok) {
        throw new Error(`API returned status ${res.status}`);
      }
      const data = await res.json();
      setEvents(data.events || []);
      setQuarantine(data.quarantine || []);
      setStatus(data.status || null);
      if (data.status && typeof data.status.dry_run === "boolean") {
        setDryRun(data.status.dry_run);
      }
    } catch (err) {
      setLoadError(
        `Unable to reach the console backend (${err.message}). Start sudo python3 ui/server.py and retry.`
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchInitial();

    const sse = new EventSource("/api/stream");
    sse.addEventListener("telemetry", (e) => {
      try {
        const rec = JSON.parse(e.data);
        setEvents((prev) => [...prev.slice(-399), rec]);
        setLoadError(null);
      } catch {
        // ignore malformed stream frame
      }
    });

    sse.addEventListener("status", (e) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.status) setStatus(payload.status);
        if (payload.quarantine) setQuarantine(payload.quarantine);
      } catch {
        // ignore malformed status frame
      }
    });

    sse.addEventListener("cleared", () => {
      setEvents([]);
      setSelectedId(null);
    });

    return () => {
      sse.close();
    };
  }, []);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (killTarget && !dialog.open) {
      dialog.showModal();
    } else if (!killTarget && dialog.open) {
      dialog.close();
    }
  }, [killTarget]);

  const counts = useMemo(() => {
    let frozen = 0;
    let alert = 0;
    let allow = 0;
    for (const ev of events) {
      if (ev.action === "FROZEN") frozen++;
      else if (ev.action === "ALERT" || ev.action === "WOULD_FREEZE") alert++;
      else if (ev.action === "ALLOW") allow++;
    }
    return { all: events.length, frozen, alert, allow };
  }, [events]);

  const filteredEvents = useMemo(() => {
    const reversed = [...events].reverse();
    if (filter === "frozen") return reversed.filter((e) => e.action === "FROZEN");
    if (filter === "alert") return reversed.filter((e) => e.action === "ALERT" || e.action === "WOULD_FREEZE");
    if (filter === "allow") return reversed.filter((e) => e.action === "ALLOW");
    return reversed;
  }, [events, filter]);

  const selectedEvent = useMemo(() => {
    if (selectedId != null) {
      const found = events.find((e) => e.id === selectedId);
      if (found) return found;
    }
    return filteredEvents[0] || null;
  }, [events, filteredEvents, selectedId]);

  const avgMtti = useMemo(() => {
    const vals = events
      .filter((e) => e.action === "FROZEN" && typeof e.mtti_ms === "number")
      .map((e) => e.mtti_ms);
    if (vals.length === 0) return null;
    return vals.reduce((a, b) => a + b, 0) / vals.length;
  }, [events]);

  async function toggleSensor() {
    setSensorBusy(true);
    setActionNotice("");
    try {
      const endpoint = status?.running ? "/api/defender/stop" : "/api/defender/start";
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dry_run: dryRun, engine }),
      });
      const data = await res.json();
      setStatus(data);
      if (data.last_error) {
        setLoadError(data.last_error);
      } else {
        setLoadError(null);
      }
    } catch (err) {
      setLoadError(`Sensor request failed: ${err.message}`);
    } finally {
      setSensorBusy(false);
    }
  }

  async function handleEngineSelect(nextEngine) {
    setEngine(nextEngine);
    setActionNotice("");
    if (!status?.running || status.engine === nextEngine) return;
    if (nextEngine === "ml" && !status?.ml_available) {
      setActionNotice("ML bundle missing: train defender_ml/model.joblib before switching the active sensor.");
      return;
    }

    setSensorBusy(true);
    try {
      await fetch("/api/defender/stop", { method: "POST" });
      const res = await fetch("/api/defender/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dry_run: dryRun, engine: nextEngine }),
      });
      const data = await res.json();
      setStatus(data);
      if (data.last_error) {
        setLoadError(data.last_error);
      } else {
        setActionNotice(
          `Switched active mitigation engine to ${nextEngine === "ml" ? "ML classifier" : "Heuristic rules"}.`
        );
      }
    } catch (err) {
      setLoadError(`Engine switch failed: ${err.message}`);
    } finally {
      setSensorBusy(false);
    }
  }

  async function handleDryRunToggle(nextDryRun) {
    setDryRun(nextDryRun);
    if (!status?.running) return;
    setSensorBusy(true);
    setActionNotice("");
    try {
      await fetch("/api/defender/stop", { method: "POST" });
      const res = await fetch("/api/defender/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dry_run: nextDryRun, engine }),
      });
      const data = await res.json();
      setStatus(data);
      if (data.last_error) {
        setLoadError(data.last_error);
      } else {
        setActionNotice(
          nextDryRun
            ? "Switched sensor to dry-run mode (logging only, no SIGSTOP)."
            : "Switched sensor to active SIGSTOP mode."
        );
      }
    } catch (err) {
      setLoadError(`Mode switch failed: ${err.message}`);
    } finally {
      setSensorBusy(false);
    }
  }

  async function handleClearLog() {
    await fetch("/api/events/clear", { method: "POST" });
    setEvents([]);
    setSelectedId(null);
    setActionNotice("Telemetry ledger cleared.");
  }

  async function handleResume(pid) {
    setBusyPid(pid);
    setActionNotice("");
    try {
      const res = await fetch(`/api/process/${pid}/resume`, { method: "POST" });
      const data = await res.json();
      if (data.quarantine) setQuarantine(data.quarantine);
      setActionNotice(data.ok ? `Sent SIGCONT to PID ${pid}.` : `Resume failed for PID ${pid}: ${data.error}`);
    } finally {
      setBusyPid(null);
    }
  }

  async function confirmKill() {
    if (!killTarget) return;
    const { pid } = killTarget;
    setKillTarget(null);
    setBusyPid(pid);
    setActionNotice("");
    try {
      const res = await fetch(`/api/process/${pid}/kill`, { method: "POST" });
      const data = await res.json();
      if (data.quarantine) setQuarantine(data.quarantine);
      setActionNotice(data.ok ? `Terminated PID ${pid} with SIGKILL.` : `Kill failed for PID ${pid}: ${data.error}`);
    } finally {
      setBusyPid(null);
    }
  }

  async function handleRunDemo(action) {
    setRunningDemo(action);
    setActionNotice("");
    try {
      const res = await fetch(`/api/demo/${action}`, { method: "POST" });
      const data = await res.json();
      setDemoResults((prev) => ({ ...prev, [action]: data }));
      const refresh = await fetch("/api/events");
      if (refresh.ok) {
        const snap = await refresh.json();
        setEvents(snap.events || []);
        setQuarantine(snap.quarantine || []);
        setStatus(snap.status || null);
      }
    } catch (err) {
      setDemoResults((prev) => ({
        ...prev,
        [action]: { ok: false, verdict: "Error", metrics: {}, output: `Request failed: ${err.message}` },
      }));
    } finally {
      setRunningDemo(null);
    }
  }

  function handleSelectPid(pid) {
    const match = [...events].reverse().find((e) => e.pid === pid);
    if (match) {
      setSelectedId(match.id);
    }
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="container topbar__inner">
          <div className="topbar__brand">
            <a href="/" className="wordmark" aria-label="MemGuard eBPF Console home">
              <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true">
                <circle cx="10" cy="10" r="8" fill="none" stroke="var(--color-accent)" strokeWidth="1.5" />
                <circle cx="10" cy="10" r="3" fill="var(--color-accent-2)" />
              </svg>
              <span>MemGuard</span>
            </a>

            <nav className="engine-nav" role="tablist" aria-label="Classifier engine">
              <button
                type="button"
                role="tab"
                className="engine-tab"
                aria-selected={engine === "heuristic"}
                onClick={() => handleEngineSelect("heuristic")}
              >
                Heuristic engine
              </button>
              <button
                type="button"
                role="tab"
                className="engine-tab"
                aria-selected={engine === "ml"}
                onClick={() => handleEngineSelect("ml")}
              >
                ML engine
              </button>
            </nav>
          </div>

          <div className="topbar__controls">
            <span
              role="status"
              className={`status-chip ${
                status?.running
                  ? status.dry_run
                    ? "status-chip--apricot"
                    : "status-chip--live"
                  : ""
              }`}
            >
              <span className="status-chip__dot" aria-hidden="true" />
              {status?.running
                ? status.dry_run
                  ? "Sensor dry-run"
                  : "Sensor active"
                : "Sensor stopped"}
            </span>

            <label className="switch">
              <input
                type="checkbox"
                role="switch"
                className="switch__input"
                checked={dryRun}
                disabled={sensorBusy || (!status?.is_root && Boolean(status?.running))}
                onChange={(e) => handleDryRunToggle(e.target.checked)}
              />
              <span className="switch__track" aria-hidden="true" />
              <span className="switch__label">Dry-run</span>
            </label>

            <button
              type="button"
              className="btn btn--primary"
              disabled={sensorBusy || (!status?.is_root && !status?.running)}
              aria-busy={sensorBusy}
              onClick={toggleSensor}
            >
              {sensorBusy
                ? "Updating…"
                : status?.running
                ? "Stop sensor"
                : "Start sensor"}
            </button>
          </div>
        </div>
      </header>

      <main id="main" className="container main">
        <div className="page-head">
          <div>
            <h1>Fileless execution ledger</h1>
            <p className="page-head__meta">
              {status
                ? `Kernel ${status.kernel} with ${status.probes} eBPF syscall tracepoints`
                : "Connecting to local eBPF console API…"}
            </p>
          </div>

          {!status?.is_root && status && (
            <p className="page-head__meta">
              Sensor start is disabled without root privileges (launch server with sudo).
            </p>
          )}
        </div>

        {loadError && (
          <div className="error-banner" role="alert">
            <span>{loadError}</span>
            <button type="button" className="btn btn--sm" onClick={fetchInitial}>
              Retry
            </button>
          </div>
        )}

        {engine === "ml" && (
          <MlComparisonPanel
            status={status}
            onRefresh={fetchInitial}
            onBackToHeuristic={() => handleEngineSelect("heuristic")}
          />
        )}

        {(engine === "heuristic" || status?.ml_available) && (
          <>
            <section className="tally" aria-label="Live telemetry summary">
              <div className="tally__item">
                <span className="tally__label">Threats frozen</span>
                <span className="tally__value">{counts.frozen}</span>
                <span className="tally__sub">{quarantine.length} currently held in SIGSTOP</span>
              </div>

              <div className="tally__item">
                <span className="tally__label">Mean time to intercept</span>
                <span className="tally__value">
                  {avgMtti !== null ? avgMtti.toFixed(3) : "0.000"}
                  <span className="tally__unit">ms</span>
                </span>
                <span className="tally__sub">
                  {avgMtti !== null ? "Measured from kernel ktime" : "Awaiting first freeze"}
                </span>
              </div>

              <div className="tally__item">
                <span className="tally__label">Benign memfd allowed</span>
                <span className="tally__value">{counts.allow}</span>
                <span className="tally__sub">Desktop and audio buffers untouched</span>
              </div>

              <div className="tally__item">
                <span className="tally__label">Defender memory</span>
                <span className="tally__value">
                  {status?.running ? status.rss_mb.toFixed(1) : "0.0"}
                  <span className="tally__unit">MB</span>
                </span>
                <span className="tally__sub">{counts.all} total logged syscalls</span>
              </div>
            </section>

            <div className="workspace">
              <section className="glass-panel" aria-labelledby="ledger-heading">
                <div className="panel-head">
                  <div>
                    <h2 id="ledger-heading">Kernel syscall stream</h2>
                    <p className="panel-head__sub">
                      Real-time memfd_create, execveat, and prctl events scored by rules.yaml.
                    </p>
                  </div>
                  <button
                    type="button"
                    className="btn btn--sm"
                    disabled={events.length === 0}
                    onClick={handleClearLog}
                  >
                    Clear log
                  </button>
                </div>

                <div className="filter-tabs" role="tablist" aria-label="Filter telemetry events">
                  {[
                    ["all", "All events", counts.all],
                    ["frozen", "Frozen", counts.frozen],
                    ["alert", "Alerts", counts.alert],
                    ["allow", "Allowed", counts.allow],
                  ].map(([key, label, count]) => (
                    <button
                      key={key}
                      type="button"
                      role="tab"
                      className="filter-tab"
                      aria-selected={filter === key}
                      onClick={() => setFilter(key)}
                    >
                      <span>{label}</span>
                      <span className="filter-tab__count">{count}</span>
                    </button>
                  ))}
                </div>

                {loading ? (
                  <div className="skeleton-list" aria-label="Loading telemetry ledger">
                    <div className="skeleton-row" />
                    <div className="skeleton-row" />
                    <div className="skeleton-row" />
                    <div className="skeleton-row" />
                  </div>
                ) : filteredEvents.length === 0 ? (
                  <div className="empty-state">
                    <p className="empty-state__title">No matching kernel events</p>
                    <p className="empty-state__desc">
                      {events.length === 0
                        ? "Start the eBPF sensor or launch a fileless payload below to populate the interception ledger."
                        : "No events match the active filter. Switch back to All events to inspect captured syscalls."}
                    </p>
                    {events.length > 0 && (
                      <button type="button" className="btn btn--sm" onClick={() => setFilter("all")}>
                        Show all events
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table className="ledger">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th className="num">PID</th>
                          <th>Syscall</th>
                          <th>Process</th>
                          <th className="num">Score</th>
                          <th className="num">Entropy</th>
                          <th>Verdict</th>
                          <th className="num">MTTI</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredEvents.slice(0, 60).map((ev) => {
                          const isSelected = selectedEvent && selectedEvent.id === ev.id;
                          const isFrozen = ev.action === "FROZEN";
                          return (
                            <tr
                              key={ev.id}
                              tabIndex={0}
                              className={`${isFrozen ? "is-frozen" : ""} ${isSelected ? "is-selected" : ""}`}
                              onClick={() => setSelectedId(ev.id)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter" || e.key === " ") {
                                  e.preventDefault();
                                  setSelectedId(ev.id);
                                }
                              }}
                            >
                              <td className="num">{ev.ts}</td>
                              <td className="num">{ev.pid}</td>
                              <td>{ev.type}</td>
                              <td>
                                <span className="ledger__proc">{ev.comm || "unknown"}</span>
                                {ev.name && <span className="ledger__sub">{ev.name}</span>}
                              </td>
                              <td className="num">
                                {engine === "ml" && ev.ml
                                  ? `${(ev.ml.prob * 100).toFixed(0)}%`
                                  : ev.score}
                              </td>
                              <td className="num">
                                {typeof ev.entropy === "number" ? ev.entropy.toFixed(2) : "n/a"}
                              </td>
                              <td>
                                <span className={`state-word ${actionClass(ev.action)}`}>
                                  {formatActionLabel(ev.action)}
                                </span>
                              </td>
                              <td className="num">
                                {typeof ev.mtti_ms === "number" ? `${ev.mtti_ms.toFixed(2)} ms` : "n/a"}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}

                <p className="helper-line" aria-live="polite">
                  {actionNotice}
                </p>
              </section>

              <div className="side-stack">
                <InspectorPane
                  selected={selectedEvent}
                  quarantine={quarantine}
                  busyPid={busyPid}
                  onResume={handleResume}
                  onRequestKill={(pid, comm) => setKillTarget({ pid, comm })}
                  onSelectPid={handleSelectPid}
                />
                <MttiStrip events={events} />
              </div>
            </div>

            <DemoLab
              runningAction={runningDemo}
              resultsByAction={demoResults}
              onRunDemo={handleRunDemo}
            />
          </>
        )}
      </main>

      <dialog
        ref={dialogRef}
        className="confirm-dialog"
        aria-labelledby="kill-dialog-title"
        onCancel={(e) => {
          e.preventDefault();
          setKillTarget(null);
        }}
      >
        <h2 id="kill-dialog-title">Terminate frozen process?</h2>
        <p className="confirm-dialog__body">
          {killTarget
            ? `Sending SIGKILL immediately destroys PID ${killTarget.pid} (${killTarget.comm}) and frees its anonymous memfd image. This cannot be undone.`
            : ""}
        </p>
        <div className="confirm-dialog__actions">
          <button
            type="button"
            className="btn"
            onClick={() => setKillTarget(null)}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn--primary"
            onClick={confirmKill}
          >
            Terminate process
          </button>
        </div>
      </dialog>
    </div>
  );
}
