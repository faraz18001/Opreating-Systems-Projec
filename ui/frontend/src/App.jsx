import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import MttiStrip from "./components/MttiStrip.jsx";

const VALID_VIEWS = ["threats", "all"];

function readViewParam() {
  const val = new URLSearchParams(window.location.search).get("view");
  return VALID_VIEWS.includes(val) ? val : "threats";
}

function writeViewParam(view) {
  const params = new URLSearchParams(window.location.search);
  params.set("view", view);
  window.history.replaceState(null, "", `${window.location.pathname}?${params.toString()}`);
}

function formatMtti(ms) {
  if (typeof ms !== "number") return "n/a";
  if (ms < 0.1) return `${(ms * 1000).toFixed(1)} µs`;
  return `${ms.toFixed(2)} ms`;
}

export default function App() {
  const [view, setView] = useState(readViewParam);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [status, setStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [quarantine, setQuarantine] = useState([]);
  const [c2Leaks, setC2Leaks] = useState([]);
  const [expandedId, setExpandedId] = useState(null);
  const [showModels, setShowModels] = useState(false);
  const [sensorBusy, setSensorBusy] = useState(false);
  const [attackBusy, setAttackBusy] = useState(false);
  const [verifyBusy, setVerifyBusy] = useState(null);
  const [busyPid, setBusyPid] = useState(null);
  const [killTarget, setKillTarget] = useState(null);
  const [notice, setNotice] = useState("");
  const dialogRef = useRef(null);

  useEffect(() => {
    writeViewParam(view);
  }, [view]);

  async function refreshSnapshot() {
    setError(null);
    try {
      const res = await fetch("/api/events");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setEvents(data.events || []);
      setQuarantine(data.quarantine || []);
      setC2Leaks(data.c2_leaks || []);
      setStatus(data.status || null);
    } catch (err) {
      setError(`Backend unreachable (${err.message}). Start sudo python3 ui/server.py --auto-start.`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refreshSnapshot();
    const sse = new EventSource("/api/stream");

    sse.addEventListener("telemetry", (e) => {
      try {
        const rec = JSON.parse(e.data);
        setEvents((prev) => [...prev.slice(-299), rec]);
        setError(null);
      } catch {
        // ignore malformed frame
      }
    });

    sse.addEventListener("status", (e) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.status) setStatus(payload.status);
        if (payload.quarantine) setQuarantine(payload.quarantine);
        if (payload.c2_leaks) setC2Leaks(payload.c2_leaks);
      } catch {
        // ignore malformed status
      }
    });

    sse.addEventListener("cleared", () => {
      setEvents([]);
      setC2Leaks([]);
      setExpandedId(null);
    });

    return () => sse.close();
  }, []);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (killTarget && !dialog.open) dialog.showModal();
    else if (!killTarget && dialog.open) dialog.close();
  }, [killTarget]);

  const rows = useMemo(() => {
    const rev = [...events].reverse();
    if (view === "threats") {
      return rev.filter((e) => e.action !== "ALLOW");
    }
    return rev;
  }, [events, view]);

  const frozenCount = useMemo(
    () => events.filter((e) => e.action === "FROZEN").length,
    [events]
  );

  const allowedCount = useMemo(
    () => events.filter((e) => e.action === "ALLOW").length,
    [events]
  );

  async function handleToggleSensor(nextActive) {
    setSensorBusy(true);
    setNotice("");
    try {
      const url = nextActive ? "/api/defender/start" : "/api/defender/stop";
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const data = await res.json();
      setStatus(data);
      if (data.last_error) setError(data.last_error);
      else setError(null);
    } catch (err) {
      setError(`Sensor toggle failed: ${err.message}`);
    } finally {
      setSensorBusy(false);
    }
  }

  async function handleReconfigure(patch, message) {
    setSensorBusy(true);
    setNotice("");
    try {
      const res = await fetch("/api/defender/mode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      const data = await res.json();
      setStatus(data);
      if (data.last_error) setError(data.last_error);
      else {
        setError(null);
        setNotice(message);
      }
    } catch (err) {
      setError(`Configuration change failed: ${err.message}`);
    } finally {
      setSensorBusy(false);
    }
  }

  async function handleSimulateAttack() {
    setAttackBusy(true);
    setNotice("");
    try {
      const res = await fetch("/api/demo/attack", { method: "POST" });
      const data = await res.json();
      await refreshSnapshot();
      if (!data.ok) {
        setError(data.error || "Attack launch failed.");
      } else if (data.frozen && !data.leaked) {
        setNotice(`PID ${data.pid} frozen in RAM. Zero bytes reached mock C2.`);
      } else if (data.frozen && data.leaked) {
        setNotice(`PID ${data.pid} frozen, but payload won the userspace race and leaked to C2.`);
      } else {
        setNotice(`Sensor is off: PID ${data.pid} exfiltrated secret to mock C2.`);
      }
    } finally {
      setAttackBusy(false);
    }
  }

  async function handleVerify(action) {
    setVerifyBusy(action);
    try {
      await fetch(`/api/demo/${action}`, { method: "POST" });
      await refreshSnapshot();
    } finally {
      setVerifyBusy(null);
    }
  }

  async function handleResume(pid) {
    setBusyPid(pid);
    try {
      const res = await fetch(`/api/process/${pid}/resume`, { method: "POST" });
      const data = await res.json();
      if (data.quarantine) setQuarantine(data.quarantine);
      setNotice(data.ok ? `Sent SIGCONT to PID ${pid}.` : `Resume failed: ${data.error}`);
    } finally {
      setBusyPid(null);
    }
  }

  async function confirmKill() {
    if (!killTarget) return;
    const { pid } = killTarget;
    setKillTarget(null);
    setBusyPid(pid);
    try {
      const res = await fetch(`/api/process/${pid}/kill`, { method: "POST" });
      const data = await res.json();
      if (data.quarantine) setQuarantine(data.quarantine);
      setNotice(data.ok ? `Terminated PID ${pid} with SIGKILL.` : `Kill failed: ${data.error}`);
    } finally {
      setBusyPid(null);
    }
  }

  async function handleReset() {
    await fetch("/api/events/clear", { method: "POST" });
    setEvents([]);
    setC2Leaks([]);
    setExpandedId(null);
    setNotice("");
  }

  const isInKernel = status ? status.kernel_freeze : true;
  const activeEngine = status?.engine || "heuristic";
  const latestLeak = c2Leaks.length > 0 ? c2Leaks[c2Leaks.length - 1] : null;
  const mlModels = status?.ml_metrics?.models || [];
  const selectedModelKey = status?.ml_metrics?.selected_model || "random_forest";

  return (
    <div className="shell">
      <header className="topbar">
        <div className="container topbar__inner">
          <div className="topbar__brand">
            <a href="/" className="wordmark" aria-label="MemGuard home">
              <svg width="18" height="18" viewBox="0 0 20 20" aria-hidden="true">
                <circle cx="10" cy="10" r="8" fill="none" stroke="var(--color-accent)" strokeWidth="1.5" />
                <circle cx="10" cy="10" r="3" fill="var(--color-accent-2)" />
              </svg>
              <span>MemGuard</span>
            </a>

            <nav className="mode-nav" role="tablist" aria-label="Classifier engine">
              <button
                type="button"
                role="tab"
                className="mode-tab"
                disabled={sensorBusy}
                aria-selected={activeEngine === "heuristic"}
                onClick={() =>
                  handleReconfigure({ engine: "heuristic" }, "Switched active classifier to Heuristic (ML shadow).")
                }
              >
                Heuristic
              </button>
              <button
                type="button"
                role="tab"
                className="mode-tab"
                disabled={sensorBusy || !status?.ml_available}
                aria-selected={activeEngine === "ml"}
                onClick={() =>
                  handleReconfigure({ engine: "ml" }, "Switched active classifier to Random Forest ML.")
                }
              >
                ML
              </button>
            </nav>

            <span className="topbar__sep" aria-hidden="true" />

            <nav className="mode-nav" role="tablist" aria-label="Freeze boundary">
              <button
                type="button"
                role="tab"
                className="mode-tab"
                disabled={sensorBusy}
                aria-selected={isInKernel}
                onClick={() =>
                  handleReconfigure({ kernel_freeze: true }, "Switched to in-kernel bpf_send_signal(SIGSTOP).")
                }
              >
                In-kernel
              </button>
              <button
                type="button"
                role="tab"
                className="mode-tab"
                disabled={sensorBusy}
                aria-selected={!isInKernel}
                onClick={() =>
                  handleReconfigure({ kernel_freeze: false }, "Switched to userspace pidfd_send_signal(SIGSTOP).")
                }
              >
                Userspace
              </button>
            </nav>
          </div>

          <div className="topbar__controls">
            <label className="switch">
              <input
                type="checkbox"
                role="switch"
                className="switch__input"
                checked={Boolean(status?.running)}
                disabled={sensorBusy || (!status?.is_root && !status?.running)}
                onChange={(e) => handleToggleSensor(e.target.checked)}
              />
              <span className="switch__track" aria-hidden="true" />
              <span className="switch__label" role="status">
                {status?.running ? "Sensor active" : "Sensor off"}
              </span>
            </label>

            <button
              type="button"
              className="btn btn--primary"
              disabled={attackBusy}
              aria-busy={attackBusy}
              onClick={handleSimulateAttack}
            >
              {attackBusy ? "Launching…" : "Simulate attack"}
            </button>
          </div>
        </div>
      </header>

      <main id="main" className="container main">
        <div className="page-head">
          <h1>Fileless execution ledger</h1>
          <p className="page-head__meta">
            {status
              ? `Linux ${status.kernel}, ${status.probes} eBPF tracepoints, ${activeEngine} classifier, ${
                  isInKernel ? "bpf_send_signal" : "pidfd_send_signal"
                }`
              : "Connecting to eBPF sensor…"}
          </p>
        </div>

        {error && (
          <div className="error-banner" role="alert">
            <span>{error}</span>
            <button type="button" className="btn btn--sm" onClick={refreshSnapshot}>
              Retry
            </button>
          </div>
        )}

        <div className="workspace">
          <section className="glass-panel" aria-labelledby="ledger-heading">
            <div className="panel-head">
              <div>
                <h2 id="ledger-heading">Interception stream</h2>
                <p className="panel-head__sub">
                  Select any row to inspect /proc telemetry, dual-engine scores, and quarantine actions.
                </p>
              </div>

              <div className="ledger-tools">
                <div className="view-switch" role="tablist" aria-label="Filter stream">
                  <button
                    type="button"
                    role="tab"
                    className="view-tab"
                    aria-selected={view === "threats"}
                    onClick={() => setView("threats")}
                  >
                    Threats ({frozenCount})
                  </button>
                  <button
                    type="button"
                    role="tab"
                    className="view-tab"
                    aria-selected={view === "all"}
                    onClick={() => setView("all")}
                  >
                    All ({events.length})
                  </button>
                </div>

                <button
                  type="button"
                  className="btn-link"
                  disabled={events.length === 0 && c2Leaks.length === 0}
                  onClick={handleReset}
                >
                  Reset
                </button>
              </div>
            </div>

            {loading ? (
              <div className="skeleton-list" aria-label="Loading stream">
                <div className="skeleton-row" />
                <div className="skeleton-row" />
                <div className="skeleton-row" />
              </div>
            ) : rows.length === 0 ? (
              <div className="empty-state">
                <p className="empty-state__title">
                  {view === "threats" ? "No threats intercepted yet" : "No kernel events captured yet"}
                </p>
                <p className="empty-state__desc">
                  Click Simulate attack to execute the sealed memfd ELF payload and watch interception in real time.
                </p>
              </div>
            ) : (
              <div className="table-wrap">
                <table className="ledger">
                  <thead>
                    <tr>
                      <th className="num">PID</th>
                      <th>Process</th>
                      <th>Syscall</th>
                      <th>Verdict</th>
                      <th className="num">MTTI</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.slice(0, 40).map((ev) => {
                      const isExpanded = expandedId === ev.id;
                      const isFrozen = ev.action === "FROZEN";
                      const isHeld = quarantine.includes(ev.pid);
                      return (
                        <Fragment key={ev.id}>
                          <tr
                            tabIndex={0}
                            className={`${isFrozen ? "is-frozen" : ""} ${isExpanded ? "is-selected" : ""}`}
                            onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" || e.key === " ") {
                                e.preventDefault();
                                setExpandedId(isExpanded ? null : ev.id);
                              }
                            }}
                          >
                            <td className="num">{ev.pid}</td>
                            <td>
                              <span className="ledger__proc">{ev.comm || "unknown"}</span>
                              {ev.name && <span className="ledger__sub">{ev.name}</span>}
                            </td>
                            <td>{ev.type}</td>
                            <td>
                              <span className={`state-word ${isFrozen ? "state-word--frozen" : "state-word--allow"}`}>
                                {isFrozen ? (isHeld ? "Frozen" : "Frozen (exited)") : "Allowed"}
                              </span>
                            </td>
                            <td className="num">{formatMtti(ev.mtti_ms)}</td>
                          </tr>

                          {isExpanded && (
                            <tr className="detail-row">
                              <td colSpan={5}>
                                <div className="inline-detail">
                                  <dl className="detail-dl">
                                    <dt>Executable</dt>
                                    <dd>{ev.exe || "exited before read"}</dd>

                                    <dt>Ancestry</dt>
                                    <dd>
                                      {ev.ancestry?.length ? ev.ancestry.join(" / ") : "unavailable"}
                                    </dd>

                                    <dt>Boundary</dt>
                                    <dd>{ev.freeze_mode || "passive"}</dd>

                                    <dt>Heuristic</dt>
                                    <dd className="num">
                                      {ev.heur_action
                                        ? `${ev.heur_action} (score ${ev.heur_score}, ${ev.heur_ms?.toFixed(3)} ms)`
                                        : `score ${ev.score}`}
                                    </dd>

                                    {ev.ml_action && (
                                      <>
                                        <dt>ML shadow</dt>
                                        <dd className="num">
                                          {`${ev.ml_action} (P=${ev.ml_prob?.toFixed(2)}, ${ev.ml_ms?.toFixed(3)} ms)`}
                                          {ev.agree !== null && (ev.agree ? ", agrees" : ", diverges")}
                                        </dd>
                                      </>
                                    )}

                                    <dt>Entropy</dt>
                                    <dd className="num">
                                      {typeof ev.entropy === "number" ? `${ev.entropy.toFixed(2)} bits` : "n/a"}
                                    </dd>

                                    <dt>Signals</dt>
                                    <dd>{ev.reasons?.join("; ") || "none"}</dd>
                                  </dl>

                                  {isHeld && (
                                    <div className="action-row">
                                      <button
                                        type="button"
                                        className="btn btn--sm"
                                        disabled={busyPid === ev.pid}
                                        onClick={() => handleResume(ev.pid)}
                                      >
                                        Resume (SIGCONT)
                                      </button>
                                      <button
                                        type="button"
                                        className="btn btn--sm btn--warn-text"
                                        disabled={busyPid === ev.pid}
                                        onClick={() =>
                                          setKillTarget({ pid: ev.pid, comm: ev.ancestry?.[0] || ev.comm })
                                        }
                                      >
                                        Terminate (SIGKILL)
                                      </button>
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            <p className="helper-line" aria-live="polite">
              {notice}
            </p>
          </section>

          <div className="side-stack">
            <MttiStrip events={events} />

            <section className="surface-panel" aria-labelledby="proof-heading">
              <div className="panel-head">
                <div>
                  <h2 id="proof-heading">Evaluation metrics</h2>
                  <p className="panel-head__sub">Live proof against mock C2, ML shadow, /proc/io, and FIM.</p>
                </div>
              </div>

              <ul className="proof-list">
                <li className="proof-row">
                  <div>
                    <span className="proof-row__label">C2 exfiltration</span>
                    <span className="proof-row__sub">
                      {latestLeak
                        ? `Last leak at ${latestLeak.ts} (${latestLeak.bytes} B)`
                        : "Loopback listener active, 0 secrets stolen"}
                    </span>
                  </div>
                  <span
                    className={`proof-row__val num ${
                      c2Leaks.length > 0 ? "state-word--frozen" : "state-word--allow"
                    }`}
                  >
                    {c2Leaks.length === 0 ? "0 B leaked" : `${c2Leaks.length} leaked`}
                  </span>
                </li>

                <li className="proof-row proof-row--stack">
                  <div className="proof-row__top">
                    <div>
                      <span className="proof-row__label">ML vs Heuristic</span>
                      <span className="proof-row__sub">
                        {typeof status?.avg_ml_infer_ms === "number" && typeof status?.avg_heuristic_infer_ms === "number"
                          ? `Heur ${status.avg_heuristic_infer_ms.toFixed(3)} ms vs ML ${status.avg_ml_infer_ms.toFixed(3)} ms`
                          : status?.ml_available
                          ? `${status?.ml_metrics?.selected_label || "Random Forest"} ready (${status?.ml_metrics?.dataset?.total_rows || 0} samples)`
                          : "Model bundle not trained"}
                      </span>
                    </div>
                    <div className="proof-row__right">
                      <span className="proof-row__val num">
                        {typeof status?.agreement_rate === "number"
                          ? `${status.agreement_rate.toFixed(0)}% agree`
                          : status?.ml_available
                          ? "Ready"
                          : "Offline"}
                      </span>
                      {mlModels.length > 0 && (
                        <button
                          type="button"
                          className="btn-link"
                          aria-expanded={showModels}
                          onClick={() => setShowModels((v) => !v)}
                        >
                          {showModels ? "Hide" : "Models"}
                        </button>
                      )}
                    </div>
                  </div>

                  {showModels && mlModels.length > 0 && (
                    <table className="mini-table" aria-label="Trained ML model benchmark">
                      <thead>
                        <tr>
                          <th>Model</th>
                          <th className="num">F1</th>
                          <th className="num">FPR</th>
                          <th className="num">Infer</th>
                        </tr>
                      </thead>
                      <tbody>
                        {mlModels.map((m) => (
                          <tr key={m.key} className={m.key === selectedModelKey ? "is-selected-row" : ""}>
                            <td>{m.label}</td>
                            <td className="num">{(m.f1 * 100).toFixed(0)}%</td>
                            <td className="num">{(m.fpr * 100).toFixed(0)}%</td>
                            <td className="num">{m.avg_infer_ms.toFixed(2)} ms</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </li>

                <li className="proof-row">
                  <div>
                    <span className="proof-row__label">Physical disk I/O</span>
                    <span className="proof-row__sub">
                      {status?.disk_io_proof
                        ? `${status.disk_io_proof.ram_bytes} B written to RAM at ${status.disk_io_proof.ts}`
                        : "Measures physical write_bytes during execution"}
                    </span>
                  </div>
                  <div className="proof-row__right">
                    <span className="proof-row__val num">
                      {status?.disk_io_proof ? `${status.disk_io_proof.write_bytes} B` : "Unverified"}
                    </span>
                    <button
                      type="button"
                      className="btn-link"
                      disabled={verifyBusy !== null}
                      onClick={() => handleVerify("disk-io")}
                    >
                      {verifyBusy === "disk-io" ? "Checking…" : "Verify"}
                    </button>
                  </div>
                </li>

                <li className="proof-row">
                  <div>
                    <span className="proof-row__label">False positives</span>
                    <span className="proof-row__sub">Benign memfd buffers allowed without disruption</span>
                  </div>
                  <div className="proof-row__right">
                    <span className="proof-row__val num">{allowedCount} allowed</span>
                    <button
                      type="button"
                      className="btn-link"
                      disabled={verifyBusy !== null}
                      onClick={() => handleVerify("benign")}
                    >
                      {verifyBusy === "benign" ? "Testing…" : "Test"}
                    </button>
                  </div>
                </li>

                <li className="proof-row">
                  <div>
                    <span className="proof-row__label">Traditional FIM (inotify)</span>
                    <span className="proof-row__sub">
                      {status?.fim_proof
                        ? `Checked at ${status.fim_proof.ts} on /tmp and /dev/shm`
                        : "Compare disk-based FIM against fileless payload"}
                    </span>
                  </div>
                  <div className="proof-row__right">
                    <span className="proof-row__val num">
                      {status?.fim_proof ? `${status.fim_proof.detected} caught` : "Unchecked"}
                    </span>
                    <button
                      type="button"
                      className="btn-link"
                      disabled={verifyBusy !== null}
                      onClick={() => handleVerify("fim")}
                    >
                      {verifyBusy === "fim" ? "Running…" : "Compare"}
                    </button>
                  </div>
                </li>

                <li className="proof-row">
                  <div>
                    <span className="proof-row__label">Defender overhead</span>
                    <span className="proof-row__sub">Resident memory of Python + eBPF userspace</span>
                  </div>
                  <span className="proof-row__val num">
                    {status?.running ? `${status.rss_mb.toFixed(1)} MB` : "0.0 MB"}
                  </span>
                </li>
              </ul>
            </section>
          </div>
        </div>
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
            ? `Sending SIGKILL destroys PID ${killTarget.pid} (${killTarget.comm}) and frees its anonymous memfd image.`
            : ""}
        </p>
        <div className="confirm-dialog__actions">
          <button type="button" className="btn" onClick={() => setKillTarget(null)}>
            Cancel
          </button>
          <button type="button" className="btn btn--primary" onClick={confirmKill}>
            Terminate
          </button>
        </div>
      </dialog>
    </div>
  );
}
