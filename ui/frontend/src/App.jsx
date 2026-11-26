import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import CompareModal from "./components/CompareModal.jsx";
import MttiStrip from "./components/MttiStrip.jsx";
import TraceModal from "./components/TraceModal.jsx";

const VALID_VIEWS = ["threats", "all", "traces"];
const ALL_VECTORS = [
  "standard",
  "dup-fd",
  "fork",
  "execve-fd",
  "high-entropy",
  "mmap-exec",
  "scm-fd",
];

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
  const [vector, setVector] = useState("standard");
  const [sensorBusy, setSensorBusy] = useState(false);
  const [attackBusy, setAttackBusy] = useState(false);
  const [sweepProgress, setSweepProgress] = useState(null);
  const [compareOpen, setCompareOpen] = useState(false);
  const [traces, setTraces] = useState([]);
  const [traceQuery, setTraceQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [activeTraceId, setActiveTraceId] = useState(null);
  const [verifyBusy, setVerifyBusy] = useState(null);
  const [busyPid, setBusyPid] = useState(null);
  const [killTarget, setKillTarget] = useState(null);
  const [notice, setNotice] = useState("");
  const dialogRef = useRef(null);
  const sweepAbortRef = useRef(false);

  useEffect(() => {
    writeViewParam(view);
  }, [view]);

  async function refreshSnapshot() {
    setError(null);
    try {
      const res = await fetch("/api/events");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const loadedEvents = data.events || [];
      setEvents(loadedEvents);
      setTraces(data.traces || []);
      if (new URLSearchParams(window.location.search).get("expand") === "first") {
        const latestFrozen = [...loadedEvents].reverse().find((e) => e.action === "FROZEN");
        if (latestFrozen) setExpandedId(latestFrozen.id);
      }
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
    if (new URLSearchParams(window.location.search).get("static") === "1") {
      return undefined;
    }
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

    sse.addEventListener("trace", (e) => {
      try {
        const t = JSON.parse(e.data);
        setTraces((prev) => {
          const next = prev.filter((item) => item.trace_id !== t.trace_id);
          return [t, ...next].slice(0, 200);
        });
        if (t.event_ids?.length) {
          const idSet = new Set(t.event_ids);
          setEvents((prev) =>
            prev.map((ev) => (idSet.has(ev.id) && !ev.trace_id ? { ...ev, trace_id: t.trace_id } : ev))
          );
        }
      } catch {
        // ignore malformed trace frame
      }
    });

    sse.addEventListener("cleared", () => {
      setEvents([]);
      setTraces([]);
      setSearchResults(null);
      setActiveTraceId(null);
      setC2Leaks([]);
      setExpandedId(null);
    });

    return () => sse.close();
  }, []);

  useEffect(() => {
    const q = traceQuery.trim();
    if (!q) {
      setSearchResults(null);
      return undefined;
    }
    const ctrl = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const res = await fetch(`/api/traces?q=${encodeURIComponent(q)}`, { signal: ctrl.signal });
        if (res.ok) {
          const data = await res.json();
          setSearchResults(data.traces || []);
        }
      } catch (err) {
        if (err.name !== "AbortError") setSearchResults(null);
      }
    }, 120);
    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [traceQuery, traces.length]);

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

  const traceIdByEventId = useMemo(() => {
    const m = new Map();
    for (const t of traces) {
      for (const eid of t.event_ids || []) {
        m.set(eid, t.trace_id);
      }
    }
    return m;
  }, [traces]);

  const visibleTraces = useMemo(() => {
    if (traceQuery.trim() && searchResults !== null) {
      return searchResults;
    }
    return traces;
  }, [traces, traceQuery, searchResults]);

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
      const res = await fetch("/api/demo/attack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vector }),
      });
      const data = await res.json();
      await refreshSnapshot();
      const tag = data.trace_id ? `[${data.trace_id}] ` : "";
      if (!data.ok) {
        setError(data.error || "Attack launch failed.");
      } else if (data.frozen && !data.leaked) {
        setNotice(`${tag}Vector ${data.vector} frozen in RAM (PID ${data.pid}). Zero bytes reached mock C2.`);
      } else if (data.frozen && data.leaked) {
        setNotice(`${tag}Vector ${data.vector} frozen (PID ${data.pid}), but payload won the userspace race and leaked to C2.`);
      } else {
        setNotice(`${tag}Sensor is off: vector ${data.vector} (PID ${data.pid}) exfiltrated secret to mock C2.`);
      }
    } finally {
      setAttackBusy(false);
    }
  }

  async function handleAutoSweep() {
    if (sweepProgress !== null) {
      sweepAbortRef.current = true;
      return;
    }

    sweepAbortRef.current = false;
    setAttackBusy(true);
    let frozenTotal = 0;
    let leakedTotal = 0;
    let completed = 0;

    try {
      for (let i = 0; i < ALL_VECTORS.length; i++) {
        if (sweepAbortRef.current) break;
        const v = ALL_VECTORS[i];
        setVector(v);
        setSweepProgress({ idx: i + 1, total: ALL_VECTORS.length, vector: v });
        setNotice(`Auto-sweep (${i + 1}/${ALL_VECTORS.length}): launching vector ${v}…`);

        const res = await fetch("/api/demo/attack", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ vector: v }),
        });
        const data = await res.json();
        completed += 1;
        if (data.frozen) frozenTotal += 1;
        if (data.leaked) leakedTotal += 1;
        await refreshSnapshot();

        if (!sweepAbortRef.current && i < ALL_VECTORS.length - 1) {
          await new Promise((r) => setTimeout(r, 220));
        }
      }
      setNotice(
        sweepAbortRef.current
          ? `Auto-sweep stopped after ${completed}/${ALL_VECTORS.length} vectors (${frozenTotal} frozen, ${leakedTotal} leaked).`
          : `Auto-sweep complete (${completed}/${ALL_VECTORS.length} vectors): ${frozenTotal} frozen, ${leakedTotal} C2 leaks.`
      );
    } finally {
      sweepAbortRef.current = false;
      setSweepProgress(null);
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
    setTraces([]);
    setTraceQuery("");
    setSearchResults(null);
    setActiveTraceId(null);
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

            <select
              className="vector-select"
              aria-label="Attack evasion vector"
              value={vector}
              disabled={attackBusy || sweepProgress !== null}
              onChange={(e) => setVector(e.target.value)}
            >
              <option value="standard">V1 · Standard</option>
              <option value="dup-fd">V2 · dup2 remap</option>
              <option value="fork">V3 · fork handoff</option>
              <option value="execve-fd">V4 · /proc/fd fallback</option>
              <option value="high-entropy">V5 · High-entropy</option>
              <option value="mmap-exec">V6 · mmap W→X</option>
              <option value="scm-fd">V7 · SCM_RIGHTS /proc/pid/fd</option>
            </select>

            <button
              type="button"
              className="btn btn--sm"
              disabled={attackBusy && sweepProgress === null}
              aria-busy={sweepProgress !== null}
              onClick={handleAutoSweep}
            >
              {sweepProgress !== null
                ? `Stop (${sweepProgress.idx}/${sweepProgress.total})`
                : "Run all (7)"}
            </button>

            <button
              type="button"
              className="btn btn--primary"
              disabled={attackBusy || sweepProgress !== null}
              aria-busy={attackBusy && sweepProgress === null}
              onClick={handleSimulateAttack}
            >
              {attackBusy && sweepProgress === null ? "Launching…" : "Simulate attack"}
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
                  <button
                    type="button"
                    role="tab"
                    className="view-tab"
                    aria-selected={view === "traces"}
                    onClick={() => setView("traces")}
                  >
                    Traces ({traces.length})
                  </button>
                </div>

                <button
                  type="button"
                  className="btn-link"
                  disabled={events.length === 0 && c2Leaks.length === 0 && traces.length === 0}
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
            ) : view === "traces" ? (
              <div className="traces-panel">
                <div className="trace-search-bar">
                  <input
                    type="search"
                    className="trace-search-input"
                    value={traceQuery}
                    onChange={(e) => setTraceQuery(e.target.value)}
                    placeholder="Search trace ID (TRC-0001), PID, vector, syscall, inode, stdout, or C2 payload…"
                    aria-label="Search execution traces"
                  />
                  {traceQuery && (
                    <button
                      type="button"
                      className="btn btn--ghost"
                      onClick={() => setTraceQuery("")}
                    >
                      Clear
                    </button>
                  )}
                </div>

                {visibleTraces.length === 0 ? (
                  <div className="empty-state">
                    <p className="empty-state__title">
                      {traceQuery.trim()
                        ? `No traces matching "${traceQuery.trim()}"`
                        : "No execution traces recorded yet"}
                    </p>
                    <p className="empty-state__desc">
                      Run Simulate attack or Run all (7) to capture deep per-iteration logs and click any trace ID to inspect it.
                    </p>
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table className="ledger trace-ledger">
                      <thead>
                        <tr>
                          <th>Trace</th>
                          <th>Vector</th>
                          <th>PIDs</th>
                          <th>Timeline</th>
                          <th>Outcome</th>
                          <th className="num">MTTI</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleTraces.map((t) => {
                          const isFrozen = t.outcome === "FROZEN";
                          const isLeak = t.outcome === "EXFILTRATED" || t.outcome === "FALSE_POSITIVE";
                          const isAllow = t.outcome === "ALLOWED";
                          return (
                            <tr
                              key={t.trace_id}
                              tabIndex={0}
                              className={isFrozen ? "is-frozen" : ""}
                              onClick={() => setActiveTraceId(t.trace_id)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter" || e.key === " ") {
                                  e.preventDefault();
                                  setActiveTraceId(t.trace_id);
                                }
                              }}
                            >
                              <td>
                                <button
                                  type="button"
                                  className="trace-pill"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setActiveTraceId(t.trace_id);
                                  }}
                                >
                                  {t.trace_id}
                                </button>
                              </td>
                              <td>
                                <span className="ledger__proc">{t.vector}</span>
                                <span className="ledger__sub">
                                  {t.kind} · {t.ts}
                                </span>
                              </td>
                              <td className="num">
                                {t.root_pid}
                                {(t.related_pids?.length || 0) > 1
                                  ? ` (+${t.related_pids.length - 1})`
                                  : ""}
                              </td>
                              <td>
                                <span>{t.summary?.event_count ?? 0} ev</span>
                                {t.types?.length > 0 && (
                                  <span className="ledger__sub">{t.types.join(", ")}</span>
                                )}
                              </td>
                              <td>
                                <span
                                  className={`state-word ${
                                    isFrozen
                                      ? "state-word--frozen"
                                      : isAllow
                                      ? "state-word--allow"
                                      : isLeak
                                      ? "state-word--danger"
                                      : ""
                                  }`}
                                >
                                  {t.outcome}
                                </span>
                                {(t.summary?.c2_leak_count || 0) > 0 && (
                                  <span className="ledger__sub">
                                    C2 {t.summary.c2_leak_bytes} B
                                  </span>
                                )}
                              </td>
                              <td className="num">
                                {formatMtti(t.summary?.min_mtti_ms)}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
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
                      const rowTraceId = ev.trace_id || traceIdByEventId.get(ev.id) || null;
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
                              {rowTraceId && (
                                <button
                                  type="button"
                                  className="trace-pill trace-pill--inline"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setActiveTraceId(rowTraceId);
                                  }}
                                  title={`Inspect deep execution trace ${rowTraceId}`}
                                >
                                  {rowTraceId}
                                </button>
                              )}
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
                                    {rowTraceId && (
                                      <>
                                        <dt>Trace ID</dt>
                                        <dd>
                                          <button
                                            type="button"
                                            className="trace-pill"
                                            onClick={() => setActiveTraceId(rowTraceId)}
                                          >
                                            Open {rowTraceId}
                                          </button>
                                        </dd>
                                      </>
                                    )}
                                    <dt>Executable</dt>
                                    <dd>{ev.exe || "exited before read"}</dd>

                                    <dt>Ancestry</dt>
                                    <dd>
                                      {ev.ancestry?.length ? ev.ancestry.join(" / ") : "unavailable"}
                                    </dd>

                                    <dt>Boundary</dt>
                                    <dd>{ev.freeze_mode || "passive"}</dd>

                                    {ev.vfs_memfd && (
                                      <>
                                        <dt>Kernel VFS</dt>
                                        <dd className="num">
                                          {`${ev.vfs_name || "memfd"} (tmpfs inode ${ev.vfs_ino})`}
                                        </dd>
                                      </>
                                    )}

                                    {ev.forensics && (
                                      <>
                                        <dt>RAM dump</dt>
                                        <dd className="num">
                                          {`${(ev.forensics.size_bytes / 1024).toFixed(1)} KB ${
                                            ev.forensics.elf?.valid_elf
                                              ? `ELF${ev.forensics.elf.bits || 64} ${ev.forensics.elf.arch || ""}`.trim()
                                              : "image"
                                          }, sha256 ${ev.forensics.sha256.slice(0, 16)}…`}
                                          {ev.forensics.iocs?.length > 0
                                            ? ` (IOCs: ${ev.forensics.iocs.join(", ")})`
                                            : ""}
                                        </dd>
                                      </>
                                    )}

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
            <MttiStrip events={events} onOpenCompare={() => setCompareOpen(true)} />

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
                      <button
                        type="button"
                        className="btn-link"
                        onClick={() => setCompareOpen(true)}
                      >
                        Graph
                      </button>
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

      <CompareModal
        open={compareOpen}
        events={events}
        onClose={() => setCompareOpen(false)}
      />

      <TraceModal
        traceId={activeTraceId}
        onClose={() => setActiveTraceId(null)}
      />

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
