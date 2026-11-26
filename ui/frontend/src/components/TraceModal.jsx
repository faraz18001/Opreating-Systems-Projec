import { useEffect, useRef, useState } from "react";

function formatMs(val) {
  if (typeof val !== "number" || Number.isNaN(val)) return "—";
  if (val < 0.1) return `${(val * 1000).toFixed(1)} µs`;
  return `${val.toFixed(3)} ms`;
}

function outcomeTone(outcome) {
  if (outcome === "FROZEN") return "badge--frozen";
  if (outcome === "ALLOWED") return "badge--allow";
  if (outcome === "EXFILTRATED" || outcome === "FALSE_POSITIVE") return "badge--danger";
  return "badge--muted";
}

export default function TraceModal({ traceId, onClose }) {
  const dialogRef = useRef(null);
  const [trace, setTrace] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return;
    if (traceId && !dlg.open) {
      dlg.showModal();
    } else if (!traceId && dlg.open) {
      dlg.close();
    }
  }, [traceId]);

  useEffect(() => {
    if (!traceId) {
      setTrace(null);
      setError("");
      setCopied(false);
      return;
    }
    const ctrl = new AbortController();
    setLoading(true);
    setError("");
    setCopied(false);
    fetch(`/api/traces/${encodeURIComponent(traceId)}`, { signal: ctrl.signal })
      .then(async (res) => {
        if (!res.ok) {
          const msg = await res.text().catch(() => "");
          throw new Error(msg || `HTTP ${res.status}`);
        }
        return res.json();
      })
      .then((data) => {
        setTrace(data);
        setLoading(false);
      })
      .catch((err) => {
        if (err.name === "AbortError") return;
        setError(err.message || "Failed to load execution trace");
        setLoading(false);
      });
    return () => ctrl.abort();
  }, [traceId]);

  function handleBackdropClick(e) {
    if (e.target === dialogRef.current) {
      onClose();
    }
  }

  async function handleCopyJson() {
    if (!trace) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(trace, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  const timeline = trace?.timeline || [];
  const c2Events = trace?.c2_events || [];
  const summary = trace?.summary || {};
  const defender = trace?.defender || {};

  return (
    <dialog
      ref={dialogRef}
      className="trace-dialog"
      aria-labelledby="trace-dialog-title"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={handleBackdropClick}
    >
      <div className="trace-dialog__surface">
        <header className="trace-dialog__header">
          <div>
            <div className="trace-dialog__title-row">
              <h2 id="trace-dialog-title" className="trace-dialog__title">
                {traceId || "Execution Trace"}
              </h2>
              {trace && (
                <>
                  <span className="badge badge--muted">
                    {trace.kind} / {trace.vector}
                  </span>
                  <span className={`badge ${outcomeTone(trace.outcome)}`}>
                    {trace.outcome}
                  </span>
                </>
              )}
            </div>
            <p className="trace-dialog__sub">
              {trace
                ? `Captured ${trace.ts} (${trace.duration_ms} ms window) · Saved to logs/traces/${trace.trace_id}.json`
                : "Deep execution & kernel telemetry trace"}
            </p>
          </div>
          <div className="trace-dialog__actions">
            {trace && (
              <button type="button" className="btn btn--ghost" onClick={handleCopyJson}>
                {copied ? "Copied JSON" : "Copy JSON"}
              </button>
            )}
            <button type="button" className="btn btn--primary" onClick={onClose}>
              Close
            </button>
          </div>
        </header>

        <div className="trace-dialog__body">
          {loading && <div className="trace-empty">Loading trace telemetry…</div>}
          {error && <div className="notice notice--error">{error}</div>}

          {!loading && !error && trace && (
            <>
              <section className="trace-meta-grid" aria-label="Trace summary">
                <div className="trace-meta-card">
                  <span className="trace-meta-card__lbl">Process Tree</span>
                  <strong className="trace-meta-card__val">
                    root PID {trace.root_pid}
                  </strong>
                  <span className="trace-meta-card__sub">
                    related: {(trace.related_pids || []).join(", ") || trace.root_pid}
                  </span>
                </div>
                <div className="trace-meta-card">
                  <span className="trace-meta-card__lbl">Final State</span>
                  <strong className="trace-meta-card__val">{trace.proc_state}</strong>
                  <span className="trace-meta-card__sub">
                    exit: {trace.exit_code === null || trace.exit_code === undefined ? "running / stopped" : trace.exit_code}
                    {trace.new_quarantine_pids?.length
                      ? ` · quarantined: ${trace.new_quarantine_pids.join(", ")}`
                      : ""}
                  </span>
                </div>
                <div className="trace-meta-card">
                  <span className="trace-meta-card__lbl">Defender Setup</span>
                  <strong className="trace-meta-card__val">
                    {defender.running ? `${defender.engine} (${defender.mode})` : "Sensor stopped"}
                  </strong>
                  <span className="trace-meta-card__sub">
                    events: {summary.event_count ?? 0} ({summary.frozen_events ?? 0} frozen, {summary.allowed_events ?? 0} allow)
                  </span>
                </div>
                <div className="trace-meta-card">
                  <span className="trace-meta-card__lbl">Peak Risk & MTTI</span>
                  <strong className="trace-meta-card__val">
                    score {summary.max_score ?? "—"} · {formatMs(summary.min_mtti_ms)}
                  </strong>
                  <span className="trace-meta-card__sub">
                    entropy: {typeof summary.max_entropy === "number" ? summary.max_entropy.toFixed(2) : "—"} · C2 leaks: {summary.c2_leak_count ?? 0} ({summary.c2_leak_bytes ?? 0} B)
                  </span>
                </div>
              </section>

              <section className="trace-section">
                <h3 className="trace-section__title">Spawned Command</h3>
                <pre className="trace-pre trace-pre--compact">{trace.command}</pre>
              </section>

              <section className="trace-section">
                <h3 className="trace-section__title">
                  Kernel &amp; Classifier Timeline ({timeline.length})
                </h3>
                {timeline.length === 0 ? (
                  <p className="trace-empty">
                    No kernel eBPF telemetry events were matched to PID {trace.root_pid} during this window
                    {defender.running ? "." : " (eBPF sensor was stopped during this run)."}
                  </p>
                ) : (
                  <ol className="trace-timeline">
                    {timeline.map((ev, idx) => (
                      <li key={`${ev.id ?? idx}-${ev.ts}-${ev.pid}`} className="trace-step">
                        <div className="trace-step__head">
                          <span className="trace-step__idx">#{idx + 1}</span>
                          <span className="trace-step__ts">{ev.ts}</span>
                          <strong className="trace-step__type">{ev.type}</strong>
                          <span className="trace-step__pid">
                            PID {ev.pid}
                            {ev.ppid ? ` (PPID ${ev.ppid})` : ""} · {ev.comm || "unknown"}
                            {ev.name ? ` → ${ev.name}` : ""}
                          </span>
                          <span
                            className={`badge ${
                              ev.action === "FROZEN" ? "badge--frozen" : "badge--allow"
                            }`}
                          >
                            {ev.action}
                            {ev.freeze_mode ? ` (${ev.freeze_mode})` : ""}
                          </span>
                        </div>

                        <dl className="detail-dl trace-step__dl">
                          <div>
                            <dt>Score / Entropy</dt>
                            <dd>
                              {ev.score ?? "—"} /{" "}
                              {typeof ev.entropy === "number" ? ev.entropy.toFixed(3) : "—"}
                            </dd>
                          </div>
                          <div>
                            <dt>MTTI</dt>
                            <dd>{formatMs(ev.mtti_ms)}</dd>
                          </div>
                          <div>
                            <dt>VFS / Inode</dt>
                            <dd>
                              {ev.vfs_name || "—"} (ino {ev.vfs_ino ?? "—"}
                              {ev.vfs_memfd ? ", memfd" : ""})
                            </dd>
                          </div>
                          <div>
                            <dt>Executable</dt>
                            <dd className="mono-wrap">{ev.exe || "—"}</dd>
                          </div>
                          <div>
                            <dt>Ancestry</dt>
                            <dd>{(ev.ancestry || []).join(" -> ") || "—"}</dd>
                          </div>
                          <div>
                            <dt>Dual Eval (Heur vs ML)</dt>
                            <dd>
                              {ev.heur_action || "—"} ({ev.heur_score ?? "—"}, {formatMs(ev.heur_ms)}) vs{" "}
                              {ev.ml_action || "—"} (
                              {typeof ev.ml_prob === "number"
                                ? `${(ev.ml_prob * 100).toFixed(1)}%`
                                : "—"}
                              , {formatMs(ev.ml_ms)})
                              {typeof ev.agree === "boolean"
                                ? ` · ${ev.agree ? "Agree" : "Disagree"}`
                                : ""}
                            </dd>
                          </div>
                          {ev.reasons?.length > 0 && (
                            <div className="trace-step__wide">
                              <dt>Rule Triggers &amp; Verdict Reasons</dt>
                              <dd>{ev.reasons.join(" · ")}</dd>
                            </div>
                          )}
                          {ev.error && (
                            <div className="trace-step__wide">
                              <dt>Mitigation Note</dt>
                              <dd>{ev.error}</dd>
                            </div>
                          )}
                          {ev.forensics && (
                            <div className="trace-step__wide">
                              <dt>Carved Memory Forensics</dt>
                              <dd className="mono-wrap">
                                {typeof ev.forensics === "string"
                                  ? ev.forensics
                                  : JSON.stringify(ev.forensics)}
                              </dd>
                            </div>
                          )}
                        </dl>
                      </li>
                    ))}
                  </ol>
                )}
              </section>

              <section className="trace-io-grid">
                <div className="trace-section">
                  <h3 className="trace-section__title">Process stdout / stderr</h3>
                  <pre className="trace-pre">
                    {trace.stdout || trace.stderr
                      ? [
                          trace.stdout ? `[stdout]\n${trace.stdout}` : "",
                          trace.stderr ? `[stderr]\n${trace.stderr}` : "",
                        ]
                          .filter(Boolean)
                          .join("\n\n")
                      : "(No userspace stdio flushed — process frozen before buffer flush or silent exit.)"}
                  </pre>
                </div>

                <div className="trace-section">
                  <h3 className="trace-section__title">
                    Mock Loopback C2 Exfiltration ({c2Events.length})
                  </h3>
                  {c2Events.length === 0 ? (
                    <p className="trace-empty">
                      Zero C2 loopback leaks recorded on 127.0.0.1 during this trace.
                    </p>
                  ) : (
                    <ul className="trace-c2-list">
                      {c2Events.map((pkt, i) => (
                        <li key={pkt.id ?? i} className="trace-c2-item">
                          <span className="trace-step__ts">{pkt.ts}</span>
                          <span className="badge badge--danger">{pkt.bytes} B</span>
                          <code className="mono-wrap">{pkt.payload}</code>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </section>

              <details className="trace-raw-details">
                <summary>Raw Trace JSON ({trace.trace_id}.json)</summary>
                <pre className="trace-pre">{JSON.stringify(trace, null, 2)}</pre>
              </details>
            </>
          )}
        </div>
      </div>
    </dialog>
  );
}
