export default function InspectorPane({
  selected,
  quarantine,
  busyPid,
  onResume,
  onRequestKill,
  onSelectPid,
}) {
  const isSelectedQuarantined =
    selected && quarantine.some((q) => q.pid === selected.pid);

  return (
    <>
      <section className="surface-panel" aria-labelledby="inspector-heading">
        <div className="panel-head">
          <div>
            <h2 id="inspector-heading">Forensic inspector</h2>
            <p className="panel-head__sub">
              {selected
                ? `PID ${selected.pid} captured at ${selected.ts}`
                : "Select any row in the ledger to inspect its ancestry and score."}
            </p>
          </div>
        </div>

        {!selected ? (
          <div className="empty-state">
            <p className="empty-state__title">No event selected</p>
            <p className="empty-state__desc">
              Choose an interception or benign memfd record from the table to inspect /proc telemetry and rule weights.
            </p>
          </div>
        ) : (
          <>
            <dl className="detail-dl">
              <dt>Syscall</dt>
              <dd>{selected.type}</dd>

              <dt>Process</dt>
              <dd>{selected.comm || "unknown"}</dd>

              <dt>Target name</dt>
              <dd>{selected.name || "none"}</dd>

              <dt>Executable</dt>
              <dd>{selected.exe || "exited before /proc read"}</dd>

              <dt>Ancestry</dt>
              <dd>
                {selected.ancestry && selected.ancestry.length > 0 ? (
                  <ol className="ancestry-list">
                    {selected.ancestry.map((name, i) => (
                      <li key={`${name}-${i}`}>{name}</li>
                    ))}
                  </ol>
                ) : (
                  "unavailable"
                )}
              </dd>

              <dt>Score</dt>
              <dd className="num">{selected.score}</dd>

              <dt>Entropy</dt>
              <dd className="num">
                {typeof selected.entropy === "number"
                  ? `${selected.entropy.toFixed(3)} bits`
                  : "not sampled"}
              </dd>

              <dt>MTTI</dt>
              <dd className="num">
                {typeof selected.mtti_ms === "number"
                  ? `${selected.mtti_ms.toFixed(3)} ms`
                  : "not mitigated"}
              </dd>
            </dl>

            {selected.reasons && selected.reasons.length > 0 && (
              <ul className="reason-list" aria-label="Matched heuristic rules">
                {selected.reasons.map((reason, idx) => (
                  <li key={idx}>{reason}</li>
                ))}
              </ul>
            )}

            {isSelectedQuarantined && (
              <div className="action-row">
                <button
                  type="button"
                  className="btn btn--rect btn--sm"
                  disabled={busyPid === selected.pid}
                  aria-busy={busyPid === selected.pid}
                  onClick={() => onResume(selected.pid)}
                >
                  Resume (SIGCONT)
                </button>
                <button
                  type="button"
                  className="btn btn--rect btn--sm btn--warn-text"
                  disabled={busyPid === selected.pid}
                  onClick={() => onRequestKill(selected.pid, selected.comm)}
                >
                  Terminate (SIGKILL)
                </button>
              </div>
            )}
          </>
        )}
      </section>

      <section className="surface-panel" aria-labelledby="quarantine-heading">
        <div className="panel-head">
          <div>
            <h2 id="quarantine-heading">Quarantined processes</h2>
            <p className="panel-head__sub">
              Live processes currently held in stopped state via pidfd_send_signal.
            </p>
          </div>
          <span className="num tally__label">{quarantine.length} held</span>
        </div>

        {quarantine.length === 0 ? (
          <div className="empty-state">
            <p className="empty-state__title">No frozen processes in memory</p>
            <p className="empty-state__desc">
              Processes intercepted with SIGSTOP appear here until resumed or terminated.
            </p>
          </div>
        ) : (
          <ul className="quarantine-list">
            {quarantine.map((item) => (
              <li key={item.pid} className="quarantine-item">
                <div className="quarantine-item__info">
                  <div className="quarantine-item__title num">
                    PID {item.pid} ({item.ancestry?.[0] || item.comm})
                  </div>
                  <div className="quarantine-item__meta">
                    {item.exe || item.name} ({item.proc_state})
                  </div>
                </div>
                <div className="quarantine-item__actions">
                  <button
                    type="button"
                    className="btn btn--rect btn--sm"
                    onClick={() => onSelectPid(item.pid)}
                  >
                    Inspect
                  </button>
                  <button
                    type="button"
                    className="btn btn--rect btn--sm"
                    disabled={busyPid === item.pid}
                    onClick={() => onResume(item.pid)}
                  >
                    Resume
                  </button>
                  <button
                    type="button"
                    className="btn btn--rect btn--sm btn--warn-text"
                    disabled={busyPid === item.pid}
                    onClick={() => onRequestKill(item.pid, item.ancestry?.[0] || item.comm)}
                  >
                    Kill
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
