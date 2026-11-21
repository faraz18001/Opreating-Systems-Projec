import { useState } from "react";

const SCENARIOS = [
  {
    id: "attack",
    name: "Fileless memfd payload",
    detail: "Decrypts an ELF in RAM, seals memfd, calls execveat, and spoofs [kworker/u8:2].",
    cta: "Launch attack",
    tone: "threat",
  },
  {
    id: "benign",
    name: "Benign shared memory",
    detail: "Creates a memfd buffer without execution to verify zero false positives.",
    cta: "Run benign",
    tone: "neutral",
  },
  {
    id: "disk-io",
    name: "Physical disk I/O audit",
    detail: "Samples /proc/<pid>/io during execution to confirm 0 bytes written to disk.",
    cta: "Verify disk I/O",
    tone: "neutral",
  },
  {
    id: "fim",
    name: "Traditional FIM baseline",
    detail: "Monitors /tmp, /dev/shm, and build directories via inotify during the attack.",
    cta: "Run FIM baseline",
    tone: "neutral",
  },
];

export default function DemoLab({ runningAction, resultsByAction, onRunDemo }) {
  const [expandedRaw, setExpandedRaw] = useState(null);

  return (
    <section className="glass-panel lab-panel" aria-labelledby="demo-heading">
      <div className="panel-head">
        <div>
          <h2 id="demo-heading">Verification lab</h2>
          <p className="panel-head__sub">
            Run controlled red-team payloads and evaluation checks directly against this kernel.
          </p>
        </div>
      </div>

      <ul className="lab-list">
        {SCENARIOS.map((sc) => {
          const result = resultsByAction[sc.id] || null;
          const isBusy = runningAction === sc.id;
          const metricEntries = result?.metrics ? Object.entries(result.metrics) : [];
          const showRaw = expandedRaw === sc.id && result?.output;

          return (
            <li key={sc.id} className="lab-row">
              <div className="lab-row__main">
                <div className="lab-row__info">
                  <div className="lab-row__title-line">
                    <span className="lab-row__title">{sc.name}</span>
                    {result && (
                      <span
                        className={`lab-verdict ${
                          sc.tone === "threat" || !result.ok
                            ? "lab-verdict--apricot"
                            : "lab-verdict--accent"
                        }`}
                      >
                        {result.verdict || (result.ok ? "Completed" : "Failed")}
                      </span>
                    )}
                  </div>
                  <p className="lab-row__desc">{sc.detail}</p>
                </div>

                <div className="lab-row__controls">
                  {result?.output && (
                    <button
                      type="button"
                      className="btn-link"
                      aria-expanded={Boolean(showRaw)}
                      onClick={() => setExpandedRaw(showRaw ? null : sc.id)}
                    >
                      {showRaw ? "Hide trace" : "Trace"}
                    </button>
                  )}
                  <button
                    type="button"
                    className={`btn btn--rect btn--sm ${sc.tone === "threat" ? "btn--warn-text" : ""}`}
                    disabled={runningAction !== null}
                    aria-busy={isBusy}
                    onClick={() => onRunDemo(sc.id)}
                  >
                    {isBusy ? "Running…" : sc.cta}
                  </button>
                </div>
              </div>

              {metricEntries.length > 0 && (
                <dl className="lab-metrics">
                  {metricEntries.map(([label, val]) => (
                    <div key={label} className="lab-metrics__pair">
                      <dt>{label}</dt>
                      <dd className="num">{val}</dd>
                    </div>
                  ))}
                </dl>
              )}

              {showRaw && (
                <pre className="lab-trace" role="region" aria-label={`${sc.name} raw trace`}>
                  {result.output}
                </pre>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
