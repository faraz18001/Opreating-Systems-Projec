import { useEffect, useMemo, useRef, useState } from "react";

function formatLatency(ms) {
  if (typeof ms !== "number" || Number.isNaN(ms)) return "n/a";
  if (ms < 0.1) return `${(ms * 1000).toFixed(1)} µs`;
  return `${ms.toFixed(3)} ms`;
}

export default function CompareModal({ open, events, onClose }) {
  const dialogRef = useRef(null);
  const [tab, setTab] = useState("latency");
  const [hoverIdx, setHoverIdx] = useState(null);

  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return;
    if (open && !dlg.open) {
      dlg.showModal();
    } else if (!open && dlg.open) {
      dlg.close();
    }
  }, [open]);

  const dualEvents = useMemo(
    () =>
      events
        .filter((e) => typeof e.heur_ms === "number" && typeof e.ml_ms === "number")
        .slice(-20),
    [events]
  );

  const mttiSeries = useMemo(() => {
    const frozen = events.filter((e) => e.action === "FROZEN" && typeof e.mtti_ms === "number");
    const inKernel = frozen.filter((e) => e.freeze_mode === "in-kernel").slice(-18);
    const usrHeur = frozen.filter((e) => e.freeze_mode !== "in-kernel" && e.engine !== "ml").slice(-18);
    const usrMl = frozen.filter((e) => e.freeze_mode !== "in-kernel" && e.engine === "ml").slice(-18);
    return { inKernel, usrHeur, usrMl };
  }, [events]);

  const dualStats = useMemo(() => {
    if (dualEvents.length === 0) return null;
    const hMean = dualEvents.reduce((a, b) => a + b.heur_ms, 0) / dualEvents.length;
    const mMean = dualEvents.reduce((a, b) => a + b.ml_ms, 0) / dualEvents.length;
    const compared = dualEvents.filter((e) => typeof e.agree === "boolean");
    const agreePct = compared.length
      ? (compared.filter((e) => e.agree).length / compared.length) * 100
      : null;
    return {
      hMean,
      mMean,
      speedup: hMean > 0 ? mMean / hMean : null,
      agreePct,
    };
  }, [dualEvents]);

  const width = 620;
  const height = 240;
  const padLeft = 52;
  const padRight = 18;
  const padTop = 18;
  const padBottom = 32;
  const plotW = width - padLeft - padRight;
  const plotH = height - padTop - padBottom;

  function renderDualChart() {
    if (dualEvents.length === 0) {
      return (
        <div className="empty-state">
          <p className="empty-state__title">No dual-scored events recorded yet</p>
          <p className="empty-state__desc">
            Enable the sensor and click Simulate attack or Run all (7) to plot live Heuristic vs. ML latency side by side.
          </p>
        </div>
      );
    }

    const logMin = -2.5;
    const logMax = 1.5;
    const yPos = (ms) => {
      const clamped = Math.max(Math.pow(10, logMin), Math.min(Math.pow(10, logMax), ms));
      const norm = (Math.log10(clamped) - logMin) / (logMax - logMin);
      return padTop + plotH - norm * plotH;
    };
    const xPos = (idx) =>
      dualEvents.length === 1
        ? padLeft + plotW / 2
        : padLeft + (idx / (dualEvents.length - 1)) * plotW;

    const ticks = [
      { v: 0.01, lbl: "10 µs" },
      { v: 0.1, lbl: "0.1 ms" },
      { v: 1.0, lbl: "1 ms" },
      { v: 10.0, lbl: "10 ms" },
    ];
    const exfilY = yPos(0.6);

    const heurPath = dualEvents
      .map((e, i) => `${i === 0 ? "M" : "L"} ${xPos(i).toFixed(1)} ${yPos(e.heur_ms).toFixed(1)}`)
      .join(" ");
    const mlPath = dualEvents
      .map((e, i) => `${i === 0 ? "M" : "L"} ${xPos(i).toFixed(1)} ${yPos(e.ml_ms).toFixed(1)}`)
      .join(" ");

    const activeIdx = hoverIdx !== null && dualEvents[hoverIdx] ? hoverIdx : dualEvents.length - 1;
    const active = dualEvents[activeIdx];

    return (
      <>
        <div className="compare-legend">
          <span className="compare-legend__item">
            <span className="compare-swatch compare-swatch--accent" />
            Heuristic rules (mean {formatLatency(dualStats.hMean)})
          </span>
          <span className="compare-legend__item">
            <span className="compare-swatch compare-swatch--apricot" />
            ML Random Forest (mean {formatLatency(dualStats.mMean)})
          </span>
          <span className="compare-legend__item">
            <span className="compare-swatch compare-swatch--exfil" />
            TCP exfil (~0.6 ms)
          </span>
          {dualStats.agreePct !== null && (
            <span className="compare-legend__meta num">
              {dualStats.agreePct.toFixed(0)}% agreement ({dualStats.speedup?.toFixed(1)}× Heur speedup)
            </span>
          )}
        </div>

        <svg
          className="compare-svg"
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label="Overlapping log-scale Heuristic vs ML decision latency chart"
          onMouseLeave={() => setHoverIdx(null)}
        >
          {ticks.map((t) => {
            const y = yPos(t.v);
            return (
              <g key={t.lbl}>
                <line x1={padLeft} x2={width - padRight} y1={y} y2={y} stroke="var(--color-rule)" strokeWidth="1" />
                <text x={padLeft - 8} y={y + 3.5} textAnchor="end" fill="var(--color-muted)" fontSize="10" className="num">
                  {t.lbl}
                </text>
              </g>
            );
          })}

          <line
            x1={padLeft}
            x2={width - padRight}
            y1={exfilY}
            y2={exfilY}
            stroke="var(--color-error)"
            strokeWidth="1.2"
            strokeDasharray="4 3"
          />
          <text x={width - padRight} y={exfilY - 5} textAnchor="end" fill="var(--color-error)" fontSize="10">
            TCP exfil (~0.6 ms)
          </text>

          <line
            x1={xPos(activeIdx)}
            x2={xPos(activeIdx)}
            y1={padTop}
            y2={padTop + plotH}
            stroke="var(--color-rule)"
            strokeWidth="1"
          />

          {dualEvents.length > 1 && (
            <>
              <path d={mlPath} fill="none" stroke="var(--color-accent-2)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
              <path d={heurPath} fill="none" stroke="var(--color-accent)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
            </>
          )}

          {dualEvents.map((e, i) => {
            const cx = xPos(i);
            const yh = yPos(e.heur_ms);
            const ym = yPos(e.ml_ms);
            const isAct = i === activeIdx;
            const diverged = e.agree === false;
            return (
              <g key={e.id ?? `${e.pid}-${i}`} className="mtti-point" onMouseEnter={() => setHoverIdx(i)}>
                <rect x={cx - 10} y={padTop} width="20" height={plotH} fill="transparent" />
                {diverged && (
                  <circle cx={cx} cy={ym} r="7" fill="none" stroke="var(--color-error)" strokeWidth="1.2" />
                )}
                <circle cx={cx} cy={ym} r={isAct ? 4.5 : 3} fill="var(--color-accent-2)" stroke="var(--color-paper-2)" strokeWidth="1.3" />
                <circle cx={cx} cy={yh} r={isAct ? 4.5 : 3} fill="var(--color-accent)" stroke="var(--color-paper-2)" strokeWidth="1.3" />
              </g>
            );
          })}

          <text x={padLeft} y={height - 8} fill="var(--color-muted)" fontSize="10">
            Event 1
          </text>
          <text x={width - padRight} y={height - 8} textAnchor="end" fill="var(--color-muted)" fontSize="10">
            Event {dualEvents.length}
          </text>
        </svg>

        {active && (
          <div className="compare-readout num">
            <span>
              <strong>PID {active.pid}</strong> ({active.comm} / {active.type})
            </span>
            <span>
              Heur: {formatLatency(active.heur_ms)} [{active.heur_action} · {active.heur_score}]
            </span>
            <span>
              ML: {formatLatency(active.ml_ms)} [{active.ml_action} · P={active.ml_prob?.toFixed(2)}]
            </span>
            <span>{active.agree === false ? "Diverged" : "Agreed"}</span>
          </div>
        )}
      </>
    );
  }

  function renderMttiOverlay() {
    const { inKernel, usrHeur, usrMl } = mttiSeries;
    const maxLen = Math.max(inKernel.length, usrHeur.length, usrMl.length);
    if (maxLen === 0) {
      return (
        <div className="empty-state">
          <p className="empty-state__title">No frozen runs recorded yet</p>
          <p className="empty-state__desc">
            Run Simulate attack in In-kernel mode, then switch to Userspace (Heuristic / ML) to overlap all three end-to-end MTTI curves.
          </p>
        </div>
      );
    }

    const logMin = -3.0;
    const logMax = 2.0;
    const yPos = (ms) => {
      const clamped = Math.max(0.001, Math.min(100, ms));
      const norm = (Math.log10(clamped) - logMin) / (logMax - logMin);
      return padTop + plotH - norm * plotH;
    };
    const xPos = (idx, len) =>
      len <= 1 ? padLeft + plotW / 2 : padLeft + (idx / (Math.max(maxLen, 2) - 1)) * plotW;

    const buildPath = (arr) =>
      arr.map((e, i) => `${i === 0 ? "M" : "L"} ${xPos(i, arr.length).toFixed(1)} ${yPos(e.mtti_ms).toFixed(1)}`).join(" ");

    const meanOf = (arr) => (arr.length ? arr.reduce((a, b) => a + b.mtti_ms, 0) / arr.length : null);
    const ticks = [
      { v: 0.001, lbl: "1 µs" },
      { v: 0.01, lbl: "10 µs" },
      { v: 0.1, lbl: "100 µs" },
      { v: 1.0, lbl: "1 ms" },
      { v: 10.0, lbl: "10 ms" },
      { v: 100.0, lbl: "100 ms" },
    ];
    const exfilY = yPos(0.6);

    return (
      <>
        <div className="compare-legend">
          <span className="compare-legend__item">
            <span className="compare-swatch compare-swatch--accent" />
            In-Kernel VFS ({inKernel.length} · mean {formatLatency(meanOf(inKernel))})
          </span>
          <span className="compare-legend__item">
            <span className="compare-swatch compare-swatch--apricot" />
            Userspace Heuristic ({usrHeur.length} · mean {formatLatency(meanOf(usrHeur))})
          </span>
          <span className="compare-legend__item">
            <span className="compare-swatch compare-swatch--ml" />
            Userspace ML ({usrMl.length} · mean {formatLatency(meanOf(usrMl))})
          </span>
        </div>

        <svg className="compare-svg" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Overlapping log-scale MTTI across In-Kernel and Userspace engines">
          {ticks.map((t) => {
            const y = yPos(t.v);
            return (
              <g key={t.lbl}>
                <line x1={padLeft} x2={width - padRight} y1={y} y2={y} stroke="var(--color-rule)" strokeWidth="1" />
                <text x={padLeft - 8} y={y + 3.5} textAnchor="end" fill="var(--color-muted)" fontSize="10" className="num">
                  {t.lbl}
                </text>
              </g>
            );
          })}

          <line
            x1={padLeft}
            x2={width - padRight}
            y1={exfilY}
            y2={exfilY}
            stroke="var(--color-error)"
            strokeWidth="1.2"
            strokeDasharray="4 3"
          />
          <text x={width - padRight} y={exfilY - 5} textAnchor="end" fill="var(--color-error)" fontSize="10">
            TCP exfil boundary (~0.6 ms)
          </text>

          {[
            { arr: usrMl, col: "#c084fc" },
            { arr: usrHeur, col: "var(--color-accent-2)" },
            { arr: inKernel, col: "var(--color-accent)" },
          ].map(({ arr, col }, sIdx) => (
            <g key={sIdx}>
              {arr.length > 1 && (
                <path d={buildPath(arr)} fill="none" stroke={col} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
              )}
              {arr.map((e, i) => (
                <circle
                  key={e.id ?? `${sIdx}-${i}`}
                  cx={xPos(i, arr.length)}
                  cy={yPos(e.mtti_ms)}
                  r="3.5"
                  fill={col}
                  stroke="var(--color-paper-2)"
                  strokeWidth="1.3"
                >
                  <title>{`PID ${e.pid}: ${formatLatency(e.mtti_ms)} (${e.freeze_mode || "userspace"} / ${e.engine || "heuristic"})`}</title>
                </circle>
              ))}
            </g>
          ))}

          <text x={padLeft} y={height - 8} fill="var(--color-muted)" fontSize="10">
            Run 1
          </text>
          <text x={width - padRight} y={height - 8} textAnchor="end" fill="var(--color-muted)" fontSize="10">
            Run {maxLen}
          </text>
        </svg>
      </>
    );
  }

  return (
    <dialog
      ref={dialogRef}
      className="compare-dialog"
      aria-labelledby="compare-dialog-title"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        if (e.target === dialogRef.current) onClose();
      }}
    >
      <div className="compare-dialog__head">
        <div>
          <h2 id="compare-dialog-title">Heuristic vs. ML Overlapping Comparison</h2>
          <p className="panel-head__sub">
            Live dual-scored kernel events plotted on log scale against the ~0.6 ms TCP exfiltration threshold.
          </p>
        </div>

        <div className="compare-dialog__actions">
          <div className="view-switch" role="tablist" aria-label="Comparison chart view">
            <button
              type="button"
              role="tab"
              className="view-tab"
              aria-selected={tab === "latency"}
              onClick={() => setTab("latency")}
            >
              Decision Latency
            </button>
            <button
              type="button"
              role="tab"
              className="view-tab"
              aria-selected={tab === "mtti"}
              onClick={() => setTab("mtti")}
            >
              End-to-End MTTI
            </button>
          </div>
          <button type="button" className="btn btn--sm" onClick={onClose}>
            Close
          </button>
        </div>
      </div>

      <div className="compare-dialog__body">
        {tab === "latency" ? renderDualChart() : renderMttiOverlay()}
      </div>
    </dialog>
  );
}
