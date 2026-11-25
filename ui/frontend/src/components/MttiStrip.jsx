import { useState } from "react";

function formatLatency(ms) {
  if (ms < 0.1) {
    return `${(ms * 1000).toFixed(1)} µs`;
  }
  return `${ms.toFixed(2)} ms`;
}

export default function MttiStrip({ events }) {
  const [hoveredIdx, setHoveredIdx] = useState(null);

  const samples = events
    .filter((ev) => ev.action === "FROZEN" && typeof ev.mtti_ms === "number")
    .slice(-18);

  if (samples.length === 0) {
    return (
      <section className="surface-panel" aria-labelledby="mtti-heading">
        <div className="panel-head">
          <div>
            <h2 id="mtti-heading">Interception latency</h2>
            <p className="panel-head__sub">Syscall entry to SIGSTOP freeze (0 ms baseline).</p>
          </div>
        </div>
        <div className="empty-state">
          <p className="empty-state__title">Awaiting first interception</p>
          <p className="empty-state__desc">
            Click Simulate attack in the top bar to compare userspace vs in-kernel freeze latency.
          </p>
        </div>
      </section>
    );
  }

  const values = samples.map((s) => s.mtti_ms);
  const maxVal = Math.max(...values, 0.05);
  const meanVal = values.reduce((a, b) => a + b, 0) / values.length;
  const ceilMax = maxVal < 0.2 ? Math.ceil(maxVal * 1.3 * 1000) / 1000 : Math.ceil(maxVal * 1.18 * 10) / 10;
  const midVal = ceilMax / 2;

  const width = 420;
  const height = 160;
  const padLeft = 44;
  const padRight = 14;
  const padTop = 14;
  const padBottom = 26;
  const plotW = width - padLeft - padRight;
  const plotH = height - padTop - padBottom;

  const points = samples.map((s, idx) => {
    const x =
      samples.length === 1
        ? padLeft + plotW / 2
        : padLeft + (idx / (samples.length - 1)) * plotW;
    const y = padTop + plotH - (s.mtti_ms / ceilMax) * plotH;
    return { x, y, sample: s, idx };
  });

  const linePath = points
    .map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
    .join(" ");

  const areaPath =
    points.length > 1
      ? `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${(padTop + plotH).toFixed(1)} L ${points[0].x.toFixed(1)} ${(padTop + plotH).toFixed(1)} Z`
      : "";

  const activePoint = hoveredIdx !== null && points[hoveredIdx] ? points[hoveredIdx] : points[points.length - 1];
  const tickFormat = (v) => (ceilMax < 0.2 ? `${(v * 1000).toFixed(0)}µ` : `${v.toFixed(1)}`);

  return (
    <section className="surface-panel" aria-labelledby="mtti-heading">
      <div className="panel-head">
        <div>
          <h2 id="mtti-heading">Interception latency</h2>
          <p className="panel-head__sub">
            Mean {formatLatency(meanVal)} across {samples.length} {samples.length === 1 ? "run" : "runs"}.
          </p>
        </div>
        <div className="chart-readout num">
          <span className="chart-readout__val">{formatLatency(activePoint.sample.mtti_ms)}</span>
          <span className="chart-readout__meta">
            PID {activePoint.sample.pid} ({activePoint.sample.freeze_mode || "userspace"})
          </span>
        </div>
      </div>

      <svg
        className="mtti-svg"
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label={`Line chart of ${samples.length} interception latencies, mean ${formatLatency(meanVal)}`}
        onMouseLeave={() => setHoveredIdx(null)}
      >
        <defs>
          <linearGradient id="mtti-area-fade" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--color-accent)" stopOpacity="0.16" />
            <stop offset="100%" stopColor="var(--color-accent)" stopOpacity="0" />
          </linearGradient>
        </defs>

        {[0, midVal, ceilMax].map((tick, i) => {
          const y = padTop + plotH - (tick / ceilMax) * plotH;
          return (
            <g key={i}>
              <line
                x1={padLeft}
                x2={width - padRight}
                y1={y}
                y2={y}
                stroke="var(--color-rule)"
                strokeWidth="1"
              />
              <text
                x={padLeft - 8}
                y={y + 4}
                textAnchor="end"
                fill="var(--color-muted)"
                fontSize="11"
                className="num"
              >
                {tick === 0 ? "0" : tickFormat(tick)}
              </text>
            </g>
          );
        })}

        {areaPath && <path d={areaPath} fill="url(#mtti-area-fade)" />}

        {points.length > 1 && (
          <path
            d={linePath}
            fill="none"
            stroke="var(--color-accent)"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        )}

        {activePoint && (
          <line
            x1={activePoint.x}
            x2={activePoint.x}
            y1={padTop}
            y2={padTop + plotH}
            stroke="var(--color-rule)"
            strokeWidth="1"
          />
        )}

        {points.map((p) => {
          const isActive = activePoint.idx === p.idx;
          const isUserspace = p.sample.freeze_mode !== "in-kernel";
          return (
            <g
              key={p.sample.id ?? `${p.sample.pid}-${p.idx}`}
              onMouseEnter={() => setHoveredIdx(p.idx)}
              className="mtti-point"
            >
              <title>{`PID ${p.sample.pid}: ${formatLatency(p.sample.mtti_ms)} (${p.sample.freeze_mode || "userspace"})`}</title>
              <circle cx={p.x} cy={p.y} r="10" fill="transparent" />
              <circle
                cx={p.x}
                cy={p.y}
                r={isActive ? 4.5 : 3}
                fill={isUserspace ? "var(--color-accent-2)" : "var(--color-accent)"}
                stroke="var(--color-paper-2)"
                strokeWidth="1.5"
              />
            </g>
          );
        })}

        <text x={padLeft} y={height - 5} fill="var(--color-muted)" fontSize="11">
          Run 1
        </text>
        <text
          x={width - padRight}
          y={height - 5}
          textAnchor="end"
          fill="var(--color-muted)"
          fontSize="11"
        >
          Run {samples.length}
        </text>
      </svg>
    </section>
  );
}
