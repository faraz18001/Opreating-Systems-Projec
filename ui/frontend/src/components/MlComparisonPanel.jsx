export default function MlComparisonPanel({
  status,
  onRefresh,
  onBackToHeuristic,
}) {
  const available = Boolean(status?.ml_available);
  const metrics = status?.ml_metrics || null;

  if (!available) {
    return (
      <section className="surface-panel ml-panel" aria-labelledby="ml-heading">
        <div className="panel-head">
          <div>
            <h2 id="ml-heading">Machine learning classifier</h2>
            <p className="panel-head__sub">
              Trained model bundle (<code>defender_ml/model.joblib</code>) is not generated yet.
            </p>
          </div>
          <div className="ml-actions">
            <button type="button" className="btn btn--sm" onClick={onRefresh}>
              Refresh status
            </button>
            <button type="button" className="btn btn--sm" onClick={onBackToHeuristic}>
              Back to heuristic
            </button>
          </div>
        </div>

        <p className="ml-panel__copy">
          Install scikit-learn and train the 4-model benchmark from collected eBPF telemetry:
        </p>
        <pre className="lab-trace">
{`sudo apt install -y python3-sklearn python3-joblib python3-numpy
python3 defender_ml/train.py`}
        </pre>
      </section>
    );
  }

  const dataset = metrics?.dataset || {};
  const models = metrics?.models || [];
  const selectedKey = metrics?.selected_model || "random_forest";
  const topFeatures = (metrics?.feature_importances || []).slice(0, 5);

  return (
    <section className="surface-panel ml-panel" aria-labelledby="ml-heading">
      <div className="panel-head">
        <div>
          <h2 id="ml-heading">
            ML model &amp; heuristic comparison ({metrics?.selected_label || "Random Forest"})
          </h2>
          <p className="panel-head__sub">
            {dataset.total_rows
              ? `Trained on ${dataset.total_rows} labeled syscall events (${dataset.benign_rows} benign, ${dataset.malicious_rows} malicious).`
              : "Trained ML classifier active for live syscall scoring."}
          </p>
        </div>
        <span className="status-chip status-chip--live">
          <span className="status-chip__dot" aria-hidden="true" />
          Live engine: {status?.engine === "ml" ? "ML active" : "ML shadow"}
        </span>
      </div>

      <div className="ml-stats">
        <div className="ml-stat">
          <span className="tally__label">Live agreement rate</span>
          <span className="ml-stat__val num">
            {typeof status?.agreement_rate === "number"
              ? `${status.agreement_rate.toFixed(1)}%`
              : "Awaiting events"}
          </span>
          <span className="tally__sub">
            {status?.compared_count
              ? `${status.compared_count} dual-scored syscalls`
              : "Run attack or benign demo below"}
          </span>
        </div>

        <div className="ml-stat">
          <span className="tally__label">Heuristic inference</span>
          <span className="ml-stat__val num">
            {typeof status?.avg_heuristic_infer_ms === "number"
              ? `${status.avg_heuristic_infer_ms.toFixed(3)} ms`
              : "n/a"}
          </span>
          <span className="tally__sub">Rule scoring via rules.yaml</span>
        </div>

        <div className="ml-stat">
          <span className="tally__label">ML inference</span>
          <span className="ml-stat__val num">
            {typeof status?.avg_ml_infer_ms === "number"
              ? `${status.avg_ml_infer_ms.toFixed(3)} ms`
              : "n/a"}
          </span>
          <span className="tally__sub">{metrics?.selected_label || "Random Forest"} predict_proba</span>
        </div>
      </div>

      {models.length > 0 && (
        <div className="table-wrap">
          <table className="ledger ml-table">
            <thead>
              <tr>
                <th>Classifier</th>
                <th className="num">Accuracy</th>
                <th className="num">Precision</th>
                <th className="num">Recall</th>
                <th className="num">F1</th>
                <th className="num">FPR</th>
                <th className="num">Infer (ms)</th>
              </tr>
            </thead>
            <tbody>
              {models.map((m) => {
                const isSelected = m.key === selectedKey;
                return (
                  <tr key={m.key} className={isSelected ? "is-selected" : ""}>
                    <td>
                      <span className="ledger__proc">{m.label}</span>
                      {isSelected && <span className="ledger__sub">Active live bundle</span>}
                    </td>
                    <td className="num">{(m.accuracy * 100).toFixed(1)}%</td>
                    <td className="num">{(m.precision * 100).toFixed(1)}%</td>
                    <td className="num">{(m.recall * 100).toFixed(1)}%</td>
                    <td className="num">{(m.f1 * 100).toFixed(1)}%</td>
                    <td className="num">{(m.fpr * 100).toFixed(1)}%</td>
                    <td className="num">{m.avg_infer_ms.toFixed(3)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {topFeatures.length > 0 && (
        <p className="ml-panel__features">
          Top features:{" "}
          {topFeatures
            .map((f) => `${f.feature} (${(f.importance * 100).toFixed(1)}%)`)
            .join(" · ")}
        </p>
      )}
    </section>
  );
}
