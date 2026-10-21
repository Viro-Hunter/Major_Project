import React, { useEffect, useState } from 'react';

// "How well it works": the evaluation results as outcomes a non-specialist can read.
// The formal metrics (F1, precision, recall, FPR...) appear with Technical details on.
export default function MetricsPanel({ apiBaseUrl, technical }) {
  const [b, setB] = useState(null);
  const [missing, setMissing] = useState(false);
  useEffect(() => {
    fetch(`${apiBaseUrl}/metrics/benchmark`).then((r) => (r.status === 404 ? (setMissing(true), null) : r.json()))
      .then((j) => j && setB(j)).catch(() => setMissing(true));
  }, [apiBaseUrl]);

  if (missing) return (
    <section className="ui-card"><h2 className="ui-h2">How well it works</h2>
      <p className="ui-muted">No test results yet.{technical && <> Run <code>python evaluation/run_benchmark.py</code> and reload.</>}</p></section>
  );
  if (!b) return null;
  const d = b.detection, ds = b.dataset, f = b.groundedness_fault_injection, h = b.headline;
  const items = [
    ['Insiders caught', `${d.tp} of ${ds.insiders}`, 'flagged for a person to review'],
    ['False alarms', `${d.fp} of ${ds.benign}`, `innocent employees flagged (${Math.round(100 * d.fpr)}%). Simple rule matching: ${Math.round(100 * b.detection_naive_any_technique.fpr)}%`],
    ['Invented AI claims caught', `${f.caught} of ${f.injected}`, `${f.clean_false_alarms} honest answers wrongly rejected`],
    ['Answer time', `${Math.round(1000 * h.mean_query_latency_s)} ms`, 'per question, once the data is loaded'],
    ['Records captured', `${Math.round(100 * h.graph_completeness)}%`, 'of people, computers, files and emails in the logs'],
  ];
  return (
    <section className="ui-card" aria-label="How well it works">
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap', alignItems: 'baseline' }}>
        <h2 className="ui-h2">How well it works</h2>
        <span className="ui-muted">Tested on {ds.users} employees, {ds.insiders} of them {b.label_mode === 'real' ? 'confirmed insiders (official answer key)' : 'simulated insiders'}</span>
      </div>
      <div className="ui-stats">
        {items.map(([t, n, s]) => <div key={t} className="ui-stat"><div className="ui-label" style={{ marginBottom: 0 }}>{t}</div><div className="n">{n}</div><div className="ui-muted" style={{ fontSize: 12 }}>{s}</div></div>)}
      </div>
      {technical && (
        <div className="ui-muted" style={{ marginTop: 12, lineHeight: 1.6 }}>
          Detection precision {d.precision.toFixed(3)} · recall {d.recall.toFixed(3)} · F1 {d.f1.toFixed(3)} · FPR {d.fpr.toFixed(3)} ·
          retrieval F1 {h.retrieval_accuracy_f1.toFixed(3)} · threat-correlation precision {h.threat_correlation_precision.toFixed(3)} ·
          indexing {h.indexing_time_s.toFixed(2)} s · fault injection: {f.recovered_by_retry} repaired, {f.flagged_unverified} flagged unverified ·
          ground truth: {b.label_mode}{b.label_mode !== 'real' && <> — run <code>python scripts/fetch_cert_data.py answers</code> for the official key</>}
        </div>
      )}
    </section>
  );
}
