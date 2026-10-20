import React, { useEffect, useState } from 'react';

// Week 10 — the five Objective-5 metrics from evaluation/run_benchmark.py.
export default function MetricsPanel({ apiBaseUrl }) {
  const [b, setB] = useState(null);
  const [missing, setMissing] = useState(false);

  useEffect(() => {
    fetch(`${apiBaseUrl}/metrics/benchmark`)
      .then((r) => (r.status === 404 ? (setMissing(true), null) : r.json()))
      .then((j) => j && setB(j))
      .catch(() => setMissing(true));
  }, [apiBaseUrl]);

  const shell = { background: 'white', borderRadius: 16, padding: 16, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0', marginTop: 18 };
  if (missing) {
    return (
      <section style={shell}>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 800 }}>Evaluation metrics</h3>
        <p style={{ fontSize: 13, color: '#475569', marginBottom: 0 }}>No benchmark results yet. Run <code>python evaluation/run_benchmark.py</code>, then reload this page.</p>
      </section>
    );
  }
  if (!b) return null;
  const h = b.headline;
  const d = b.detection;
  const items = [
    { name: 'Retrieval accuracy', value: h.retrieval_accuracy_f1.toFixed(3), unit: 'F1', note: 'Evidence entities vs malicious-event entities' },
    { name: 'Graph completeness', value: `${(100 * h.graph_completeness).toFixed(1)}%`, note: `${b.graph_completeness.found.toLocaleString()} of ${b.graph_completeness.expected.toLocaleString()} entities` },
    { name: 'Threat-correlation precision', value: h.threat_correlation_precision.toFixed(3), note: `Recall ${b.threat_correlation.recall.toFixed(3)} on user → technique links` },
    { name: 'Response time', value: `${(1000 * h.mean_query_latency_s).toFixed(0)} ms`, unit: 'per query', note: `Indexing ${h.indexing_time_s.toFixed(2)} s once` },
    { name: 'Detection', value: d.f1.toFixed(3), unit: 'F1', note: `P ${d.precision.toFixed(2)}, R ${d.recall.toFixed(2)}, FPR ${(100 * d.fpr).toFixed(1)}%` },
  ];
  const g = b.groundedness_fault_injection;
  return (
    <section style={shell}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 8 }}>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 800 }}>Evaluation metrics</h3>
        <span style={{ fontSize: 12, color: '#64748b' }}>
          {b.dataset.users} users ({b.dataset.insiders} insiders), {b.label_mode === 'real' ? 'official CERT answer key' : 'injected insider scenarios'}, generated {new Date(b.generated_at).toLocaleString()}
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 10, marginTop: 12 }}>
        {items.map((m) => (
          <div key={m.name} style={{ border: '1px solid #e2e8f0', borderRadius: 12, padding: 12 }}>
            <div style={{ fontSize: 12, color: '#475569', fontWeight: 600 }}>{m.name}</div>
            <div style={{ fontSize: 24, fontWeight: 800, fontVariantNumeric: 'tabular-nums', margin: '4px 0' }}>
              {m.value} {m.unit && <span style={{ fontSize: 12, fontWeight: 600, color: '#64748b' }}>{m.unit}</span>}
            </div>
            <div style={{ fontSize: 12, color: '#64748b' }}>{m.note}</div>
          </div>
        ))}
      </div>
      <p style={{ fontSize: 12, color: '#475569', margin: '12px 0 0' }}>
        Groundedness check: caught {g.caught} of {g.injected} fabricated citations, recovered {g.recovered_by_retry} by regeneration, flagged {g.flagged_unverified} as unverified, {g.clean_false_alarms} false alarms on {g.clean_verdicts} clean verdicts.
        {b.label_mode !== 'real' && ' Run python scripts/fetch_cert_data.py answers to evaluate against the official answer key.'}
      </p>
    </section>
  );
}
