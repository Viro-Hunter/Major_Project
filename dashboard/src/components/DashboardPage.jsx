import React, { useEffect, useState } from 'react';
import EntityGraph from './EntityGraph';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const ENTITY_PRESETS = ['AAM0658', 'd.kapoor', 'PC-001', 'C:\\data\\secrets.zip'];

export default function DashboardPage() {
  const [entityId, setEntityId] = useState('AAM0658');
  const [hops, setHops] = useState(2);
  const [health, setHealth] = useState(null);
  const [query, setQuery] = useState('Why is this user linked to the confidential report?');
  const [result, setResult] = useState(null);
  const [subgraph, setSubgraph] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchHealth = async () => {
    try {
      const r = await fetch(`${API}/health`);
      const j = await r.json();
      setHealth(j);
    } catch (e) {
      setHealth({ status: 'offline', error: String(e) });
    }
  };

  const fetchSubgraph = async () => {
    setError(null);
    try {
      const r = await fetch(`${API}/graph/subgraph?entity=${encodeURIComponent(entityId)}&hops=${hops}`);
      if (!r.ok) throw new Error(`Graph ${r.status}`);
      const j = await r.json();
      setSubgraph(j);
    } catch (e) {
      setError(String(e));
    }
  };

  const analyze = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(`${API}/incidents/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entity: entityId, query, hops }),
      });
      if (!r.ok) {
        const text = await r.text();
        throw new Error(`Analyze ${r.status}: ${text.slice(0, 120)}`);
      }
      const j = await r.json();
      setResult(j);
      setSubgraph(j.subgraph);
    } catch (e) {
      setError(String(e));
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  useEffect(() => {
    fetchSubgraph();
  }, [entityId, hops]);

  const riskColor = (score) => {
    if (score == null) return '#64748b';
    if (score >= 0.7) return '#dc2626';
    if (score >= 0.4) return '#d97706';
    return '#059669';
  };

  const riskLabel = (score) => {
    if (score == null) return 'unknown';
    if (score >= 0.7) return 'HIGH';
    if (score >= 0.4) return 'MEDIUM';
    return 'LOW';
  };

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%)' }}>
      {/* Header */}
      <header style={{ background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%)', color: 'white', padding: '28px 24px', boxShadow: '0 10px 30px rgba(15,23,42,0.15)' }}>
        <div style={{ maxWidth: 1180, margin: '0 auto' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
            <div>
              <h1 style={{ margin: 0, fontSize: 26, letterSpacing: '-0.02em', fontWeight: 800 }}>Cyber Intelligence GraphRAG</h1>
              <p style={{ margin: '6px 0 0', opacity: 0.85, fontSize: 13, maxWidth: 720 }}>
                Behavioral insider-threat detection — CERT logs → knowledge graph → GraphRAG retrieval → grounded LLM reasoning
              </p>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12 }}>
              <span style={{ background: 'rgba(255,255,255,0.12)', padding: '6px 10px', borderRadius: 20, backdropFilter: 'blur(6px)' }}>
                API: <code style={{ color: '#e2e8f0' }}>{API}</code>
              </span>
              <span style={{ background: health?.status === 'ok' ? '#10b981' : '#f59e0b', padding: '6px 10px', borderRadius: 20, fontWeight: 700 }}>
                {health?.status === 'ok' ? `● Live • ${health.nodes} nodes / ${health.edges} edges` : '○ Checking...'}
              </span>
            </div>
          </div>
        </div>
      </header>

      <main style={{ maxWidth: 1180, margin: '0 auto', padding: '24px' }}>
        {/* Controls */}
        <section style={{ background: 'white', borderRadius: 16, padding: 18, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0', marginBottom: 18 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 140px 160px', gap: 12, alignItems: 'end' }}>
            <label style={{ fontSize: 13, fontWeight: 600, color: '#334155' }}>
              Entity ID
              <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
                <input
                  value={entityId}
                  onChange={(e) => setEntityId(e.target.value)}
                  placeholder="e.g. AAM0658 or d.kapoor"
                  list="entity-presets"
                  style={{ flex: 1, padding: '10px 12px', borderRadius: 10, border: '1px solid #cbd5e1', background: '#f8fafc', outline: 'none' }}
                />
                <datalist id="entity-presets">
                  {ENTITY_PRESETS.map((p) => <option key={p} value={p} />)}
                </datalist>
              </div>
            </label>
            <label style={{ fontSize: 13, fontWeight: 600, color: '#334155' }}>
              Hops
              <select value={hops} onChange={(e) => setHops(Number(e.target.value))} style={{ width: '100%', marginTop: 6, padding: '10px 12px', borderRadius: 10, border: '1px solid #cbd5e1', background: 'white' }}>
                <option value={1}>1 hop</option>
                <option value={2}>2 hops</option>
                <option value={3}>3 hops</option>
              </select>
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={fetchSubgraph} style={{ flex: 1, padding: '10px 14px', borderRadius: 10, border: '1px solid #e2e8f0', background: '#0f172a', color: 'white', fontWeight: 700, cursor: 'pointer' }}>
                ↻ Reload
              </button>
              <button onClick={fetchHealth} style={{ padding: '10px 14px', borderRadius: 10, border: '1px solid #e2e8f0', background: 'white', fontWeight: 600, cursor: 'pointer' }}>
                Health
              </button>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 8, fontSize: 12, color: '#64748b' }}>
            <span>Presets:</span>
            {ENTITY_PRESETS.map((p) => (
              <button key={p} onClick={() => setEntityId(p)} style={{ padding: '4px 8px', borderRadius: 20, border: '1px solid #e2e8f0', background: entityId === p ? '#0f172a' : 'white', color: entityId === p ? 'white' : '#334155', cursor: 'pointer', fontSize: 12 }}>
                {p}
              </button>
            ))}
            <span style={{ marginLeft: 'auto' }}>Try: <em>“Why is AAM0658 linked to PC-001?”</em></span>
          </div>
        </section>

        {/* Graph */}
        <section style={{ background: 'white', borderRadius: 16, padding: 16, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0', marginBottom: 18 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 800, color: '#0f172a' }}>Attack-Path Visualization</h3>
            <span style={{ fontSize: 12, color: '#64748b' }}>
              {subgraph ? `${subgraph.nodes?.length ?? 0} nodes • ${subgraph.edges?.length ?? 0} edges` : '—'}
            </span>
          </div>
          <EntityGraph entityId={entityId} hops={hops} apiBaseUrl={API} />
          {error && <p style={{ color: '#b91c1c', background: '#fef2f2', padding: '8px 10px', borderRadius: 8, border: '1px solid #fecaca', marginTop: 10 }}>{error}</p>}
        </section>

        {/* Analyze + Health */}
        <section style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 14, marginBottom: 18 }}>
          <div style={{ background: 'white', borderRadius: 16, padding: 16, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0' }}>
            <h4 style={{ margin: '0 0 8px', fontSize: 13, fontWeight: 800 }}>System Health</h4>
            <pre style={{ margin: 0, background: '#0f172a', color: '#e2e8f0', padding: 12, borderRadius: 10, fontSize: 12, overflow: 'auto' }}>{JSON.stringify(health, null, 2)}</pre>
            <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
              <button onClick={fetchHealth} style={{ flex: 1, padding: '8px 10px', borderRadius: 8, border: '1px solid #e2e8f0', background: 'white', cursor: 'pointer', fontWeight: 600 }}>Refresh</button>
              <a href={`${API}/metrics`} target="_blank" rel="noreferrer" style={{ flex: 1, textAlign: 'center', padding: '8px 10px', borderRadius: 8, background: '#f8fafc', border: '1px solid #e2e8f0', textDecoration: 'none', color: '#0f172a', fontWeight: 600 }}>Metrics</a>
            </div>
          </div>

          <div style={{ background: 'white', borderRadius: 16, padding: 16, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0' }}>
            <h4 style={{ margin: '0 0 8px', fontSize: 13, fontWeight: 800 }}>GraphRAG — Ask a Behavioral Question</h4>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder='e.g. Why is AAM0658 linked to the confidential report?'
                style={{ flex: 1, padding: '10px 12px', borderRadius: 10, border: '1px solid #cbd5e1', background: '#f8fafc' }}
              />
              <button onClick={analyze} disabled={loading} style={{ padding: '10px 16px', borderRadius: 10, border: 'none', background: loading ? '#94a3b8' : '#2563eb', color: 'white', fontWeight: 800, cursor: loading ? 'not-allowed' : 'pointer', minWidth: 110 }}>
                {loading ? 'Analyzing…' : 'Analyze'}
              </button>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 8 }}>
              {['Why is user linked to host?', 'What files did AAM0658 access?', 'Is d.kapoor exfiltrating data?'].map((q) => (
                <button key={q} onClick={() => setQuery(q)} style={{ padding: '5px 10px', borderRadius: 20, border: '1px solid #e2e8f0', background: 'white', fontSize: 12, cursor: 'pointer' }}>
                  {q}
                </button>
              ))}
            </div>
          </div>
        </section>

        {/* Verdict */}
        {result && (
          <div style={{ background: 'white', borderRadius: 16, padding: 16, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: `1px solid ${riskColor(result.verdict?.risk_score)}20`, marginBottom: 14, borderLeft: `4px solid ${riskColor(result.verdict?.risk_score)}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 800 }}>
                Verdict — <span style={{ color: riskColor(result.verdict?.risk_score) }}>{riskLabel(result.verdict?.risk_score)}</span>{' '}
                <span style={{ fontWeight: 400, color: '#64748b' }}>Risk {result.verdict?.risk_score} • Conf {result.verdict?.confidence}</span>
              </h3>
              <span style={{ padding: '4px 10px', borderRadius: 20, background: result.decision === 'auto' ? '#fee2e2' : result.decision === 'analyst' ? '#ffedd5' : '#dcfce7', color: result.decision === 'auto' ? '#991b1b' : result.decision === 'analyst' ? '#9a3412' : '#166534', fontWeight: 700, fontSize: 12 }}>
                {result.decision?.toUpperCase()}
              </span>
            </div>
            <p style={{ margin: '8px 0', color: '#1e293b', lineHeight: 1.5 }}>{result.verdict?.narrative}</p>
            <small style={{ color: '#64748b' }}>
              Query type: <b>{result.query_type}</b> • Grounded: {String(result.grounded)} • Edges: {result.verdict?.evidence_edges}
            </small>
          </div>
        )}

        {/* Subgraph tables */}
        {subgraph && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div style={{ background: 'white', borderRadius: 16, padding: 16, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0' }}>
              <h4 style={{ margin: '0 0 10px', fontSize: 13, fontWeight: 800 }}>Subgraph Nodes ({subgraph.nodes?.length ?? 0})</h4>
              <div style={{ maxHeight: 280, overflow: 'auto', border: '1px solid #f1f5f9', borderRadius: 10 }}>
                <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
                  <thead style={{ position: 'sticky', top: 0, background: '#f8fafc' }}>
                    <tr><th style={{ textAlign: 'left', padding: '8px 10px', borderBottom: '1px solid #e2e8f0' }}>ID</th><th style={{ textAlign: 'left', padding: '8px 10px', borderBottom: '1px solid #e2e8f0' }}>Type</th><th style={{ padding: '8px 10px', borderBottom: '1px solid #e2e8f0' }}>Dist</th></tr>
                  </thead>
                  <tbody>
                    {subgraph.nodes?.length ? (
                      subgraph.nodes.map((n) => (
                        <tr key={n.id} style={{ borderTop: '1px solid #f1f5f9' }}>
                          <td style={{ padding: '7px 10px', fontWeight: 600 }}>{n.id}</td>
                          <td style={{ padding: '7px 10px' }}><span style={{ background: '#f1f5f9', padding: '2px 8px', borderRadius: 20, fontSize: 12 }}>{n.type}</span></td>
                          <td style={{ padding: '7px 10px', textAlign: 'center' }}>{n.distance ?? '-'}</td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan={3} style={{ padding: 16, textAlign: 'center', color: '#94a3b8' }}>No nodes — try another entity or increase hops</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
            <div style={{ background: 'white', borderRadius: 16, padding: 16, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0' }}>
              <h4 style={{ margin: '0 0 10px', fontSize: 13, fontWeight: 800 }}>Edges ({subgraph.edges?.length ?? 0})</h4>
              <div style={{ maxHeight: 280, overflow: 'auto', border: '1px solid #f1f5f9', borderRadius: 10 }}>
                <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
                  <thead style={{ position: 'sticky', top: 0, background: '#f8fafc' }}>
                    <tr><th style={{ textAlign: 'left', padding: '8px 10px', borderBottom: '1px solid #e2e8f0' }}>Source</th><th style={{ textAlign: 'left', padding: '8px 10px', borderBottom: '1px solid #e2e8f0' }}>Relation</th><th style={{ textAlign: 'left', padding: '8px 10px', borderBottom: '1px solid #e2e8f0' }}>Target</th><th style={{ padding: '8px 10px', borderBottom: '1px solid #e2e8f0' }}>Conf</th></tr>
                  </thead>
                  <tbody>
                    {subgraph.edges?.length ? (
                      subgraph.edges.map((e, i) => (
                        <tr key={i} style={{ borderTop: '1px solid #f1f5f9' }}>
                          <td style={{ padding: '7px 10px' }}>{e.source}</td>
                          <td style={{ padding: '7px 10px' }}><span style={{ background: '#eff6ff', color: '#1d4ed8', padding: '2px 8px', borderRadius: 20, fontSize: 12, fontWeight: 600 }}>{e.relation || e.type}</span></td>
                          <td style={{ padding: '7px 10px' }}>{e.target}</td>
                          <td style={{ padding: '7px 10px', textAlign: 'center' }}>{e.confidence?.toFixed ? e.confidence.toFixed(2) : e.confidence}</td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan={4} style={{ padding: 16, textAlign: 'center', color: '#94a3b8' }}>No edges for this entity/hops</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        <div style={{ marginTop: 18, display: 'flex', gap: 10, flexWrap: 'wrap', fontSize: 12, color: '#64748b' }}>
          <a href={`${API}/graph/stats`} target="_blank" rel="noreferrer" style={{ background: 'white', padding: '8px 12px', borderRadius: 20, border: '1px solid #e2e8f0', textDecoration: 'none', color: '#0f172a' }}>Graph stats</a>
          <a href={`${API}/metrics`} target="_blank" rel="noreferrer" style={{ background: 'white', padding: '8px 12px', borderRadius: 20, border: '1px solid #e2e8f0', textDecoration: 'none', color: '#0f172a' }}>Metrics</a>
          <a href={`${API}/actions`} target="_blank" rel="noreferrer" style={{ background: 'white', padding: '8px 12px', borderRadius: 20, border: '1px solid #e2e8f0', textDecoration: 'none', color: '#0f172a' }}>Actions</a>
          <span style={{ alignSelf: 'center' }}>• Ollama default: <code>llama3.1:8b</code> — change via <code>.env</code> or <code>./scripts/pull_model.sh</code></span>
        </div>
      </main>
    </div>
  );
}
