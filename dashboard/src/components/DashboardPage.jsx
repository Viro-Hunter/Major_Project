import React, { useEffect, useState, useMemo } from 'react';
import EntityGraph from './EntityGraph';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function DashboardPage() {
  const [entityId, setEntityId] = useState('AAM0658');
  const [hops, setHops] = useState(2);
  const [health, setHealth] = useState(null);
  const [query, setQuery] = useState('Why is this user linked to the confidential report?');
  const [result, setResult] = useState(null);
  const [subgraph, setSubgraph] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Dynamic entity list
  const [entities, setEntities] = useState([]);
  const [entitySearch, setEntitySearch] = useState('');
  const [showDropdown, setShowDropdown] = useState(false);

  const fetchHealth = async () => {
    try {
      const r = await fetch(`${API}/health`);
      const j = await r.json();
      setHealth(j);
    } catch (e) {
      setHealth({ status: 'offline', error: String(e) });
    }
  };

  const fetchEntities = async (q = '') => {
    try {
      const url = q
        ? `${API}/graph/entities?q=${encodeURIComponent(q)}&limit=100`
        : `${API}/graph/entities?type=User&limit=100`;
      const r = await fetch(url);
      if (!r.ok) throw new Error(`entities ${r.status}`);
      const j = await r.json();
      setEntities(j.entities || []);
    } catch (e) {
      // fallback to presets if API not ready
      setEntities([
        { id: 'AAM0658', type: 'User', degree: 3 },
        { id: 'd.kapoor', type: 'User', degree: 3 },
        { id: 'PC-001', type: 'Host', degree: 5 },
      ]);
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
    fetchEntities('');
  }, []);

  useEffect(() => {
    fetchSubgraph();
  }, [entityId, hops]);

  // Live search debounce
  useEffect(() => {
    const t = setTimeout(() => {
      if (entitySearch.trim()) fetchEntities(entitySearch.trim());
      else fetchEntities('');
    }, 300);
    return () => clearTimeout(t);
  }, [entitySearch]);

  const filteredEntities = useMemo(() => {
    if (!entitySearch) return entities.slice(0, 20);
    const q = entitySearch.toLowerCase();
    return entities.filter((e) => e.id.toLowerCase().includes(q)).slice(0, 20);
  }, [entities, entitySearch]);

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

  const isFallback = result?.verdict?.model === 'template-fallback';
  const modelName = result?.verdict?.model || (isFallback ? 'template-fallback' : 'unknown');

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
        {/* Controls - Entity with searchable dropdown */}
        <section style={{ background: 'white', borderRadius: 16, padding: 18, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0', marginBottom: 18 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 140px 160px', gap: 12, alignItems: 'end' }}>
            <div style={{ position: 'relative' }}>
              <label style={{ fontSize: 13, fontWeight: 600, color: '#334155', display: 'block', marginBottom: 6 }}>
                Entity ID — {entities.length} users available
              </label>
              <div style={{ display: 'flex', gap: 6 }}>
                <div style={{ flex: 1, position: 'relative' }}>
                  <input
                    value={entityId}
                    onChange={(e) => {
                      setEntityId(e.target.value);
                      setEntitySearch(e.target.value);
                      setShowDropdown(true);
                    }}
                    onFocus={() => {
                      setShowDropdown(true);
                      if (entities.length === 0) fetchEntities('');
                    }}
                    placeholder="Search users e.g. AAM0658, CTR0341, d.kapoor..."
                    style={{ width: '100%', padding: '10px 12px', borderRadius: 10, border: '1px solid #cbd5e1', background: '#f8fafc', outline: 'none' }}
                  />
                  {showDropdown && filteredEntities.length > 0 && (
                    <div
                      style={{
                        position: 'absolute',
                        top: '100%',
                        left: 0,
                        right: 0,
                        marginTop: 6,
                        background: 'white',
                        border: '1px solid #e2e8f0',
                        borderRadius: 12,
                        boxShadow: '0 10px 30px rgba(15,23,42,0.12)',
                        maxHeight: 260,
                        overflowY: 'auto',
                        zIndex: 50,
                      }}
                      onMouseLeave={() => setShowDropdown(false)}
                    >
                      <div style={{ padding: '8px 12px', fontSize: 11, fontWeight: 700, color: '#64748b', borderBottom: '1px solid #f1f5f9', position: 'sticky', top: 0, background: 'white' }}>
                        {entitySearch ? `Search "${entitySearch}" — ${filteredEntities.length} matches` : `All Users — showing ${filteredEntities.length} of ${entities.length}`}
                      </div>
                      {filteredEntities.map((e) => (
                        <button
                          key={e.id}
                          onClick={() => {
                            setEntityId(e.id);
                            setEntitySearch('');
                            setShowDropdown(false);
                          }}
                          style={{
                            width: '100%',
                            textAlign: 'left',
                            padding: '9px 12px',
                            border: 'none',
                            background: entityId === e.id ? '#eff6ff' : 'white',
                            borderBottom: '1px solid #f8fafc',
                            cursor: 'pointer',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                          }}
                        >
                          <span style={{ fontWeight: 600, color: '#0f172a' }}>{e.id}</span>
                          <span style={{ fontSize: 11, display: 'flex', gap: 6, alignItems: 'center' }}>
                            <span style={{ background: '#f1f5f9', padding: '2px 8px', borderRadius: 20, color: '#334155' }}>{e.type}</span>
                            <span style={{ color: '#64748b' }}>{e.degree} edges</span>
                          </span>
                        </button>
                      ))}
                      {filteredEntities.length === 0 && (
                        <div style={{ padding: 16, textAlign: 'center', color: '#94a3b8', fontSize: 13 }}>No matches — try a different prefix</div>
                      )}
                    </div>
                  )}
                </div>
              </div>
              <div style={{ fontSize: 11, color: '#64748b', marginTop: 6 }}>
                Type to search 200 users — e.g. <code>CTR</code>, <code>AAL</code>, <code>d.kapoor</code>. Press ↻ to load graph.
              </div>
            </div>
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
        </section>

        {/* Graph */}
        <section style={{ background: 'white', borderRadius: 16, padding: 16, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0', marginBottom: 18 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 800, color: '#0f172a' }}>Attack-Path Visualization</h3>
            <span style={{ fontSize: 12, color: '#64748b' }}>
              {subgraph ? `${subgraph.nodes?.length ?? 0} nodes • ${subgraph.edges?.length ?? 0} edges` : '—'} {entityId && `for ${entityId}`}
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
            <div style={{ marginTop: 12, padding: 10, background: '#f8fafc', borderRadius: 10, border: '1px solid #e2e8f0', fontSize: 12, color: '#475569' }}>
              <b>Model status:</b>{' '}
              {isFallback && result
                ? '⚠️ template-fallback — Ollama not reachable (results are rule-based). Start Ollama for real LLM.'
                : result
                ? `✅ ${modelName} — grounded LLM`
                : 'Run Analyze to see model'}
              <br />
              <span style={{ fontSize: 11, color: '#64748b' }}>
                {isFallback ? 'Start: ollama serve & ollama pull qwen2.5:3b' : 'Fine-tune once → Modelfile.finetuned → OPENAI_MODEL=cybergraphrag:ft (see docs/TRAINING.md)'}
              </span>
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
              {[
                'Why is this user linked to host?',
                'What files did this entity access?',
                'Is this user exfiltrating data?',
                'Why is this user linked to the confidential report?',
                'Show path to attack technique',
              ].map((q) => (
                <button
                  key={q}
                  onClick={() => setQuery(q)}
                  style={{ padding: '5px 10px', borderRadius: 20, border: '1px solid #e2e8f0', background: 'white', fontSize: 12, cursor: 'pointer' }}
                >
                  {q}
                </button>
              ))}
            </div>
            <div style={{ marginTop: 10, fontSize: 11, color: '#64748b', background: '#f8fafc', padding: 8, borderRadius: 8, border: '1px dashed #e2e8f0' }}>
              <b>Why “ignore”?</b> Normal users have low risk (0.1–0.3) → <code>ignore</code>. Try a risky preset <code>d.kapoor</code> or a user with high-degree ATT&CK edges — risk will be HIGH. Full training (Sem 8) will learn subtler patterns.
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
                {result.decision?.toUpperCase()} • {modelName}
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
          <span style={{ alignSelf: 'center' }}>• Ollama default: <code>qwen2.5:3b</code> — change via <code>.env</code> or <code>./scripts/pull_model.sh</code></span>
        </div>
      </main>
    </div>
  );
}
