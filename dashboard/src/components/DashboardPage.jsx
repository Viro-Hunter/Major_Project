import React, { useEffect, useState } from 'react';
import EntityGraph from './EntityGraph';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export default function DashboardPage() {
  const [entityId, setEntityId] = useState('AAM0658');
  const [hops, setHops] = useState(2);
  const [health, setHealth] = useState(null);
  const [query, setQuery] = useState('What actions did this user take outside business hours?');
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
    try {
      const r = await fetch(`${API}/graph/subgraph?entity=${encodeURIComponent(entityId)}&hops=${hops}`);
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
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
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
    fetchSubgraph();
  }, []);

  return (
    <main style={{ maxWidth: 1180, margin: '0 auto', padding: '2rem', fontFamily: 'sans-serif', color: '#0f172a' }}>
      <div style={{ background: '#ecfdf5', border: '1px solid #6ee7b7', padding: '10px 14px', borderRadius: 8, marginBottom: 16, fontSize: 13 }}>
        <b>✅ Week 1-6 Complete</b> — Ingestion → Graph (NetworkX + ATT&CK) → Retrieval (subgraph traversal) → Router (structural/lookup) • <b>Week 6 milestone visible:</b> vis-network graph + retrieval paths + subgraphs. Ollama default: <code>llama3.1:8b</code> (local, free) — see <code>docs/OLLAMA.md</code> & <code>docs/PROGRESS_WEEK6.md</code> • <code>LLM_PROVIDER=openai</code> + <code>Modelfile</code> for Sem 8 fine-tune.
      </div>
      <h1>Cyber Intelligence GraphRAG Dashboard</h1>
      <p>Explore users, hosts, events, and ATT&amp;CK techniques connected in the CERT graph. Graph-Augmented Insider Threat Detection — Live API: <code>{API}</code></p>

      <div style={{ display: 'flex', gap: 12, alignItems: 'end', flexWrap: 'wrap', margin: '1.5rem 0' }}>
        <label>
          Entity ID
          <br />
          <input value={entityId} onChange={(event) => setEntityId(event.target.value)} style={{ padding: 8, minWidth: 220 }} />
        </label>
        <label>
          Hops
          <br />
          <select value={hops} onChange={(event) => setHops(Number(event.target.value))} style={{ padding: 8 }}>
            <option value={1}>1</option>
            <option value={2}>2</option>
            <option value={3}>3</option>
          </select>
        </label>
        <button onClick={fetchSubgraph} style={{ padding: 8 }}>Reload Graph</button>
      </div>

      <EntityGraph entityId={entityId} hops={hops} apiBaseUrl={API} />

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', margin: '1rem 0', marginTop: '1.5rem' }}>
        <div style={{ border: '1px solid #ddd', padding: 12, borderRadius: 8, minWidth: 200, flex: '0 0 260px' }}>
          <b>Health</b>
          <pre style={{ fontSize: 12 }}>{JSON.stringify(health, null, 2)}</pre>
          <button onClick={fetchHealth}>Refresh</button>
        </div>
        <div style={{ border: '1px solid #ddd', padding: 12, borderRadius: 8, flex: 1 }}>
          <b>Analyze</b>
          <br />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="query" style={{ width: '70%', padding: 8, marginTop: 8 }} />
          <div style={{ marginTop: 8 }}>
            <button onClick={analyze} disabled={loading}>
              {loading ? 'Analyzing...' : 'Analyze'}
            </button>
            <button onClick={fetchSubgraph} style={{ marginLeft: 8, padding: 8 }}>
              Load Subgraph JSON
            </button>
          </div>
          {error && <p style={{ color: 'red' }}>{error}</p>}
        </div>
      </div>

      {result && (
        <div style={{ border: '1px solid #4caf50', padding: 12, borderRadius: 8, background: '#f6fff6', marginBottom: 12 }}>
          <h3>
            Verdict — Risk {result.verdict?.risk_score} | Confidence {result.verdict?.confidence} | Decision:{' '}
            <span style={{ color: result.decision === 'auto' ? 'red' : result.decision === 'analyst' ? 'orange' : 'green' }}>{result.decision}</span>
          </h3>
          <p>{result.verdict?.narrative}</p>
          <small>
            Query type: {result.query_type} | Grounded: {String(result.grounded)} | Evidence edges: {result.verdict?.evidence_edges}
          </small>
        </div>
      )}

      {subgraph && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div style={{ border: '1px solid #ddd', padding: 12, borderRadius: 8 }}>
            <h4>Subgraph Nodes ({subgraph.nodes?.length})</h4>
            <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th align="left">ID</th>
                  <th>Type</th>
                  <th>Dist</th>
                </tr>
              </thead>
              <tbody>
                {subgraph.nodes?.map((n) => (
                  <tr key={n.id} style={{ borderTop: '1px solid #eee' }}>
                    <td>{n.id}</td>
                    <td>{n.type}</td>
                    <td>{n.distance ?? '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ border: '1px solid #ddd', padding: 12, borderRadius: 8 }}>
            <h4>Edges ({subgraph.edges?.length})</h4>
            <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th align="left">Source</th>
                  <th>Relation</th>
                  <th>Target</th>
                  <th>Conf</th>
                </tr>
              </thead>
              <tbody>
                {subgraph.edges?.map((e, i) => (
                  <tr key={i} style={{ borderTop: '1px solid #eee' }}>
                    <td>{e.source}</td>
                    <td>{e.relation}</td>
                    <td>{e.target}</td>
                    <td>{e.confidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div style={{ marginTop: 16, fontSize: 12, color: '#888' }}>
        Metrics: <a href={`${API}/metrics`} target="_blank" rel="noreferrer">/metrics</a> | Graph stats: <a href={`${API}/graph/stats`} target="_blank" rel="noreferrer">/graph/stats</a> | Actions: <a href={`${API}/actions`} target="_blank" rel="noreferrer">/actions</a>
      </div>
    </main>
  );
}
