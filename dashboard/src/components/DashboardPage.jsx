import React, { useEffect, useState } from 'react';
import '../ui.css';
import PeopleQueue from './PeopleQueue';
import CaseView from './CaseView';
import MetricsPanel from './MetricsPanel';
import ModelSettings from './ModelSettings';

// Same-origin by default: Vite proxies API routes to the backend (see vite.config.mjs).
// Set VITE_API_URL only when the API lives on a different public URL.
const API = import.meta.env.VITE_API_URL || '';

const readPref = () => { try { return localStorage.getItem('cgr.technical') === '1'; } catch { return false; } };

export default function DashboardPage() {
  const [health, setHealth] = useState(null);
  const [people, setPeople] = useState(null);
  const [selected, setSelected] = useState(null);
  const [row, setRow] = useState(null);
  const [technical, setTechnical] = useState(readPref);
  const [llm, setLlm] = useState(null);
  const [aiResults, setAiResults] = useState({}); // entity -> checked verdict summary, keeps the list in sync

  useEffect(() => {
    fetch(`${API}/health`).then((r) => r.json()).then(setHealth).catch(() => setHealth({ status: 'offline' }));
  }, []);
  useEffect(() => { try { localStorage.setItem('cgr.technical', technical ? '1' : '0'); } catch { /* storage unavailable */ } }, [technical]);

  const onLoaded = (rows) => {
    setPeople(rows);
    if (!selected && rows.length) { setSelected(rows[0].entity); setRow(rows[0]); }
  };
  const online = health?.status === 'ok';

  return (
    <div style={{ minHeight: '100vh' }}>
      <header style={{ background: '#0f172a', color: 'white', padding: '16px 24px' }}>
        <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ minWidth: 0 }}>
            <h1 style={{ margin: 0, fontSize: 22, letterSpacing: '-.01em' }}>Insider Threat Investigator</h1>
            <p style={{ margin: '4px 0 0', fontSize: 13, color: '#cbd5e1' }}>
              Spots employees whose behaviour looks like data theft, explains why, and checks every claim against the logs.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', fontSize: 13 }}>
            <span title={online ? `${health.nodes} items and ${health.edges} connections loaded` : 'The API is not reachable'}
                  style={{ background: online ? '#14532d' : '#7c2d12', padding: '5px 10px', borderRadius: 99, fontWeight: 600 }}>
              {online ? `● Online · ${people ? `${people.length} people` : '…'} · ${health.edges.toLocaleString()} records` : health ? '● Offline' : '○ Connecting…'}
            </span>
            {llm && <span style={{ color: '#cbd5e1' }} title="The AI model used for investigations">AI: <b style={{ color: '#fff' }}>{llm.model}</b></span>}
            <a href="#story" style={{ color: '#fbbf24', fontWeight: 700, textDecoration: 'none' }}>▶ Story mode</a>
            <label className="ui-switch" title="Show raw IDs, edge lists, ATT&CK codes and formal metrics">
              <input type="checkbox" checked={technical} onChange={(e) => setTechnical(e.target.checked)} /> Technical details
            </label>
          </div>
        </div>
      </header>

      <main style={{ maxWidth: 1400, margin: '0 auto', padding: 16, display: 'grid', gap: 16 }}>
        {health?.status === 'offline' && <p className="ui-error">Can't reach the API. Start it with <code>uvicorn api.main:app --port 8000</code>, then reload.</p>}
        <div className="ui-layout">
          <div className="ui-sticky">
            <PeopleQueue apiBaseUrl={API} selected={selected} technical={technical} onLoaded={onLoaded} overrides={aiResults}
                         onSelect={(id, r) => { setSelected(id); setRow(r); window.scrollTo({ top: 0, behavior: 'smooth' }); }} />
          </div>
          <CaseView key={selected || 'none'} apiBaseUrl={API} entity={selected} row={row} technical={technical}
                    onVerdict={(id, r) => setAiResults((m) => ({ ...m, [id]: r }))} />
        </div>
        <MetricsPanel apiBaseUrl={API} technical={technical} />
        <details className="ui-card" open={false}>
          <summary style={{ cursor: 'pointer', fontWeight: 700 }}>
            AI model {llm ? <span className="ui-muted" style={{ fontWeight: 400 }}>— {llm.model} on {llm.label}{llm.tier && llm.tier !== 'unknown' ? ` (${llm.tier})` : ''}</span> : ''}
          </summary>
          <div style={{ marginTop: 12 }}><ModelSettings apiBaseUrl={API} onStatusChange={setLlm} /></div>
        </details>
      </main>
    </div>
  );
}
