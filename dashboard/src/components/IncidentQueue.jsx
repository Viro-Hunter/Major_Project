import React, { useEffect, useState } from 'react';

const LABEL = {
  high_risk: { text: 'High risk', bg: '#fee2e2', fg: '#991b1b', bar: '#dc2626' },
  suspicious: { text: 'Suspicious', bg: '#ffedd5', fg: '#9a3412', bar: '#d97706' },
  benign: { text: 'Benign', bg: '#dcfce7', fg: '#166534', bar: '#059669' },
};

// Week 9 — triage queue: every user scored from ATT&CK evidence paths
// (risk + propagated confidence), highest risk first. "Investigate" loads the
// user into the graph and runs the full LLM + groundedness verdict.
export default function IncidentQueue({ apiBaseUrl, selected, onInvestigate }) {
  const [rows, setRows] = useState(null);
  const [total, setTotal] = useState(0);
  const [onlyFlagged, setOnlyFlagged] = useState(true);
  const [error, setError] = useState(null);

  const load = async () => {
    setError(null);
    try {
      const r = await fetch(`${apiBaseUrl}/incidents/queue?limit=15&min_risk=${onlyFlagged ? 0.4 : 0}`);
      if (!r.ok) throw new Error(`queue ${r.status}`);
      const j = await r.json();
      setRows(j.incidents); setTotal(j.total_users);
    } catch (e) { setError(String(e)); }
  };
  useEffect(() => { load(); }, [onlyFlagged]);

  return (
    <section style={{ background: 'white', borderRadius: 16, padding: 16, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0', marginBottom: 18 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginBottom: 10 }}>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 800 }}>Incident queue <span style={{ fontWeight: 400, color: '#64748b' }}>{rows ? `${total} user${total === 1 ? '' : 's'} ${onlyFlagged ? 'flagged' : 'scored'}` : ''}</span></h3>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', fontSize: 12 }}>
          <label style={{ display: 'flex', gap: 6, alignItems: 'center', cursor: 'pointer' }}>
            <input type="checkbox" checked={onlyFlagged} onChange={(e) => setOnlyFlagged(e.target.checked)} /> Only suspicious and above
          </label>
          <button onClick={load} style={{ padding: '6px 10px', borderRadius: 8, border: '1px solid #e2e8f0', background: 'white', cursor: 'pointer', fontWeight: 600 }}>Refresh</button>
        </div>
      </div>
      {error && <p style={{ color: '#b91c1c', fontSize: 13 }}>Could not load the queue ({error}). Is the API running?</p>}
      {rows && rows.length === 0 && <p style={{ color: '#64748b', fontSize: 13 }}>No users at or above the suspicious threshold. Untick the filter to see every score.</p>}
      {rows && rows.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: '#475569', borderBottom: '1px solid #e2e8f0' }}>
                <th style={{ padding: '8px 10px' }}>User</th>
                <th style={{ padding: '8px 10px' }}>Verdict</th>
                <th style={{ padding: '8px 10px', minWidth: 140 }}>Risk</th>
                <th style={{ padding: '8px 10px' }}>Confidence</th>
                <th style={{ padding: '8px 10px' }}>ATT&CK techniques</th>
                <th style={{ padding: '8px 10px' }} />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const l = LABEL[r.verdict_label] || LABEL.benign;
                return (
                  <tr key={r.entity} style={{ borderTop: '1px solid #f1f5f9', background: selected === r.entity ? '#eff6ff' : 'transparent' }}>
                    <td style={{ padding: '8px 10px', fontWeight: 700 }}>{r.entity}</td>
                    <td style={{ padding: '8px 10px' }}><span style={{ background: l.bg, color: l.fg, padding: '2px 8px', borderRadius: 20, fontWeight: 700, fontSize: 12 }}>{l.text}</span></td>
                    <td style={{ padding: '8px 10px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ flex: 1, height: 6, background: '#f1f5f9', borderRadius: 3 }} aria-hidden="true">
                          <div style={{ width: `${Math.round(r.risk_score * 100)}%`, height: 6, background: l.bar, borderRadius: 3 }} />
                        </div>
                        <span style={{ fontVariantNumeric: 'tabular-nums' }}>{r.risk_score.toFixed(2)}</span>
                      </div>
                    </td>
                    <td style={{ padding: '8px 10px', fontVariantNumeric: 'tabular-nums' }} title="Propagated confidence of the strongest evidence path">{r.confidence_pct.toFixed(1)}%</td>
                    <td style={{ padding: '8px 10px', color: '#334155' }}>{r.techniques.join(', ') || '—'}</td>
                    <td style={{ padding: '8px 10px', textAlign: 'right' }}>
                      <button onClick={() => onInvestigate(r.entity)} style={{ padding: '5px 10px', borderRadius: 8, border: 'none', background: '#0f172a', color: 'white', cursor: 'pointer', fontWeight: 700, fontSize: 12 }}>Investigate</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
