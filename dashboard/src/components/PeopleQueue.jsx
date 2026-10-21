import React, { useEffect, useMemo, useState } from 'react';
import { techPlain, verdictFor } from '../plain';

// "People to review": every employee ranked by how unusual their behaviour is (fast rules-based
// triage, no AI call). Selecting one opens their case on the right.
export default function PeopleQueue({ apiBaseUrl, selected, onSelect, onLoaded, technical, overrides = {} }) {
  const [rows, setRows] = useState(null);
  const [error, setError] = useState(null);
  const [q, setQ] = useState('');
  const [onlyFlagged, setOnlyFlagged] = useState(true);
  const [sort, setSort] = useState('risk');

  useEffect(() => {
    fetch(`${apiBaseUrl}/incidents/queue?limit=500`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((j) => { setRows(j.incidents); onLoaded?.(j.incidents); })
      .catch((e) => setError(String(e.message || e)));
  }, [apiBaseUrl]);

  const shown = useMemo(() => {
    if (!rows) return [];
    let r = rows.filter((x) => (!onlyFlagged || x.verdict_label !== 'benign') && x.entity.toLowerCase().includes(q.trim().toLowerCase()));
    if (sort === 'name') r = [...r].sort((a, b) => a.entity.localeCompare(b.entity));
    if (sort === 'confidence') r = [...r].sort((a, b) => b.confidence_pct - a.confidence_pct);
    return r;
  }, [rows, q, onlyFlagged, sort]);
  const flagged = rows ? rows.filter((x) => x.verdict_label !== 'benign').length : 0;

  return (
    <section className="ui-card" aria-label="People to review" style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <h2 className="ui-h2">People to review</h2>
      <p className="ui-muted" style={{ margin: '2px 0 10px' }}>
        {rows ? `${flagged} of ${rows.length} people show unusual behaviour` : error ? '' : 'Loading…'}
      </p>
      <input className="ui-input" placeholder="Search by employee ID" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search employees" />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, margin: '8px 0', fontSize: 13 }}>
        <label style={{ display: 'flex', gap: 6, alignItems: 'center', cursor: 'pointer' }}>
          <input type="checkbox" checked={onlyFlagged} onChange={(e) => setOnlyFlagged(e.target.checked)} /> Only needs review
        </label>
        <select className="ui-select" value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort">
          <option value="risk">Highest risk</option><option value="confidence">Most certain</option><option value="name">Name</option>
        </select>
      </div>
      {error && <p className="ui-error">Could not load the list ({error}). Is the API running?</p>}
      <ul className="ui-list" style={{ listStyle: 'none', margin: 0, padding: 0, overflowY: 'auto', flex: 1, minHeight: 0 }}>
        {shown.map((r0) => {
          const r = overrides[r0.entity] ? { ...r0, ...overrides[r0.entity] } : r0;
          const v = verdictFor(r.verdict_label);
          const top = (r.behaviour || []).filter((b) => b.contribution > 0).slice(0, 2);
          return (
            <li key={r.entity}>
              <button onClick={() => onSelect(r.entity, r)} aria-current={selected === r.entity}
                      className={`ui-row${selected === r.entity ? ' on' : ''}`}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                  <b>{r.entity}</b>
                  <span style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                    {r.ai && <span title="Checked by the AI investigation" style={{ fontSize: 11, color: '#15803d', fontWeight: 700 }}>✓ AI-checked</span>}
                    <span className="ui-pill" style={{ background: v.bg, color: v.fg }}>{v.text}</span>
                  </span>
                </div>
                <div className="ui-meter" aria-label={`Risk ${Math.round(r.risk_score * 100)} out of 100`}>
                  <div style={{ width: `${Math.round(r.risk_score * 100)}%`, background: v.bar }} />
                </div>
                <div className="ui-muted" style={{ fontSize: 12, lineHeight: 1.4 }}>
                  {top.length ? top.map((b) => techPlain(b.technique_id)).join(' · ') : 'Nothing unusual'}
                  {technical && <span> · risk {r.risk_score.toFixed(2)} · {r.techniques.join(', ')}</span>}
                </div>
              </button>
            </li>
          );
        })}
        {rows && shown.length === 0 && <li className="ui-muted" style={{ padding: 12 }}>No one matches. {onlyFlagged && 'Untick “Only needs review” to see everyone.'}</li>}
      </ul>
    </section>
  );
}
