import React, { useEffect, useMemo, useRef, useState } from 'react';
import EvidenceGraph from './EvidenceGraph';
import GroundednessBadge from './GroundednessBadge';
import Timeline from './Timeline';
import { RECOMMENDATION, TECHNIQUES, edgeIds, fmtWhen, isNight, nodeLabel, relPlain, techPlain, verdictFor } from '../plain';

const SUGGESTED = ['Is this person taking company data?', 'Why was this person flagged?', 'What did this person do late at night?'];

function Info({ text }) {
  return <span className="ui-info" tabIndex={0} role="note" aria-label={text} title={text}>i</span>;
}

function ActivityChart({ subgraph, focus }) {
  const days = useMemo(() => {
    const m = new Map();
    for (const e of subgraph?.edges || []) {
      if (e.source !== focus || !e.timestamp) continue;
      const key = String(e.timestamp).slice(0, 10);
      const d = m.get(key) || { day: 0, night: 0, flagged: 0 };
      if ((e.type || e.relation) === 'MATCHES_TECHNIQUE') d.flagged += 1;
      else if (isNight(e.timestamp)) d.night += 1; else d.day += 1;
      m.set(key, d);
    }
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [subgraph, focus]);
  if (!days.length) return <p className="ui-muted">No dated activity for this person.</p>;
  const max = Math.sqrt(Math.max(...days.map(([, d]) => d.day + d.night), 1));
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'center', gap: 4, height: 126, overflowX: 'auto' }} role="img" aria-label="Daily activity; night-time activity in purple, days with suspicious behaviour marked">
        {days.map(([k, d]) => {
          const tot = d.day + d.night || 1;
          const h = (100 * Math.sqrt(tot)) / max;
          return (
            <div key={k} title={`${new Date(k).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}: ${d.day} daytime, ${d.night} night-time actions${d.flagged ? `, ${d.flagged} suspicious` : ''}`}
                 style={{ flex: '1 1 0', minWidth: 8, maxWidth: 36, height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', alignItems: 'center' }}>
              {d.flagged > 0 && <span style={{ color: '#dc2626', fontSize: 10, lineHeight: 1 }}>⚑</span>}
              <div style={{ width: '100%', height: `${h}%`, display: 'flex', flexDirection: 'column', borderRadius: '3px 3px 0 0', overflow: 'hidden', outline: d.flagged ? '2px solid #fca5a5' : 'none' }}>
                <div style={{ flex: d.night, background: '#7c3aed' }} /><div style={{ flex: d.day, background: '#94a3b8' }} />
              </div>
              <span style={{ fontSize: 10, color: '#64748b', marginTop: 3, fontVariantNumeric: 'tabular-nums' }}>{Number(k.slice(8))}</span>
            </div>
          );
        })}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#64748b', marginTop: 4 }}>
        <span>{new Date(days[0][0]).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}</span>
        <span><span style={{ color: '#94a3b8' }}>■</span> daytime <span style={{ color: '#7c3aed', marginLeft: 8 }}>■</span> night (8 PM–6 AM) <span style={{ color: '#dc2626', marginLeft: 8 }}>⚑</span> suspicious</span>
        <span>{new Date(days[days.length - 1][0]).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}</span>
      </div>
    </div>
  );
}

export default function CaseView({ apiBaseUrl, entity, row, technical }) {
  const [subgraph, setSubgraph] = useState(null);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [question, setQuestion] = useState('');
  const [thread, setThread] = useState([]);
  const [asking, setAsking] = useState(false);
  const threadEnd = useRef(null);
  const [hops, setHops] = useState(1);

  useEffect(() => {
    setResult(null); setError(null); setSubgraph(null);
    if (!entity) return;
    fetch(`${apiBaseUrl}/graph/subgraph?entity=${encodeURIComponent(entity)}&hops=${hops}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(r.status === 404 ? 'not found' : `HTTP ${r.status}`))))
      .then(setSubgraph).catch((e) => setError(`Could not load this person's activity (${e.message}).`));
  }, [apiBaseUrl, entity, hops]);

  // Questions are a conversation about the evidence: answers appear under the box and never
  // replace the case verdict above.
  const ask = async (q) => {
    const text = (q ?? question).trim();
    if (!text || asking) return;
    setAsking(true); setQuestion('');
    setThread((t) => [...t, { q: text, pending: true }]);
    let a;
    try {
      const r = await fetch(`${apiBaseUrl}/incidents/ask`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                                             body: JSON.stringify({ entity, question: text }) });
      a = r.ok ? await r.json() : { error: `The question could not be answered (HTTP ${r.status}).` };
    } catch (e) { a = { error: `The question could not be answered (${e.message}).` }; }
    setThread((t) => t.map((x, k) => (k === t.length - 1 ? { q: text, a } : x)));
    setAsking(false);
  };
  useEffect(() => { threadEnd.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, [thread]);

  const investigate = async (q = SUGGESTED[0]) => {
    setBusy(true); setError(null);
    try {
      const r = await fetch(`${apiBaseUrl}/incidents/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                                                 body: JSON.stringify({ entity, query: q, hops }) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setResult(j); setSubgraph(j.subgraph);
    } catch (e) { setError(`The investigation could not run (${e.message}).`); }
    setBusy(false);
  };

  const v = result?.verdict;
  const verified = useMemo(() => new Set((v?.groundedness?.verified_edges || []).map(String)), [v]);
  const behaviour = (v?.behaviour || row?.behaviour || []).slice().sort((a, b) => b.contribution - a.contribution);
  const risk = v ? v.risk_score : row?.risk_score ?? 0;
  const label = v ? v.verdict_label : row?.verdict_label || 'benign';
  const conf = v ? v.confidence_pct : row?.confidence_pct ?? 0;
  const vs = verdictFor(label);
  const status = v?.groundedness?.status;
  const unusual = behaviour.filter((b) => b.contribution > 0);
  const nights = unusual.filter((b) => b.last_seen && isNight(b.last_seen));

  const summary = unusual.length
    ? `${entity} ${unusual.slice(0, 3).map((b) => techPlain(b.technique_id).charAt(0).toLowerCase() + techPlain(b.technique_id).slice(1)).join(', ')}.` +
      ` ${unusual.length > 1 ? 'Each is uncommon among colleagues, and together they form a pattern.' : 'This is uncommon among colleagues.'}`
    : `${entity}'s activity matches what most colleagues do. Nothing stands out.`;

  if (!entity) return <section className="ui-card"><p className="ui-muted">Choose a person on the left to open their case.</p></section>;

  return (
    <div style={{ display: 'grid', gap: 16, minWidth: 0 }}>
      {/* Case header */}
      <section className="ui-card" aria-label={`Case for ${entity}`}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap', alignItems: 'flex-start' }}>
          <div style={{ minWidth: 0 }}>
            <div className="ui-kicker">Case file</div>
            <h2 className="ui-h1">{entity} <span className="ui-pill big" style={{ background: vs.bg, color: vs.fg }}>{vs.text}</span></h2>
            <p style={{ margin: '6px 0 0', fontSize: 16, lineHeight: 1.5, maxWidth: 680 }}>{summary}</p>
            {nights.length > 0 && <p className="ui-muted" style={{ margin: '4px 0 0' }}>Most recent unusual activity: {fmtWhen(nights[0].last_seen)} (outside working hours).</p>}
          </div>
          <div style={{ display: 'grid', gap: 10, minWidth: 220 }}>
            <div>
              <div className="ui-label">How risky <Info text="0 to 100. Combines the unusual behaviours found, weighted by how rare each one is among colleagues and how strong the evidence is." /></div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div className="ui-meter" style={{ flex: 1, height: 10 }}><div style={{ width: `${Math.round(risk * 100)}%`, background: vs.bar }} /></div>
                <b style={{ fontVariantNumeric: 'tabular-nums' }}>{Math.round(risk * 100)}</b>
              </div>
            </div>
            <div>
              <div className="ui-label">How sure <Info text="How strong the evidence is. Only evidence that was checked against the logs counts, and older evidence counts for less." /></div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div className="ui-meter" style={{ flex: 1, height: 10 }}><div style={{ width: `${conf}%`, background: '#2563eb' }} /></div>
                <b style={{ fontVariantNumeric: 'tabular-nums' }}>{Math.round(conf)}%</b>
              </div>
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 14 }}>
          <button className="ui-btn primary" onClick={() => investigate()} disabled={busy}>{busy ? 'Investigating…' : v ? 'Investigate again' : 'Ask the AI to investigate'}</button>
          <a className="ui-btn" href={`${apiBaseUrl}/incidents/${encodeURIComponent(entity)}/stix`} download={`case_${entity}.stix.json`}
             title="Download this case in STIX 2.1, the standard format security tools use to share findings">Export case file</a>
        </div>
        {error && <p className="ui-error">{error}</p>}
      </section>

      {/* AI result */}
      {v && (
        <section className="ui-card" aria-label="AI investigation result" style={{ borderLeft: `5px solid ${status === 'unverified' ? '#dc2626' : '#16a34a'}` }}>
          <h3 className="ui-h3">What the AI concluded</h3>
          <p style={{ margin: '6px 0', fontSize: 15 }}><b>Recommendation:</b> {RECOMMENDATION[result.decision] || RECOMMENDATION.analyst}</p>
          {status === 'unverified'
            ? <p className="ui-warn">⚠ Some of the AI's claims could not be found in the logs. The answer is marked unverified and its risk was lowered. Treat it with caution.</p>
            : <p className="ui-ok">✓ Every claim was checked against the original logs ({v.groundedness?.verified_edges?.length || 0} pieces of evidence){status === 'regenerated' ? '. The AI had to correct itself first.' : '.'}</p>}
          <p className="ui-muted" style={{ margin: '4px 0 0' }}>
            {v.model !== 'template-fallback' ? `Written by ${v.model}.`
              : v.fallback_reason && v.fallback_reason !== 'offline'
                ? <>Written by the built-in rules engine because the AI model's answer could not be used: <b>{v.fallback_reason}</b>.</>
                : 'Written by the built-in rules engine (no AI model connected). Connect one under “AI model” below.'}
          </p>
          <details style={{ marginTop: 8 }} open={technical}>
            <summary className="ui-muted" style={{ cursor: 'pointer' }}>Show the full AI answer</summary>
            <p style={{ fontSize: 14, lineHeight: 1.55, background: '#f8fafc', padding: 12, borderRadius: 8, overflowWrap: 'anywhere' }}>{v.narrative}</p>
            {technical && <GroundednessBadge verdict={v} />}
          </details>
        </section>
      )}

      {/* Why */}
      <section className="ui-card" aria-label="Why this person was flagged">
        <h3 className="ui-h3">Why {unusual.length ? 'we think so' : 'nothing stands out'}</h3>
        {!v && <p className="ui-muted" style={{ marginTop: 2 }}>Found by the rules engine. Ask the AI to investigate to have each item checked against the logs.</p>}
        <div className="ui-table-wrap">
          <table className="ui-table">
            <thead><tr><th>What happened</th><th>When</th><th>Times</th><th>Colleagues who do this <Info text="Share of all employees in the data who show the same behaviour. Rare behaviour counts more." /></th>{v && <th>Checked</th>}</tr></thead>
            <tbody>
              {behaviour.map((b) => (
                <tr key={b.technique_id} style={{ opacity: b.contribution > 0 ? 1 : 0.6 }}>
                  <td><b>{techPlain(b.technique_id)}</b>{technical && <div className="ui-code">{b.technique_id} · {TECHNIQUES[b.technique_id]?.name} · {b.pattern}</div>}</td>
                  <td>{b.first_seen === b.last_seen ? fmtWhen(b.last_seen) : <>{fmtWhen(b.first_seen)}<br />to {fmtWhen(b.last_seen)}</>}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{b.support}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 120 }}>
                      <div className="ui-meter" style={{ flex: 1 }}><div style={{ width: `${Math.round(100 * b.peer_prevalence)}%`, background: b.peer_prevalence < 0.25 ? '#dc2626' : b.peer_prevalence < 0.6 ? '#ea580c' : '#94a3b8' }} /></div>
                      <span style={{ fontVariantNumeric: 'tabular-nums' }}>{Math.round(100 * b.peer_prevalence)}%</span>
                    </div>
                    {b.contribution === 0 && <div className="ui-muted" style={{ fontSize: 12 }}>Common, so it does not add to the risk</div>}
                  </td>
                  {v && <td>{b.verified ? <span className="ui-ok">✓ Found in logs</span> : <span className="ui-muted">—</span>}</td>}
                </tr>
              ))}
              {behaviour.length === 0 && <tr><td colSpan={5} className="ui-muted">No behaviours matching known attacker techniques.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      {/* Graph + activity */}
      <section className="ui-card" aria-label="How it connects">
        <h3 className="ui-h3">How it connects</h3>
        <p className="ui-muted" style={{ marginTop: 2 }}>Each line is a real log record. Suspicious behaviours are named using MITRE ATT&CK <Info text="MITRE ATT&CK is the catalogue of known attacker behaviour used by security teams worldwide." />.</p>
        {subgraph ? <EvidenceGraph subgraph={subgraph} focus={entity} verified={verified} technical={technical} /> : <p className="ui-muted">Loading…</p>}
      </section>
      <section className="ui-card" aria-label="Activity over time">
        <h3 className="ui-h3">Activity over time</h3>
        {subgraph ? <ActivityChart subgraph={subgraph} focus={entity} /> : <p className="ui-muted">Loading…</p>}
      </section>

      {/* Ask */}
      <section className="ui-card" aria-label="Ask a question">
        <h3 className="ui-h3">Ask a question about {entity}</h3>
        <p className="ui-muted" style={{ margin: '2px 0 8px' }}>Answers come only from {entity}'s work activity in the logs. Questions about personal characteristics are declined.</p>
        <div aria-live="polite" style={{ display: 'grid', gap: 10, marginBottom: thread.length ? 12 : 0 }}>
          {thread.map((m, k) => (
            <div key={k} style={{ display: 'grid', gap: 6 }}>
              <div style={{ justifySelf: 'end', background: '#eef2ff', color: '#1e1b4b', padding: '8px 12px', borderRadius: '12px 12px 2px 12px', maxWidth: '85%', overflowWrap: 'anywhere' }}>{m.q}</div>
              {m.pending ? <div className="ui-muted" style={{ padding: '4px 2px' }}>Looking through the logs…</div> : <Answer a={m.a} technical={technical} />}
            </div>
          ))}
          <div ref={threadEnd} />
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '0 0 8px' }}>
          {SUGGESTED.map((sg) => <button key={sg} className="ui-chip" onClick={() => ask(sg)} disabled={asking}>{sg}</button>)}
        </div>
        <form onSubmit={(e) => { e.preventDefault(); ask(); }} style={{ display: 'flex', gap: 8 }}>
          <input className="ui-input" value={question} onChange={(e) => setQuestion(e.target.value)} aria-label="Your question"
                 placeholder={`e.g. Did ${entity} use a USB drive at night?`} maxLength={500} style={{ flex: 1, minWidth: 0 }} />
          <button className="ui-btn primary" disabled={asking || !question.trim()}>{asking ? 'Asking…' : 'Ask'}</button>
        </form>
      </section>

      {technical && (
        <section className="ui-card" aria-label="Technical details">
          <h3 className="ui-h3">Technical details</h3>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center', fontSize: 13, margin: '6px 0 10px' }}>
            <label>Graph depth{' '}
              <select className="ui-select" value={hops} onChange={(e) => setHops(Number(e.target.value))}>
                <option value={1}>1 hop (this person)</option><option value={2}>2 hops (+ neighbours)</option>
              </select>
            </label>
            {result && <span>Query type: <b>{result.query_type}</b> · gate decision: <b>{result.decision}</b> · groundedness: <b>{status}</b> · retries {v?.groundedness?.retries_used ?? 0}</span>}
          </div>
          {subgraph && <RawTables subgraph={subgraph} focus={entity} cited={new Set((v?.cited_edges || []).map(String))} />}
          <div style={{ marginTop: 12 }}><Timeline entityId={entity} apiBaseUrl={apiBaseUrl} /></div>
        </section>
      )}
    </div>
  );
}

function Answer({ a, technical }) {
  if (a.error) return <p className="ui-error" style={{ margin: 0 }}>{a.error}</p>;
  const box = { background: a.refused ? '#f8fafc' : '#ffffff', border: `1px solid ${a.refused ? '#cbd5e1' : '#e2e8f0'}`,
                borderRadius: '12px 12px 12px 2px', padding: '10px 12px', maxWidth: '92%', overflowWrap: 'anywhere' };
  return (
    <div style={box}>
      {a.refused && <div className="ui-label" style={{ color: '#475569' }}>🛡 Not something this tool will answer</div>}
      <div style={{ lineHeight: 1.5 }}>{a.answer}</div>
      {a.evidence?.length > 0 && (
        <ul style={{ margin: '8px 0 0', paddingLeft: 18, fontSize: 13, color: '#334155', lineHeight: 1.6 }}>
          {a.evidence.map((e, i) => <li key={i}>{e}</li>)}
          {a.more > 0 && <li className="ui-muted">and {a.more} more</li>}
        </ul>
      )}
      <div className="ui-muted" style={{ fontSize: 12, marginTop: 6, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {!a.refused && a.status === 'grounded' && a.cited_edges?.length > 0 && <span className="ui-ok" style={{ margin: 0 }}>✓ Checked against {a.cited_edges.length} log record{a.cited_edges.length > 1 ? 's' : ''}</span>}
        {a.status === 'unverified' && <span style={{ color: '#b91c1c', fontWeight: 600 }}>⚠ Some cited records do not exist; treat with caution</span>}
        {a.model === 'rules-engine' && <span>Answered from the logs directly{a.fallback_reason && a.fallback_reason !== 'offline mode' ? ` (AI model not used: ${a.fallback_reason})` : ''}</span>}
        {a.model && !['rules-engine', 'scope-guard'].includes(a.model) && <span>Answered by {a.model}</span>}
        {a.refused && a.model === 'scope-guard' && <span>Declined before reaching the AI · recorded in the audit log</span>}
        {technical && a.cited_edges?.length > 0 && <span className="ui-code">{a.cited_edges.join(', ')}</span>}
      </div>
    </div>
  );
}

function RawTables({ subgraph, focus, cited }) {
  const ids = edgeIds(subgraph);
  const edges = subgraph.edges.map((e, i) => ({ ...e, _id: ids[i] }))
    .sort((a, b) => (b.source === focus) - (a.source === focus) || cited.has(b._id) - cited.has(a._id));
  const nodes = [...subgraph.nodes].sort((a, b) => (a.distance ?? 9) - (b.distance ?? 9));
  return (
    <div className="ui-grid2">
      <div><div className="ui-label">Nodes ({nodes.length})</div>
        <div className="ui-table-wrap" style={{ maxHeight: 320 }}><table className="ui-table mono">
          <thead><tr><th>ID</th><th>Type</th><th>Dist</th></tr></thead>
          <tbody>{nodes.map((n) => <tr key={n.id}><td className="ui-trunc" title={n.id}>{n.id}</td><td>{n.type}</td><td>{n.distance}</td></tr>)}</tbody>
        </table></div></div>
      <div><div className="ui-label">Edges ({edges.length}) · cited first</div>
        <div className="ui-table-wrap" style={{ maxHeight: 320 }}><table className="ui-table mono">
          <thead><tr><th>ID</th><th>From → to</th><th>Relation</th><th>Conf</th></tr></thead>
          <tbody>{edges.map((e) => (
            <tr key={e._id} style={{ background: cited.has(e._id) ? '#ecfdf5' : undefined }}>
              <td>{e._id}</td><td className="ui-trunc" title={`${e.source} → ${e.target}`}>{e.source} → {e.target}</td>
              <td title={relPlain(e.type || e.relation)}>{e.type || e.relation}</td><td>{Math.round(100 * (e.confidence ?? 0))}%</td>
            </tr>))}</tbody>
        </table></div></div>
    </div>
  );
}
