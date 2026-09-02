import React, { useEffect, useState } from 'react';

export default function Timeline({ entityId, apiBaseUrl }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!entityId) return;
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError('');
      try {
        const r = await fetch(`${apiBaseUrl}/graph/timeline/${encodeURIComponent(entityId)}?limit=50`);
        if (!r.ok) throw new Error(`Timeline ${r.status}`);
        const j = await r.json();
        if (!cancelled) setData(j);
      } catch (e) {
        if (!cancelled) setError(String(e));
      }
      setLoading(false);
    }
    load();
    return () => { cancelled = true; };
  }, [entityId, apiBaseUrl]);

  if (loading) return <p style={{ fontSize: 13, color: '#64748b' }}>Loading timeline for {entityId}…</p>;
  if (error) return <p style={{ color: '#b91c1c', fontSize: 13 }}>{error}</p>;
  if (!data) return null;

  const typeColor = (type) => {
    if (type === 'MATCHES_TECHNIQUE' || type === 'INDICATES') return '#dc2626';
    if (type === 'ACCESSED' || type === 'SENT_EMAIL_TO' || type === 'BROWSED') return '#d97706';
    if (type === 'OBSERVED_ON' || type === 'LOGGED_IN_FROM') return '#0f766e';
    return '#64748b';
  };

  const typeBadge = (type) => (
    <span style={{ background: typeColor(type) + '18', color: typeColor(type), border: `1px solid ${typeColor(type)}30`, padding: '2px 8px', borderRadius: 20, fontSize: 11, fontWeight: 700 }}>
      {type}
    </span>
  );

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <h4 style={{ margin: 0, fontSize: 13, fontWeight: 800 }}>Dissected Timeline — {entityId} <span style={{ fontWeight: 400, color: '#64748b' }}>({data.total_events} events)</span></h4>
        <span style={{ fontSize: 11, color: '#64748b', background: '#f8fafc', padding: '4px 8px', borderRadius: 20, border: '1px solid #e2e8f0' }}>{data.summary}</span>
      </div>

      {/* Vertical timeline */}
      <div style={{ position: 'relative', paddingLeft: 18, borderLeft: '2px solid #e2e8f0' }}>
        {data.events.length === 0 ? (
          <p style={{ fontSize: 13, color: '#94a3b8', fontStyle: 'italic' }}>No events for this entity — try another user or increase hops.</p>
        ) : (
          data.events.map((e, idx) => (
            <div key={idx} style={{ position: 'relative', marginBottom: 14, background: 'white', borderRadius: 12, padding: '10px 12px', boxShadow: '0 2px 10px rgba(15,23,42,0.04)', border: '1px solid #f1f5f9', borderLeft: `3px solid ${typeColor(e.type || e.relation)}` }}>
              {/* dot */}
              <span style={{ position: 'absolute', left: -25, top: 14, width: 12, height: 12, borderRadius: '50%', background: typeColor(e.type || e.relation), border: '2px solid white', boxShadow: '0 0 0 2px #e2e8f0' }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#0f172a' }}>{e.timestamp || '—'} {typeBadge(e.type || e.relation)}</span>
                <span style={{ fontSize: 11, color: '#64748b' }}>{e.source} → {e.target}</span>
              </div>
              <div style={{ marginTop: 6, fontSize: 13, color: '#1e293b', lineHeight: 1.4 }}>{e.story}</div>
              {e.pattern && <div style={{ marginTop: 4, fontSize: 11, color: '#475569' }}>Pattern: <code>{e.pattern}</code> {e.confidence ? `• ${Math.round(e.confidence * 100)}%` : ''}</div>}
              {e.type === 'MATCHES_TECHNIQUE' && <div style={{ marginTop: 4, fontSize: 11, color: '#dc2626', fontWeight: 600 }}>→ ATT&CK: {e.target} — review as potential insider step</div>}
            </div>
          ))
        )}
      </div>

      {/* Dissected clusters */}
      <div style={{ marginTop: 12, display: 'flex', gap: 8, flexWrap: 'wrap', fontSize: 11, color: '#64748b' }}>
        <span>Dissect by:</span>
        <span style={{ background: '#fef3c7', color: '#92400e', padding: '3px 8px', borderRadius: 20, border: '1px solid #fde68a' }}>File: {data.events.filter(e => (e.type||'').includes('ACCESSED')).length} accesses</span>
        <span style={{ background: '#fee2e2', color: '#991b1b', padding: '3px 8px', borderRadius: 20, border: '1px solid #fecaca' }}>Technique: {data.events.filter(e => (e.type||'').includes('MATCHES')).length} matches</span>
        <span style={{ background: '#dcfce7', color: '#166534', padding: '3px 8px', borderRadius: 20, border: '1px solid #bbf7d0' }}>Host: {new Set(data.events.map(e => e.target).filter(t => t.startsWith('host:'))).size} hosts</span>
      </div>
    </div>
  );
}
