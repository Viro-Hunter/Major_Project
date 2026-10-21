import React, { useEffect, useMemo, useState } from 'react';

// Mirrors llm/providers.py detect_provider() so the badge updates while typing,
// without sending a half-typed key anywhere.
const RULES = [
  ['openrouter', 'OpenRouter', /^sk-or-/],
  ['anthropic', 'Anthropic', /^sk-ant-/],
  ['groq', 'Groq', /^gsk_/],
  ['gemini', 'Google Gemini', /^AIza[0-9A-Za-z_-]{20,}$/],
  ['xai', 'xAI', /^xai-/],
  ['openai', 'OpenAI', /^sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}$/],
];
const PROVIDER_LABELS = Object.fromEntries(RULES.map(([id, label]) => [id, label]));

function detect(key) {
  const k = key.trim();
  if (!k) return null;
  if (/\s/.test(k)) return { id: null, text: 'The key contains spaces — paste it again.' };
  const hit = RULES.find(([, , re]) => re.test(k));
  return hit ? { id: hit[0], text: `${hit[1]} key detected` } : { id: null, text: 'Unrecognised key — choose the provider below.' };
}

const card = { background: 'white', borderRadius: 16, padding: 16, boxShadow: '0 4px 20px rgba(15,23,42,0.06)', border: '1px solid #e2e8f0' };
const input = { width: '100%', padding: '10px 12px', borderRadius: 10, border: '1px solid #cbd5e1', background: '#f8fafc', outline: 'none', fontSize: 14 };
const btn = (primary, disabled) => ({
  padding: '9px 14px', borderRadius: 10, fontWeight: 700, fontSize: 13, cursor: disabled ? 'not-allowed' : 'pointer',
  border: primary ? 'none' : '1px solid #e2e8f0', background: disabled ? '#94a3b8' : primary ? '#2563eb' : 'white', color: primary ? 'white' : '#0f172a',
});

function priceLabel(m) {
  if (m.free) return 'free';
  if (m.est_cost_per_verdict == null) return 'paid';
  const c = m.est_cost_per_verdict;
  return `≈ $${c < 0.001 ? c.toFixed(5) : c.toFixed(4)} per verdict`;
}

export default function ModelSettings({ apiBaseUrl, onStatusChange }) {
  const [key, setKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [providerOverride, setProviderOverride] = useState('');
  const [status, setStatus] = useState(null);
  const [check, setCheck] = useState(null);
  const [busy, setBusy] = useState('');
  const [filter, setFilter] = useState('');
  const [test, setTest] = useState(null);
  const [error, setError] = useState(null);

  const detected = useMemo(() => detect(key), [key]);
  const provider = providerOverride || detected?.id || '';

  const post = async (path, body) => {
    const r = await fetch(`${apiBaseUrl}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.detail || `HTTP ${r.status}`);
    return j;
  };

  const refreshStatus = async () => {
    try {
      const j = await (await fetch(`${apiBaseUrl}/llm/status`)).json();
      setStatus(j);
      onStatusChange?.(j);
    } catch {
      setStatus(null);
    }
  };
  useEffect(() => { refreshStatus(); }, []);

  const connect = async () => {
    setBusy('connect'); setError(null); setTest(null);
    try {
      const j = await post('/llm/connect', { api_key: key, provider: provider || undefined });
      setCheck(j);
      if (j.valid) { setKey(''); setFilter(''); }
      await refreshStatus();
    } catch (e) { setError(String(e.message || e)); }
    setBusy('');
  };

  const select = async (model) => {
    setBusy('select'); setError(null); setTest(null);
    try { const j = await post('/llm/select', { model }); setStatus(j); onStatusChange?.(j); }
    catch (e) { setError(String(e.message || e)); }
    setBusy('');
  };

  const runTest = async () => {
    setBusy('test'); setTest(null);
    try { setTest(await post('/llm/test')); } catch (e) { setTest({ ok: false, error: String(e.message || e) }); }
    setBusy('');
  };

  const disconnect = async () => {
    setBusy('disconnect');
    try { const j = await post('/llm/disconnect'); setStatus(j); onStatusChange?.(j); setCheck(null); setTest(null); } catch (e) { setError(String(e.message || e)); }
    setBusy('');
  };

  const models = check?.valid ? check.models : [];
  const visible = models.filter((m) => !filter || `${m.id} ${m.name}`.toLowerCase().includes(filter.toLowerCase()));
  const paid = visible.filter((m) => !m.free);
  const free = visible.filter((m) => m.free);
  const connected = status?.source === 'dashboard';

  const option = (m) => (
    <option key={m.id} value={m.id}>
      {m.id === check?.recommended ? '★ ' : ''}{m.name} — {m.router ? 'router: a different model each time, ' : ''}{priceLabel(m)}{m.context_length ? `, ${Math.round(m.context_length / 1000)}k context` : ''}
    </option>
  );

  return (
    <section style={{ ...card, marginBottom: 18 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', flexWrap: 'wrap', gap: 8, marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 800 }}>AI model</h3>
        <span style={{ fontSize: 13, color: '#334155' }}>
          {status ? (
            <>
              Using <b>{status.model}</b> on {status.label}
              {status.tier === 'free' && <span style={{ marginLeft: 6, background: '#dcfce7', color: '#166534', padding: '2px 8px', borderRadius: 20, fontSize: 12, fontWeight: 700 }}>free tier</span>}
              {status.tier === 'paid' && <span style={{ marginLeft: 6, background: '#dbeafe', color: '#1e40af', padding: '2px 8px', borderRadius: 20, fontSize: 12, fontWeight: 700 }}>paid</span>}
              {status.source === 'env' && <span style={{ color: '#64748b' }}> (from .env)</span>}
              {status.offline && <span style={{ color: '#b45309' }}> — offline mode is on, verdicts use the rule template</span>}
            </>
          ) : 'API offline'}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 170px auto', gap: 8, alignItems: 'end' }}>
        <label style={{ fontSize: 13, fontWeight: 600, color: '#334155' }}>
          API key
          <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
            <input
              type={showKey ? 'text' : 'password'}
              value={key}
              onChange={(e) => { setKey(e.target.value); setProviderOverride(''); setCheck(null); }}
              onKeyDown={(e) => e.key === 'Enter' && key.trim() && connect()}
              placeholder={connected ? `Connected ${status.key_hint} — paste another key to switch` : 'Paste an OpenRouter, Anthropic, OpenAI, Groq or Gemini key'}
              autoComplete="off" spellCheck={false}
              style={{ ...input, fontFamily: key && !showKey ? 'inherit' : undefined }}
              aria-describedby="key-detect"
            />
            <button type="button" onClick={() => setShowKey(!showKey)} style={btn(false)} aria-label={showKey ? 'Hide key' : 'Show key'}>{showKey ? 'Hide' : 'Show'}</button>
          </div>
        </label>
        <label style={{ fontSize: 13, fontWeight: 600, color: '#334155' }}>
          Provider
          <select value={provider} onChange={(e) => setProviderOverride(e.target.value)} style={{ ...input, marginTop: 6, background: 'white' }}>
            <option value="">Auto-detect</option>
            {Object.entries(PROVIDER_LABELS).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </select>
        </label>
        <button type="button" onClick={connect} disabled={!key.trim() || busy === 'connect'} style={btn(true, !key.trim() || busy === 'connect')}>
          {busy === 'connect' ? 'Checking…' : 'Check key'}
        </button>
      </div>

      <div id="key-detect" aria-live="polite" style={{ fontSize: 12, marginTop: 6, minHeight: 16, color: detected?.id ? '#047857' : '#b45309' }}>
        {detected ? `${detected.id ? '✓ ' : ''}${detected.text}` : ''}
      </div>

      {check && (
        <div role="status" style={{ marginTop: 8, padding: '9px 12px', borderRadius: 10, fontSize: 13,
          background: check.valid ? (check.tier === 'paid' ? '#eff6ff' : '#f0fdf4') : '#fef2f2',
          border: `1px solid ${check.valid ? (check.tier === 'paid' ? '#bfdbfe' : '#bbf7d0') : '#fecaca'}`,
          color: check.valid ? '#0f172a' : '#991b1b' }}>
          {check.message}
          {check.valid && check.credits?.remaining_usd != null && <> Credit left: <b>${check.credits.remaining_usd.toFixed(2)}</b>.</>}
        </div>
      )}

      {check?.valid && (
        <div style={{ display: 'grid', gridTemplateColumns: '200px minmax(0,1fr)', gap: 8, marginTop: 12, alignItems: 'end' }}>
          <label style={{ fontSize: 13, fontWeight: 600, color: '#334155' }}>
            Filter models
            <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="e.g. llama, claude" style={{ ...input, marginTop: 6 }} />
          </label>
          <label style={{ fontSize: 13, fontWeight: 600, color: '#334155' }}>
            Model ({visible.length} of {models.length}) — ★ recommended for this key
            <select value={status?.model || ''} onChange={(e) => select(e.target.value)} disabled={busy === 'select'} style={{ ...input, marginTop: 6, background: 'white' }}>
              {!visible.some((m) => m.id === status?.model) && status?.model && <option value={status.model}>{status.model}</option>}
              {check.tier === 'paid' && paid.length > 0 && <optgroup label="Paid models (uses your credit)">{paid.map(option)}</optgroup>}
              {free.length > 0 && <optgroup label="Free models (rate-limited)">{free.map(option)}</optgroup>}
            </select>
          </label>
        </div>
      )}

      {error && <p style={{ color: '#b91c1c', fontSize: 13, margin: '8px 0 0' }}>{error}</p>}

      <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <button type="button" onClick={runTest} disabled={!!busy || status?.offline} style={btn(false, !!busy || status?.offline)}>
          {busy === 'test' ? 'Sending…' : 'Send test prompt'}
        </button>
        {connected && <button type="button" onClick={disconnect} disabled={!!busy} style={btn(false, !!busy)}>Forget key</button>}
        {test && (
          <span style={{ fontSize: 13, color: test.ok ? '#047857' : '#b91c1c' }}>
            {test.ok ? `✓ ${test.model} answered in ${test.latency_ms} ms` : test.error || `Unexpected reply: ${test.reply}`}
          </span>
        )}
      </div>
      <p style={{ fontSize: 11, color: '#64748b', margin: '10px 0 0' }}>
        The key is held in the API server's memory only and is forgotten when it restarts. To keep it, add it to <code>.env</code> (see <code>.env.example</code>).
      </p>
    </section>
  );
}
