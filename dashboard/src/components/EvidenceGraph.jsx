import React, { useEffect, useMemo, useRef, useState } from 'react';
import { DataSet, Network } from 'vis-network/standalone';
import 'vis-network/styles/vis-network.css';
import { KIND_STYLE, edgeIds, fmtWhen, nodeKind, nodeLabel, relPlain } from '../plain';

// Evidence-first graph: the investigated person on the left, what they touched in the middle,
// suspicious behaviours on the right. Positions are computed here and physics is OFF, so the
// layout never stretches or drifts. Edge labels appear only in the hover tooltip.

const COLS = { person: 0, mid: 330, behaviour: 700 };
const ROW = 66;
const PER_BEHAVIOUR = 3;

function build(subgraph, focus, mode, verified, technical) {
  const nodes = subgraph?.nodes || [];
  const edges = subgraph?.edges || [];
  const ids = edgeIds(subgraph);
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  if (!byId[focus]) return { nodes: [], edges: [], note: 'This person is not in the graph.' };
  const rel = (e) => e.type || e.relation;
  const out = [];
  const add = (from, to, e, i, extra = {}) => out.push({ from, to, e, id: ids[i], ...extra });

  const shownMid = new Map(); // id -> node
  const shownBeh = new Set();
  const groupOf = new Map(); // mid id -> technique it was first shown for (layout grouping)
  let note = '';

  if (mode === 'evidence') {
    const ownByKey = new Map();
    edges.forEach((e, i) => { if (e.source === focus && rel(e) !== 'MATCHES_TECHNIQUE') ownByKey.set(`${e.target}|${e.timestamp}`, i); });
    const chains = {}; // technique -> [{mid, i1, i2, ts}]
    const direct = {};
    edges.forEach((e, i) => {
      if (rel(e) === 'INDICATES' && ownByKey.has(`${e.source}|${e.timestamp}`)) {
        (chains[e.target] ||= []).push({ mid: e.source, i1: ownByKey.get(`${e.source}|${e.timestamp}`), i2: i, ts: e.timestamp });
      } else if (rel(e) === 'MATCHES_TECHNIQUE' && e.source === focus) {
        (direct[e.target] ||= []).push(i);
      }
    });
    const techs = [...new Set([...Object.keys(chains), ...Object.keys(direct)])];
    if (techs.length === 0) {
      mode = 'nearby';
      note = 'No suspicious behaviour found for this person. Showing what they used instead.';
    } else {
      for (const t of techs) {
        shownBeh.add(t);
        const list = (chains[t] || []).sort((a, b) => {
          const va = verified.has(ids[a.i1]) && verified.has(ids[a.i2]) ? 1 : 0;
          const vb = verified.has(ids[b.i1]) && verified.has(ids[b.i2]) ? 1 : 0;
          return vb - va || String(b.ts).localeCompare(String(a.ts));
        });
        const seen = new Set();
        let shown = 0;
        for (const c of list) {
          if (seen.has(c.mid)) continue;
          seen.add(c.mid);
          if (shown < PER_BEHAVIOUR) {
            shownMid.set(c.mid, byId[c.mid]);
            if (!groupOf.has(c.mid)) groupOf.set(c.mid, t);
            add(focus, c.mid, edges[c.i1], c.i1);
            add(c.mid, t, edges[c.i2], c.i2);
            shown += 1;
          }
        }
        const rest = seen.size - shown;
        if (rest > 0) {
          const mid = `more:${t}`;
          shownMid.set(mid, { id: mid, type: 'more', label: `+${rest} more` });
          groupOf.set(mid, t);
          out.push({ from: focus, to: mid, more: true });
          out.push({ from: mid, to: t, more: true });
        }
        if (!list.length) (direct[t] || []).slice(0, 1).forEach((i) => add(focus, t, edges[i], i, { dashed: true }));
      }
    }
  }

  if (mode === 'nearby') {
    const groups = new Map(); // other -> {indices, dirOut}
    edges.forEach((e, i) => {
      if (e.source !== focus && e.target !== focus) return;
      const other = e.source === focus ? e.target : e.source;
      if (!byId[other]) return;
      const g = groups.get(other) || { idx: [], from: e.source, to: e.target };
      g.idx.push(i);
      groups.set(other, g);
    });
    const ranked = [...groups.entries()].sort((a, b) => {
      const ka = byId[a[0]].type === 'AttackTechnique' ? 0 : 1, kb = byId[b[0]].type === 'AttackTechnique' ? 0 : 1;
      return ka - kb || b[1].idx.length - a[1].idx.length;
    });
    const MAX = 24;
    ranked.slice(0, MAX).forEach(([other, g]) => {
      if (byId[other].type === 'AttackTechnique') shownBeh.add(other); else shownMid.set(other, byId[other]);
      const i = g.idx[0];
      out.push({ from: g.from, to: g.to, e: edges[i], id: ids[i], count: g.idx.length, allIds: g.idx.map((k) => ids[k]) });
    });
    if (ranked.length > MAX) note = `Showing the ${MAX} things this person used most (of ${ranked.length}).`;
  }

  const visNodes = [];
  const techs = [...shownBeh].filter((t) => byId[t]);
  const midList = [...shownMid.values()].sort((a, b) => {
    const ga = techs.indexOf(groupOf.get(a.id)), gb = techs.indexOf(groupOf.get(b.id));
    return (ga < 0 ? 99 : ga) - (gb < 0 ? 99 : gb) || (a.type === 'more') - (b.type === 'more') ||
      nodeKind(a).localeCompare(nodeKind(b)) || String(a.id).localeCompare(String(b.id));
  });
  const midY = new Map(midList.map((n, k) => [n.id, (k - (midList.length - 1) / 2) * ROW]));
  // each behaviour sits level with the evidence that supports it; then spread to avoid overlaps
  const techY = techs.map((t, k) => {
    const ys = midList.filter((n) => groupOf.get(n.id) === t).map((n) => midY.get(n.id));
    return { t, y: ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : (k - (techs.length - 1) / 2) * ROW };
  }).sort((a, b) => a.y - b.y);
  for (let k = 1; k < techY.length; k += 1) techY[k].y = Math.max(techY[k].y, techY[k - 1].y + ROW * 0.95);
  // with no middle column (direct matches only), centre the behaviours on the person
  const centre = !midList.length && techY.length ? (techY[0].y + techY[techY.length - 1].y) / 2 : 0;
  visNodes.push({ n: byId[focus], x: COLS.person, y: 0 });
  midList.forEach((n) => visNodes.push({ n, x: COLS.mid, y: midY.get(n.id) }));
  techY.forEach(({ t, y }) => visNodes.push({ n: byId[t], x: COLS.behaviour, y: y - centre }));

  const vn = visNodes.map(({ n, x, y }) => {
    const kind = n.type === 'more' ? 'more' : nodeKind(n);
    const st = KIND_STYLE[kind];
    const isFocus = n.id === focus;
    return {
      id: n.id, x, y, fixed: false, physics: false,
      label: n.type === 'more' ? n.label : nodeLabel(n, technical),
      title: n.type === 'more' ? 'More items with the same behaviour (hidden to keep the picture readable)'
        : `${nodeLabel(n)}${technical ? `\n${n.id} (${n.type})` : ''}`,
      ...(kind === 'behaviour'
        ? { shape: 'box', margin: { top: 7, bottom: 7, left: 10, right: 10 }, widthConstraint: { maximum: 230 },
            color: { background: '#fef2f2', border: '#dc2626', highlight: { background: '#fee2e2', border: '#991b1b' } }, borderWidth: 1.5,
            shapeProperties: { borderRadius: 8 }, font: { size: 13, color: '#7f1d1d', face: 'Inter, system-ui, sans-serif' } }
        : { shape: 'dot', size: isFocus ? 26 : kind === 'more' ? 10 : 16,
            color: { background: st.color, border: isFocus ? '#0f172a' : '#ffffff', highlight: { background: st.color, border: '#0f172a' } },
            borderWidth: isFocus ? 4 : 2,
            font: { size: isFocus ? 16 : 13, color: '#0f172a', face: 'Inter, system-ui, sans-serif', strokeWidth: 4, strokeColor: '#ffffff' } }),
      labelHighlightBold: false,
    };
  });
  const ve = out.map((o, k) => {
    const ok = o.id && verified.has(o.id);
    const r = o.e ? rel(o.e) : '';
    const when = o.e?.timestamp ? fmtWhen(o.e.timestamp) : '';
    return {
      id: `v${k}`, from: o.from, to: o.to, arrows: { to: { enabled: !o.more, scaleFactor: 0.45 } },
      dashes: o.more || o.dashed, width: o.count ? Math.min(6, 1 + Math.log2(o.count)) : ok ? 2.6 : 1.4,
      color: { color: o.more ? '#cbd5e1' : ok ? '#16a34a' : (byId[o.to]?.type === 'AttackTechnique' ? '#f87171' : '#94a3b8'), highlight: '#2563eb', hover: '#2563eb' },
      smooth: { type: 'cubicBezier', forceDirection: 'horizontal', roundness: 0.4 },
      title: o.more ? 'Hidden items' : `${nodeLabel(byId[o.from]) || o.from} ${relPlain(r)} ${nodeLabel(byId[o.to]) || o.to}${o.count > 1 ? ` (${o.count} times)` : ''}${when ? `\n${when}` : ''}${ok ? '\n✓ checked against the logs' : ''}${technical && o.id ? `\nedge ${o.id} · ${r} · confidence ${Math.round(100 * (o.e?.confidence ?? 0))}%` : ''}`,
    };
  });
  return { nodes: vn, edges: ve, note, rows: Math.max(shownMid.size, shownBeh.size, 1) };
}

const NO_EDGES = new Set();
export default function EvidenceGraph({ subgraph, focus, verified = NO_EDGES, technical = false }) {
  const ref = useRef(null);
  const net = useRef(null);
  const [mode, setMode] = useState('evidence');
  const data = useMemo(() => build(subgraph, focus, mode, verified, technical), [subgraph, focus, mode, verified, technical]);
  const height = Math.max(300, Math.min(620, data.rows * ROW + 90));

  useEffect(() => {
    if (!ref.current) return;
    net.current?.destroy();
    net.current = new Network(ref.current, { nodes: new DataSet(data.nodes), edges: new DataSet(data.edges) }, {
      autoResize: true, physics: { enabled: false }, layout: { randomSeed: 1, improvedLayout: false },
      interaction: { hover: true, tooltipDelay: 120, navigationButtons: false, keyboard: false, zoomView: true, dragView: true, dragNodes: true },
      edges: { selectionWidth: 1.5, hoverWidth: 1 },
    });
    const fit = () => net.current?.fit({ animation: false, padding: 40 });
    net.current.once('afterDrawing', fit);
    return () => { net.current?.destroy(); net.current = null; };
  }, [data]);

  const zoom = (f) => { const n = net.current; if (n) n.moveTo({ scale: n.getScale() * f, animation: { duration: 150 } }); };
  const btn = { border: '1px solid #e2e8f0', background: 'white', borderRadius: 8, width: 32, height: 32, cursor: 'pointer', fontSize: 16, fontWeight: 700, color: '#334155' };
  const tab = (on) => ({ border: 'none', padding: '6px 12px', borderRadius: 8, cursor: 'pointer', fontWeight: 600, fontSize: 13,
                         background: on ? 'white' : 'transparent', color: on ? '#0f172a' : '#475569', boxShadow: on ? '0 1px 3px rgba(15,23,42,.12)' : 'none' });
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
        <div role="tablist" aria-label="Graph view" style={{ display: 'inline-flex', background: '#f1f5f9', padding: 3, borderRadius: 10 }}>
          <button role="tab" aria-selected={mode === 'evidence'} style={tab(mode === 'evidence')} onClick={() => setMode('evidence')}>What looks suspicious</button>
          <button role="tab" aria-selected={mode === 'nearby'} style={tab(mode === 'nearby')} onClick={() => setMode('nearby')}>Everything they used</button>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button style={btn} onClick={() => zoom(1.25)} aria-label="Zoom in" title="Zoom in">+</button>
          <button style={btn} onClick={() => zoom(0.8)} aria-label="Zoom out" title="Zoom out">−</button>
          <button style={{ ...btn, width: 'auto', padding: '0 10px', fontSize: 13 }} onClick={() => net.current?.fit({ animation: { duration: 250 }, padding: 40 })}>Reset view</button>
        </div>
      </div>
      <div style={{ position: 'relative', border: '1px solid #e2e8f0', borderRadius: 12, background: '#fbfcfe', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', fontSize: 11, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '.06em', padding: '10px 14px 0', pointerEvents: 'none' }}>
          <span>Person</span><span style={{ textAlign: 'center' }}>What they used</span><span style={{ textAlign: 'right' }}>Suspicious behaviour</span>
        </div>
        <div ref={ref} style={{ height }} aria-label={`Graph of ${focus}'s activity`} role="img" />
      </div>
      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', fontSize: 12, color: '#475569', marginTop: 8, alignItems: 'center' }}>
        {data.note && <span style={{ color: '#9a3412' }}>{data.note}</span>}
        <span><span style={{ display: 'inline-block', width: 18, borderTop: '3px solid #16a34a', verticalAlign: 'middle' }} /> checked against the logs</span>
        <span><span style={{ display: 'inline-block', width: 18, borderTop: '2px solid #f87171', verticalAlign: 'middle' }} /> linked to a suspicious behaviour</span>
        <span style={{ marginLeft: 'auto' }}>Hover a line for details · scroll to zoom · drag to move</span>
      </div>
    </div>
  );
}
