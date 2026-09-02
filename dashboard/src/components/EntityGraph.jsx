import React, { useEffect, useRef, useState, useMemo } from 'react';
import { DataSet, Network } from 'vis-network/standalone';
import 'vis-network/styles/vis-network.css';

const COLORS = {
  User: '#2563eb',
  Host: '#0f766e',
  FileResource: '#d97706',
  AttackTechnique: '#dc2626',
  Device: '#7c3aed',
  EmailEvent: '#be185d',
  NetworkConnection: '#475569',
};

export default function EntityGraph({ entityId, hops = 2, apiBaseUrl = '', height = 520 }) {
  const containerRef = useRef(null);
  const networkRef = useRef(null);
  const [status, setStatus] = useState('loading');
  const [error, setError] = useState('');
  const [rawGraph, setRawGraph] = useState(null);
  const [maxEdges, setMaxEdges] = useState(25);
  const [groupParallel, setGroupParallel] = useState(true);
  const [minConfidence, setMinConfidence] = useState(0);

  useEffect(() => {
    let cancelled = false;
    async function loadGraph() {
      setStatus('loading');
      setError('');
      try {
        const response = await fetch(`${apiBaseUrl}/graph/subgraph/${encodeURIComponent(entityId)}?hops=${hops}`);
        if (!response.ok) throw new Error(response.status === 404 ? 'Entity was not found.' : `Graph request failed (${response.status}).`);
        const graph = await response.json();
        if (cancelled) return;
        setRawGraph(graph);
        setStatus('ready');
      } catch (requestError) {
        if (!cancelled) { setError(requestError.message); setStatus('error'); }
      }
    }
    loadGraph();
    return () => { cancelled = true; };
  }, [apiBaseUrl, entityId, hops]);

  const { displayNodes, displayEdges, stats } = useMemo(() => {
    if (!rawGraph) return { displayNodes: [], displayEdges: [], stats: null };
    const nodes = rawGraph.nodes || [];
    let edges = rawGraph.links || rawGraph.edges || [];

    // Filter by confidence
    edges = edges.filter((e) => (e.confidence ?? 1) >= minConfidence);

    // Sort by confidence desc, then type
    edges = [...edges].sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0));

    const originalCount = edges.length;

    // Group parallel edges for cleaner view
    if (groupParallel) {
      const grouped = new Map();
      for (const e of edges) {
        const from = e.from || e.source;
        const to = e.to || e.target;
        const type = e.type || e.relation || 'UNKNOWN';
        const key = `${from}→${to}:${type}`;
        if (!grouped.has(key)) {
          grouped.set(key, { ...e, from, to, count: 1, confidence: e.confidence ?? 0 });
        } else {
          const g = grouped.get(key);
          g.count += 1;
          // keep max confidence
          g.confidence = Math.max(g.confidence, e.confidence ?? 0);
        }
      }
      edges = Array.from(grouped.values()).map((g) => ({
        ...g,
        label: g.count > 1 ? `${g.type || g.relation} ×${g.count}` : (g.type || g.relation || ''),
        title: g.count > 1 ? `${g.type} ×${g.count} (grouped parallel edges)` : g.type,
        width: g.count > 1 ? Math.min(6, 1 + Math.log2(g.count)) : 1,
      }));
    }

    // Cap to maxEdges (most relevant)
    const limited = edges.slice(0, maxEdges);
    const hidden = edges.length - limited.length;

    // Build node set from limited edges + ensure entityId visible
    const involved = new Set([entityId]);
    for (const e of limited) {
      const from = e.from || e.source;
      const to = e.to || e.target;
      if (from) involved.add(from);
      if (to) involved.add(to);
    }
    // Include isolated entity if no edges
    let filteredNodes = nodes.filter((n) => involved.has(n.id));
    if (filteredNodes.length === 0) {
      // fallback: show entity itself
      const selfNode = nodes.find((n) => n.id === entityId);
      if (selfNode) filteredNodes = [selfNode];
    }

    return {
      displayNodes: filteredNodes,
      displayEdges: limited,
      stats: { original: originalCount, displayed: limited.length, hidden, grouped: groupParallel },
    };
  }, [rawGraph, maxEdges, groupParallel, minConfidence, entityId]);

  useEffect(() => {
    if (!rawGraph || status !== 'ready') return;
    if (!containerRef.current) return;

    const nodes = new DataSet(
      displayNodes.map((node) => ({
        ...node,
        label: node.label || node.name || node.id,
        title: `${node.type || 'Entity'}: ${node.id}${node.attributes?.name ? ` (${node.attributes.name})` : ''}\nDegree: ${node.degree ?? '?'}`,
        color: COLORS[node.type] || '#64748b',
        shape: node.type === 'AttackTechnique' ? 'star' : node.id === entityId ? 'diamond' : 'dot',
        size: node.id === entityId ? 32 : node.type === 'AttackTechnique' ? 22 : 18,
        borderWidth: node.id === entityId ? 3 : 2,
        font: { color: '#0f172a', size: 13, strokeWidth: 3, strokeColor: '#ffffff' },
      }))
    );

    const edges = new DataSet(
      displayEdges.map((edge, index) => ({
        ...edge,
        id: edge.id || `${edge.from || edge.source}-${edge.to || edge.target}-${edge.key ?? index}`,
        from: edge.from || edge.source,
        to: edge.to || edge.target,
        arrows: 'to',
        label: edge.label || edge.type || edge.relation || '',
        font: { align: 'middle', size: 10, background: '#ffffff' },
        color: { color: edge.confidence >= 0.85 ? '#0f172a' : '#94a3b8', highlight: '#2563eb' },
        smooth: { type: 'curvedCW', roundness: 0.15 },
        width: edge.width || 1,
        title: `${edge.type || edge.relation} — ${Math.round((edge.confidence ?? 0) * 100)}%${edge.count ? ` ×${edge.count}` : ''}`,
      }))
    );

    // Story layout: User on top, Host in middle, File/Device/Email/Network below, Technique at bottom
    // Use hierarchical for incident story, forceAtlas for exploration — toggle via state
    const useHierarchical = true;
    if (networkRef.current) networkRef.current.destroy();
    networkRef.current = new Network(containerRef.current, { nodes, edges }, {
      autoResize: true,
      layout: useHierarchical ? {
        hierarchical: {
          direction: 'UD',
          sortMethod: 'directed',
          levelSeparation: 90,
          nodeSpacing: 140,
          blockShifting: true,
          edgeMinimization: true,
          parentCentralization: true,
        },
      } : undefined,
      physics: useHierarchical ? { enabled: false } : {
        solver: 'forceAtlas2Based',
        forceAtlas2Based: { gravitationalConstant: -80, centralGravity: 0.008, springLength: 140, springConstant: 0.04 },
        stabilization: { iterations: 80 },
      },
      interaction: { hover: true, navigationButtons: true, keyboard: true, tooltipDelay: 200, zoomView: true, dragView: true },
      nodes: {
        borderWidth: 2,
        shadow: { enabled: true, color: 'rgba(0,0,0,0.08)', size: 8 },
        font: { multi: 'html' },
      },
      edges: {
        shadow: { enabled: true, color: 'rgba(0,0,0,0.06)', size: 6 },
        arrows: { to: { enabled: true, scaleFactor: 0.8 } },
        labelHighlightBold: true,
      },
    });

    // Click to dissect: focus on node and filter
    try {
      networkRef.current.on('click', (params) => {
        if (params.nodes.length > 0) {
          const clicked = params.nodes[0];
          // Highlight: dim others, focus
          const allNodes = nodes.get();
          const connectedEdges = edges.get().filter((e) => e.from === clicked || e.to === clicked);
          const connectedIds = new Set([clicked, ...connectedEdges.map((e) => e.from), ...connectedEdges.map((e) => e.to)]);
          // Visual feedback via title
          // Could trigger parent to filter timeline, but keep simple: just focus
          try { networkRef.current.focus(clicked, { scale: 1.1, animation: true }); } catch {}
        }
      });
    } catch {}

    // Fit and focus on entity
    setTimeout(() => {
      try { networkRef.current?.fit({ animation: { duration: 300 } }); } catch {}
    }, 100);

    return () => {
      // cleanup handled on next effect
    };
  }, [displayNodes, displayEdges, status]);

  useEffect(() => {
    return () => {
      if (networkRef.current) { networkRef.current.destroy(); networkRef.current = null; }
    };
  }, []);

  const fit = () => { try { networkRef.current?.fit({ animation: true }); } catch {} };
  const togglePhysics = () => {
    try {
      const opts = networkRef.current?.physics?.options;
      const enabled = opts?.enabled ?? true;
      networkRef.current?.setOptions({ physics: { enabled: !enabled } });
    } catch {}
  };

  return (
    <section aria-label="Entity relationship graph">
      {/* Controls */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 8, fontSize: 12 }}>
        <span style={{ fontWeight: 700, color: '#334155' }}>
          {stats ? `${stats.displayed} of ${stats.original} edges` : ''} {stats?.hidden ? `(${stats.hidden} hidden)` : ''} {groupParallel && stats?.original !== stats?.displayed ? '• grouped' : ''}
        </span>
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          <label style={{ display: 'flex', gap: 4, alignItems: 'center', cursor: 'pointer' }}>
            <input type="checkbox" checked={groupParallel} onChange={(e) => setGroupParallel(e.target.checked)} /> Group parallel
          </label>
          <select value={maxEdges} onChange={(e) => setMaxEdges(Number(e.target.value))} style={{ padding: '4px 8px', borderRadius: 20, border: '1px solid #e2e8f0', background: 'white' }}>
            <option value={15}>Top 15</option>
            <option value={25}>Top 25</option>
            <option value={50}>Top 50</option>
            <option value={100}>Top 100</option>
          </select>
          <select value={minConfidence} onChange={(e) => setMinConfidence(Number(e.target.value))} style={{ padding: '4px 8px', borderRadius: 20, border: '1px solid #e2e8f0', background: 'white' }}>
            <option value={0}>All conf</option>
            <option value={0.5}>≥ 0.5</option>
            <option value={0.7}>≥ 0.7</option>
            <option value={0.85}>≥ 0.85</option>
          </select>
          <button onClick={fit} style={{ padding: '4px 10px', borderRadius: 20, border: '1px solid #e2e8f0', background: 'white', cursor: 'pointer' }}>Fit</button>
          <button onClick={togglePhysics} style={{ padding: '4px 10px', borderRadius: 20, border: '1px solid #e2e8f0', background: 'white', cursor: 'pointer' }}>Toggle physics</button>
        </span>
      </div>

      <div ref={containerRef} style={{ height, border: '1px solid #cbd5e1', borderRadius: 12, background: 'radial-gradient(circle at 30% 20%, #f8fafc, #eef2ff 60%, #f1f5f9)', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.6)' }} />
      {status === 'loading' && <p role="status" style={{ fontSize: 13, color: '#64748b' }}>Loading graph for {entityId}…</p>}
      {status === 'error' && <p role="alert" style={{ color: '#b91c1c', background: '#fef2f2', padding: '8px 10px', borderRadius: 8, border: '1px solid #fecaca' }}>{error}</p>}
      {status === 'ready' && stats?.hidden > 0 && (
        <p style={{ fontSize: 11, color: '#64748b', marginTop: 6 }}>
          Showing top {stats.displayed} most confident edges. {stats.hidden} lower-confidence edges hidden — increase “Top” or lower confidence filter to see more. Parallel edges are grouped (×N) when enabled.
        </p>
      )}
      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginTop: 10, fontSize: 13 }}>
        {Object.entries(COLORS).map(([type, color]) => <span key={type}><i style={{ display: 'inline-block', width: 10, height: 10, borderRadius: '50%', background: color, marginRight: 5 }} />{type}</span>)}
      </div>
    </section>
  );
}
