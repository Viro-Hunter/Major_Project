import React, { useEffect, useRef, useState } from 'react';
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
        const nodes = new DataSet((graph.nodes || []).map((node) => ({
          ...node,
          label: node.label || node.name || node.id,
          title: `${node.type || 'Entity'}: ${node.id}`,
          color: COLORS[node.type] || '#64748b',
          shape: node.type === 'AttackTechnique' ? 'star' : 'dot',
          size: node.id === entityId ? 28 : 18,
        })));
        const edges = new DataSet((graph.links || graph.edges || []).map((edge, index) => ({
          ...edge,
          id: edge.id || `${edge.from}-${edge.to}-${edge.key || index}`,
          from: edge.from || edge.source,
          to: edge.to || edge.target,
          arrows: 'to',
          label: edge.type || edge.relation_type || '',
          font: { align: 'middle', size: 10 },
        })));
        if (networkRef.current) networkRef.current.destroy();
        networkRef.current = new Network(containerRef.current, { nodes, edges }, {
          autoResize: true,
          physics: { stabilization: { iterations: 150 }, barnesHut: { gravitationalConstant: -3500 } },
          interaction: { hover: true, navigationButtons: true, keyboard: true },
          nodes: { borderWidth: 2, font: { color: '#0f172a', size: 13 } },
          edges: { color: '#94a3b8', smooth: { type: 'dynamic' } },
        });
        setStatus('ready');
      } catch (requestError) {
        if (!cancelled) { setError(requestError.message); setStatus('error'); }
      }
    }
    loadGraph();
    return () => { cancelled = true; if (networkRef.current) networkRef.current.destroy(); };
  }, [apiBaseUrl, entityId, hops]);

  return (
    <section aria-label="Entity relationship graph">
      <div ref={containerRef} style={{ height, border: '1px solid #cbd5e1', borderRadius: 10, background: '#f8fafc' }} />
      {status === 'loading' && <p role="status">Loading graph…</p>}
      {status === 'error' && <p role="alert" style={{ color: '#b91c1c' }}>{error}</p>}
      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginTop: 10, fontSize: 13 }}>
        {Object.entries(COLORS).map(([type, color]) => <span key={type}><i style={{ display: 'inline-block', width: 10, height: 10, borderRadius: '50%', background: color, marginRight: 5 }} />{type}</span>)}
      </div>
    </section>
  );
}
