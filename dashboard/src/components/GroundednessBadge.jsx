import React, { useState } from 'react';

const STYLES = {
  grounded: { bg: '#e6f4ea', fg: '#137333', label: 'Grounded' },
  regenerated: { bg: '#fef7e0', fg: '#b06000', label: 'Grounded after retry' },
  unverified: { bg: '#fce8e6', fg: '#c5221f', label: 'Unverified' },
};

export default function GroundednessBadge({ verdict }) {
  const [open, setOpen] = useState(false);
  const g = verdict?.groundedness;
  if (!g) return null;

  const s = STYLES[g.status] || STYLES.grounded;
  const cited = verdict.cited_edges || [];
  const verified = g.verified_edges || [];
  const missing = g.missing_edges || [];

  return (
    <div style={{ margin: '8px 0' }}>
      <span
        onClick={() => setOpen(!open)}
        style={{
          background: s.bg,
          color: s.fg,
          padding: '4px 10px',
          borderRadius: 12,
          fontSize: 13,
          fontWeight: 600,
          cursor: 'pointer',
        }}
        title="Click for details"
      >
        {g.status === 'unverified' ? '⚠ ' : '✓ '}
        {s.label}
      </span>

      {g.status === 'unverified' && (
        <div style={{ color: s.fg, fontSize: 13, marginTop: 6 }}>
          Some cited evidence could not be found in the graph. The risk score was reduced by 20% and this case
          should be reviewed by an analyst.
        </div>
      )}

      {open && (
        <div style={{ fontSize: 13, marginTop: 8, lineHeight: 1.6 }}>
          <div>Retries used: {g.retries_used} / 2</div>
          <div>
            Cited edges: {cited.length} ({verified.length} verified)
          </div>
          {missing.length > 0 && <div style={{ color: '#c5221f' }}>Missing edges: {missing.join(', ')}</div>}
        </div>
      )}
    </div>
  );
}
