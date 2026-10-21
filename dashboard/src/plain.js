// Plain-language vocabulary shared by the dashboard. Technical names stay available
// (shown when "Technical details" is on), but nothing on the default view needs them.

export const TECHNIQUES = {
  T1078: { plain: 'Logged in outside working hours', name: 'Valid Accounts' },
  T1052: { plain: 'Plugged in a USB storage device', name: 'Exfiltration Over Physical Medium' },
  T1005: { plain: 'Opened files they had never touched before', name: 'Data from Local System' },
  T1567: { plain: 'Emailed attachments outside the company', name: 'Exfiltration Over Web Service' },
  T1048: { plain: 'Emailed many outside addresses at once', name: 'Exfiltration Over Alternative Protocol' },
  T1030: { plain: 'Moved an unusually large amount of data', name: 'Data Transfer Size Limits' },
  T1071: { plain: 'Used an upload or file-sharing website', name: 'Application Layer Protocol' },
  T1213: { plain: 'Pulled documents from shared repositories', name: 'Data from Information Repositories' },
  T1056: { plain: "Captured other people's keystrokes", name: 'Input Capture' },
};
export const techId = (nodeId) => String(nodeId || '').replace(/^attack:/, '');
export const techPlain = (id) => TECHNIQUES[techId(id)]?.plain || techId(id);

export const RELATIONS = {
  OBSERVED_ON: 'used computer', ACCESSED: 'opened', CONNECTED_DEVICE: 'plugged in', SENT_EMAIL_TO: 'sent',
  BROWSED: 'visited', MATCHES_TECHNIQUE: 'matches the behaviour', INDICATES: 'is a sign of',
  LOCATED_ON: 'is stored on', CONNECTED_TO: 'was attached to', SENT_FROM: 'was sent from', FROM_HOST: 'was opened on',
  LOGGED_IN_FROM: 'logged in from',
};
export const relPlain = (r) => RELATIONS[r] || String(r || '').toLowerCase().replace(/_/g, ' ');

export const VERDICT = {
  high_risk: { text: 'High risk', bg: '#fee2e2', fg: '#991b1b', bar: '#dc2626' },
  suspicious: { text: 'Needs review', bg: '#ffedd5', fg: '#9a3412', bar: '#ea580c' },
  benign: { text: 'Looks normal', bg: '#dcfce7', fg: '#166534', bar: '#16a34a' },
};
export const verdictFor = (label) => VERDICT[label] || VERDICT.benign;

export const RECOMMENDATION = {
  auto: 'Strong, verified evidence: escalate to the security team now.',
  analyst: 'A person should review this activity before anything else happens.',
  ignore: 'No action needed. The activity looks like normal work.',
};

export function nodeKind(n) {
  const t = n?.type || '';
  return { User: 'person', Host: 'computer', Device: 'usb', FileResource: 'file', EmailEvent: 'email',
           NetworkConnection: 'web', AttackTechnique: 'behaviour' }[t] || 'other';
}

export function nodeLabel(n, technical = false) {
  if (!n) return '';
  if (technical) return n.id;
  const raw = String(n.id || '').split(':').slice(1).join(':').replace(/[{}]/g, '');
  const a = n.attributes || {};
  switch (n.type) {
    case 'User': return n.id;
    case 'Host': return `Computer ${raw}`;
    case 'Device': return 'USB drive';
    case 'FileResource': return `File ${raw.length > 18 ? raw.slice(0, 16) + '…' : raw}`;
    case 'EmailEvent': {
      const to = String(a.to || '').split(';').filter((x) => x.includes('@'));
      const outside = to.filter((x) => !x.toLowerCase().endsWith('dtaa.com')).length;
      return outside ? `Email to ${outside} outside address${outside > 1 ? 'es' : ''}` : 'Internal email';
    }
    case 'NetworkConnection': {
      const url = a.url || raw;
      const host = url.includes('://') ? url.split('/')[2] : url.split('/')[0];
      return `Website ${host.replace(/^www\./, '').slice(0, 24)}`;
    }
    case 'AttackTechnique': return techPlain(n.id);
    default: return raw || n.id;
  }
}

export const KIND_STYLE = {
  person: { color: '#2563eb', glyph: '👤' }, computer: { color: '#64748b', glyph: '🖥' },
  usb: { color: '#7c3aed', glyph: '🔌' }, file: { color: '#d97706', glyph: '📄' },
  email: { color: '#0891b2', glyph: '✉' }, web: { color: '#15803d', glyph: '🌐' },
  behaviour: { color: '#dc2626', glyph: '⚑' }, other: { color: '#94a3b8', glyph: '•' }, more: { color: '#cbd5e1', glyph: '+' },
};

export function fmtWhen(iso, withDate = true) {
  if (!iso) return '';
  const d = new Date(String(iso).replace(' ', 'T'));
  if (Number.isNaN(d.getTime())) return String(iso);
  const t = d.toLocaleTimeString('en-GB', { hour: 'numeric', minute: '2-digit', hour12: true });
  // weekday shown so weekend activity ("outside working hours" at 9 AM on a Saturday) is self-explanatory
  return withDate ? `${d.toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' })}, ${t}` : t;
}
export const isNight = (iso) => { const h = new Date(String(iso).replace(' ', 'T')).getHours(); return h >= 20 || h < 6; };

export const edgeIds = (sg) => (sg?.edges || []).map((e, i) => String(e.id ?? e.edge_id ?? `e${i}`));
