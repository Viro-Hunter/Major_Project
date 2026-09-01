<<<<<<< HEAD
import React, { useState } from 'react';
import EntityGraph from './EntityGraph';

const DashboardPage = () => {
  const [entityId, setEntityId] = useState('AAM0658');
  const [hops, setHops] = useState(2);

  return (
    <main style={{ maxWidth: 1180, margin: '0 auto', padding: '2rem', fontFamily: 'sans-serif', color: '#0f172a' }}>
      <h1>Cyber Intelligence GraphRAG Dashboard</h1>
      <p>Explore users, hosts, events, and ATT&amp;CK techniques connected in the CERT graph.</p>
      <div style={{ display: 'flex', gap: 12, alignItems: 'end', flexWrap: 'wrap', margin: '1.5rem 0' }}>
        <label>Entity ID<br /><input value={entityId} onChange={(event) => setEntityId(event.target.value)} style={{ padding: 8, minWidth: 220 }} /></label>
        <label>Hops<br /><select value={hops} onChange={(event) => setHops(Number(event.target.value))} style={{ padding: 8 }}><option value={1}>1</option><option value={2}>2</option><option value={3}>3</option></select></label>
      </div>
      <EntityGraph entityId={entityId} hops={hops} />
    </main>
  );
};

export default DashboardPage;
=======
import React from 'react';

const DashboardPage = () => {
  return (
    <div style={{ padding: '2rem', fontFamily: 'sans-serif' }}>
      <h1>Cyber Intelligence GraphRAG Dashboard</h1>
      <p>This is a placeholder page for the GraphRAG-based insider threat detection system.</p>
      <p>The dashboard will provide real-time visualization of threat graphs, incident queues, and analytics.</p>
    </div>
  );
};

export default DashboardPage;
>>>>>>> b41879e3bad66a46af7fd56c38399276053be697
