import React, { useEffect, useState } from 'react';
import DashboardPage from './components/DashboardPage';
import StoryMode from './components/StoryMode';

// #story -> presenter walkthrough for non-technical audiences; anything else -> analyst dashboard
function App() {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const onChange = () => setHash(window.location.hash);
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return window.__STORY_DATA__ || hash.startsWith('#story') ? <StoryMode /> : <DashboardPage />;
}

export default App;
