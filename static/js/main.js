// Speichert offline erstellte Sessions in LocalStorage
function saveOfflineSession(sessionData) {
    let offlineSessions = JSON.parse(localStorage.getItem('offlineSessions')) || [];
    const normalizedSession = { ...sessionData };
    if (normalizedSession.notes === undefined) {
      normalizedSession.notes = null;
    }
    if (normalizedSession.perceived_exertion === undefined) {
      normalizedSession.perceived_exertion = null;
    }
    offlineSessions.push(normalizedSession);
    localStorage.setItem('offlineSessions', JSON.stringify(offlineSessions));
  }
  
  // Synchronisation beim Online-Gehen
  window.addEventListener('online', function() {
    let offlineSessions = JSON.parse(localStorage.getItem('offlineSessions')) || [];
    offlineSessions = offlineSessions.map(session => ({
      ...session,
      notes: session.notes ?? null,
      perceived_exertion: session.perceived_exertion ?? null,
    }));
    if (offlineSessions.length > 0) {
      fetch('/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessions: offlineSessions })
      })
      .then(response => response.json())
      .then(data => {
        if (data.status === 'success') {
          localStorage.removeItem('offlineSessions');
        }
      })
      .catch(err => console.error('Sync failed', err));
    }
  });
