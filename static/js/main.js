// Speichert offline erstellte Sessions in LocalStorage
function saveOfflineSession(sessionData) {
    let offlineSessions = JSON.parse(localStorage.getItem('offlineSessions')) || [];
    offlineSessions.push(sessionData);
    localStorage.setItem('offlineSessions', JSON.stringify(offlineSessions));
  }
  
  // Synchronisation beim Online-Gehen
  window.addEventListener('online', function() {
    let offlineSessions = JSON.parse(localStorage.getItem('offlineSessions')) || [];
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
  