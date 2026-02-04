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
  updateOfflineBadge();
}

// Anzahl der ausstehenden Offline-Sessions abrufen
function getOfflineSessionCount() {
  const offlineSessions = JSON.parse(localStorage.getItem('offlineSessions')) || [];
  return offlineSessions.length;
}

// Badge aktualisieren, um ausstehende Sync-Sessions anzuzeigen
function updateOfflineBadge() {
  const count = getOfflineSessionCount();
  let badge = document.getElementById('offline-sync-badge');

  if (count > 0) {
    if (!badge) {
      badge = document.createElement('div');
      badge.id = 'offline-sync-badge';
      badge.style.cssText = 'position: fixed; bottom: 20px; right: 20px; background: #ffc107; color: #000; padding: 10px 15px; border-radius: 8px; font-weight: bold; z-index: 9999; box-shadow: 0 2px 10px rgba(0,0,0,0.2); cursor: pointer;';
      badge.onclick = function() { syncOfflineSessions(); };
      document.body.appendChild(badge);
    }
    badge.textContent = count + ' Session' + (count > 1 ? 's' : '') + ' offline gespeichert';
    badge.title = 'Klicken zum Synchronisieren';
  } else if (badge) {
    badge.remove();
  }
}

// Synchronisation der Offline-Sessions
function syncOfflineSessions() {
  if (!navigator.onLine) {
    console.log('Sync übersprungen - keine Verbindung');
    return;
  }

  let offlineSessions = JSON.parse(localStorage.getItem('offlineSessions')) || [];
  if (offlineSessions.length === 0) {
    return;
  }

  // Sessions normalisieren
  offlineSessions = offlineSessions.map(session => ({
    ...session,
    notes: session.notes ?? null,
    perceived_exertion: session.perceived_exertion ?? null,
  }));

  // Badge auf "Syncing..." setzen
  const badge = document.getElementById('offline-sync-badge');
  if (badge) {
    badge.textContent = 'Synchronisiere...';
    badge.style.background = '#17a2b8';
  }

  fetch('/sync', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessions: offlineSessions })
  })
  .then(response => response.json())
  .then(data => {
    if (data.status === 'success') {
      localStorage.removeItem('offlineSessions');
      updateOfflineBadge();
      // Erfolgs-Toast anzeigen
      showSyncToast('success', offlineSessions.length + ' Session' + (offlineSessions.length > 1 ? 's' : '') + ' erfolgreich synchronisiert!');
    } else {
      // Fehler-Toast anzeigen
      showSyncToast('error', 'Sync fehlgeschlagen: ' + (data.message || 'Unbekannter Fehler'));
      updateOfflineBadge();
      // Retry nach 30 Sekunden planen
      scheduleRetry();
    }
  })
  .catch(err => {
    console.error('Sync failed', err);
    showSyncToast('error', 'Sync fehlgeschlagen - wird später erneut versucht');
    updateOfflineBadge();
    // Retry nach 30 Sekunden planen
    scheduleRetry();
  });
}

// Toast-Nachricht anzeigen
function showSyncToast(type, message) {
  const toast = document.createElement('div');
  toast.style.cssText = 'position: fixed; top: 20px; right: 20px; padding: 15px 20px; border-radius: 8px; z-index: 10000; box-shadow: 0 2px 10px rgba(0,0,0,0.2); transition: opacity 0.3s;';
  toast.style.background = type === 'success' ? '#28a745' : '#dc3545';
  toast.style.color = '#fff';
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Retry-Timer für fehlgeschlagene Syncs
let retryTimeout = null;
function scheduleRetry() {
  if (retryTimeout) {
    clearTimeout(retryTimeout);
  }
  retryTimeout = setTimeout(() => {
    if (navigator.onLine && getOfflineSessionCount() > 0) {
      console.log('Retry-Versuch für Offline-Sync...');
      syncOfflineSessions();
    }
  }, 30000); // 30 Sekunden warten
}

// Synchronisation beim Online-Gehen
window.addEventListener('online', function() {
  console.log('Online-Event erkannt - starte Sync');
  syncOfflineSessions();
});

// Sync beim Seiten-Load (falls bereits online und Sessions vorhanden)
document.addEventListener('DOMContentLoaded', function() {
  updateOfflineBadge();
  // Kurze Verzögerung, damit die Seite vollständig geladen ist
  setTimeout(function() {
    if (navigator.onLine && getOfflineSessionCount() > 0) {
      console.log('Seite geladen mit ausstehenden Offline-Sessions - starte Sync');
      syncOfflineSessions();
    }
  }, 1000);
});

// Periodischer Check alle 60 Sekunden (für den Fall, dass online-Event nicht feuert)
setInterval(function() {
  if (navigator.onLine && getOfflineSessionCount() > 0) {
    console.log('Periodischer Check - starte Sync');
    syncOfflineSessions();
  }
}, 60000);
