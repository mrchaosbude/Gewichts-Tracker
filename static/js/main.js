// ============================================================
// Offline-Datenhaltung mit IndexedDB
// ============================================================

var DB_NAME = 'FitnessAppOffline';
var DB_VERSION = 1;
var STORE_SESSIONS = 'offlineSessions';
var STORE_WEIGHTS = 'offlineWeights';

function getRequestHeaders(contentType) {
  var headers = { 'X-Requested-With': 'XMLHttpRequest' };
  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  if (contentType) {
    headers['Content-Type'] = contentType;
  }
  if (csrfMeta && csrfMeta.content) {
    headers['X-CSRFToken'] = csrfMeta.content;
  }
  return headers;
}

window.getRequestHeaders = getRequestHeaders;

// --- UUID-Helper ---
function generateUUID() {
  if (crypto && crypto.randomUUID) return crypto.randomUUID();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    var r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

// --- IndexedDB-Wrapper ---
function openDB() {
  return new Promise(function (resolve, reject) {
    var req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = function (e) {
      var db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_SESSIONS)) {
        db.createObjectStore(STORE_SESSIONS, { keyPath: 'uuid' });
      }
      if (!db.objectStoreNames.contains(STORE_WEIGHTS)) {
        db.createObjectStore(STORE_WEIGHTS, { keyPath: 'uuid' });
      }
    };
    req.onsuccess = function () { resolve(req.result); };
    req.onerror = function () { reject(req.error); };
  });
}

function addEntry(storeName, data) {
  data.uuid = generateUUID();
  return openDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, 'readwrite');
      tx.objectStore(storeName).add(data);
      tx.oncomplete = function () { resolve(data.uuid); };
      tx.onerror = function () { reject(tx.error); };
    });
  });
}

function getAllEntries(storeName) {
  return openDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, 'readonly');
      var req = tx.objectStore(storeName).getAll();
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  });
}

function getEntryCount(storeName) {
  return openDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, 'readonly');
      var req = tx.objectStore(storeName).count();
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  });
}

function deleteEntries(storeName, uuids) {
  return openDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, 'readwrite');
      var store = tx.objectStore(storeName);
      uuids.forEach(function (uuid) { store.delete(uuid); });
      tx.oncomplete = function () { resolve(); };
      tx.onerror = function () { reject(tx.error); };
    });
  });
}

function clearStore(storeName) {
  return openDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, 'readwrite');
      tx.objectStore(storeName).clear();
      tx.oncomplete = function () { resolve(); };
      tx.onerror = function () { reject(tx.error); };
    });
  });
}

// --- Migration von localStorage → IndexedDB ---
function migrateFromLocalStorage() {
  var raw = localStorage.getItem('offlineSessions');
  if (!raw) return Promise.resolve();
  try {
    var sessions = JSON.parse(raw);
    if (!Array.isArray(sessions) || sessions.length === 0) {
      localStorage.removeItem('offlineSessions');
      return Promise.resolve();
    }
    return openDB().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE_SESSIONS, 'readwrite');
        var store = tx.objectStore(STORE_SESSIONS);
        sessions.forEach(function (s) {
          s.uuid = s.uuid || generateUUID();
          store.put(s);
        });
        tx.oncomplete = function () {
          localStorage.removeItem('offlineSessions');
          resolve();
        };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  } catch (e) {
    localStorage.removeItem('offlineSessions');
    return Promise.resolve();
  }
}

// ============================================================
// Öffentliche API: Speichern
// ============================================================

function saveOfflineSession(sessionData) {
  var data = Object.assign({}, sessionData);
  if (data.notes === undefined) data.notes = null;
  if (data.perceived_exertion === undefined) data.perceived_exertion = null;
  return addEntry(STORE_SESSIONS, data).then(function () {
    updateOfflineBadge();
    requestBackgroundSync('sync-sessions');
  });
}

function saveOfflineWeight(weightData) {
  var data = Object.assign({}, weightData);
  if (data.notes === undefined) data.notes = null;
  return addEntry(STORE_WEIGHTS, data).then(function () {
    updateOfflineBadge();
    requestBackgroundSync('sync-weights');
  });
}

// ============================================================
// Badge-Anzeige
// ============================================================

function updateOfflineBadge() {
  Promise.all([
    getEntryCount(STORE_SESSIONS),
    getEntryCount(STORE_WEIGHTS)
  ]).then(function (counts) {
    var total = counts[0] + counts[1];
    var badge = document.getElementById('offline-sync-badge');

    if (total > 0) {
      if (!badge) {
        badge = document.createElement('div');
        badge.id = 'offline-sync-badge';
        badge.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#ffc107;color:#000;padding:10px 15px;border-radius:8px;font-weight:bold;z-index:9999;box-shadow:0 2px 10px rgba(0,0,0,0.2);cursor:pointer;';
        badge.onclick = function () { syncAll(); };
        document.body.appendChild(badge);
      }
      var label = total === 1 ? '1 Eintrag offline gespeichert' : total + ' Einträge offline gespeichert';
      badge.textContent = label;
      badge.title = 'Klicken zum Synchronisieren';
      badge.style.background = '#ffc107';
    } else if (badge) {
      badge.remove();
    }
  });
}

// ============================================================
// Sync-Logik
// ============================================================

function syncOfflineSessions() {
  return getAllEntries(STORE_SESSIONS).then(function (entries) {
    if (entries.length === 0) return;
    return fetch('/sync', {
      method: 'POST',
      headers: getRequestHeaders('application/json'),
      body: JSON.stringify({ sessions: entries })
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (data.status === 'success') {
        var uuids = data.synced_uuids || entries.map(function (e) { return e.uuid; });
        return deleteEntries(STORE_SESSIONS, uuids).then(function () {
          return entries.length;
        });
      } else {
        throw new Error(data.message || 'Sync fehlgeschlagen');
      }
    });
  });
}

function syncOfflineWeights() {
  return getAllEntries(STORE_WEIGHTS).then(function (entries) {
    if (entries.length === 0) return;
    return fetch('/sync_weights', {
      method: 'POST',
      headers: getRequestHeaders('application/json'),
      body: JSON.stringify({ weights: entries })
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (data.status === 'success') {
        var uuids = data.synced_uuids || entries.map(function (e) { return e.uuid; });
        return deleteEntries(STORE_WEIGHTS, uuids).then(function () {
          return entries.length;
        });
      } else {
        throw new Error(data.message || 'Sync fehlgeschlagen');
      }
    });
  });
}

function syncAll() {
  if (!navigator.onLine) return;

  var badge = document.getElementById('offline-sync-badge');
  if (badge) {
    badge.textContent = 'Synchronisiere...';
    badge.style.background = '#17a2b8';
  }

  Promise.all([
    syncOfflineSessions().catch(function (e) { return { error: e }; }),
    syncOfflineWeights().catch(function (e) { return { error: e }; })
  ]).then(function (results) {
    var totalSynced = 0;
    var hasError = false;
    results.forEach(function (r) {
      if (r && r.error) { hasError = true; }
      else if (typeof r === 'number') { totalSynced += r; }
    });

    updateOfflineBadge();

    if (totalSynced > 0) {
      var label = totalSynced === 1 ? '1 Eintrag' : totalSynced + ' Einträge';
      showSyncToast('success', label + ' erfolgreich synchronisiert!');
    }
    if (hasError) {
      showSyncToast('error', 'Einige Einträge konnten nicht synchronisiert werden');
      scheduleRetry();
    }
  });
}

// ============================================================
// Background Sync Registration
// ============================================================

function requestBackgroundSync(tag) {
  if ('serviceWorker' in navigator && 'SyncManager' in window) {
    navigator.serviceWorker.ready.then(function (reg) {
      return reg.sync.register(tag);
    }).catch(function (err) {
      console.warn('Background Sync Registration fehlgeschlagen:', err);
    });
  }
}

// ============================================================
// Toast + Retry
// ============================================================

function showSyncToast(type, message) {
  var toast = document.createElement('div');
  toast.style.cssText = 'position:fixed;top:20px;right:20px;padding:15px 20px;border-radius:8px;z-index:10000;box-shadow:0 2px 10px rgba(0,0,0,0.2);transition:opacity 0.3s;color:#fff;';
  toast.style.background = type === 'success' ? '#28a745' : '#dc3545';
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(function () {
    toast.style.opacity = '0';
    setTimeout(function () { toast.remove(); }, 300);
  }, 4000);
}

var retryTimeout = null;
function scheduleRetry() {
  if (retryTimeout) clearTimeout(retryTimeout);
  retryTimeout = setTimeout(function () {
    if (navigator.onLine) syncAll();
  }, 30000);
}

// ============================================================
// Event-Listener
// ============================================================

window.addEventListener('online', function () {
  syncAll();
});

document.addEventListener('DOMContentLoaded', function () {
  migrateFromLocalStorage().then(function () {
    updateOfflineBadge();
    setTimeout(function () {
      if (navigator.onLine) syncAll();
    }, 1000);
  });
});

setInterval(function () {
  if (navigator.onLine) {
    Promise.all([
      getEntryCount(STORE_SESSIONS),
      getEntryCount(STORE_WEIGHTS)
    ]).then(function (counts) {
      if (counts[0] + counts[1] > 0) syncAll();
    });
  }
}, 60000);
