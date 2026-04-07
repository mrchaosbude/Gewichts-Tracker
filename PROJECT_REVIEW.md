# Projekt-Review: Gewichts-Tracker

Erstellt: 2026-03-31

---

## KRITISCH

| # | Problem | Stelle |
|---|---------|--------|
| 1 | **Hartcodierter SECRET_KEY** `'dein_geheimer_schluessel'` — erlaubt Session-Forgery, CSRF-Bypass, Admin-Impersonation | app.py:38 |
| 2 | **`debug=True` hardcoded** — aktiviert Werkzeug-Debugger (Remote Code Execution bei offentlichem Server) | app.py:3140 |
| 3 | **API `/api/register` umgeht Sicherheit** — keine Passwort-Mindestlange, keine E-Mail-Verifizierung, erster User wird automatisch Admin | app.py:2787 |
| 4 | **SMTP-Passwort im Klartext** in der DB gespeichert | app.py:194 |
| 5 | **Fehlender CSRF-Schutz** auf Foto-Upload, Kalender-Planung, Template-Liste | progress_photos.html:54, training_calendar.html:245 |
| 6 | **Flash-Messages werden nie angezeigt** — `base.html` hat kein `get_flashed_messages()`-Block. Alle ~30+ `flash()`-Aufrufe verpuffen | base.html |
| 7 | **`bleach` ist deprecated** (seit Jan 2023) — sollte durch `nh3` ersetzt werden | requirements.txt |

---

## WICHTIG

### Sicherheit
| # | Problem | Stelle |
|---|---------|--------|
| 8 | `admin_required`/`trainer_or_admin_required` prufen nicht `is_authenticated` — ohne `@login_required` kein Schutz | app.py:345-361 |
| 9 | Logout uber GET — CSRF-Zwangs-Logout moglich (`<img src="/logout">`) | app.py:1031 |
| 10 | E-Mail-Bestatigungstoken hat kein Ablaufdatum | app.py:1039 |
| 11 | Kein Rate-Limiting auf `/login`, `/register`, `/api/login`, `/api/register` | app.py |
| 12 | Service Worker cached authentifizierte Seiten — nach Logout konnte ein anderer Nutzer gecachte Inhalte sehen | sw.js:39 |

### Performance / Datenbank
| # | Problem | Stelle |
|---|---------|--------|
| 13 | **Fehlende DB-Indizes** auf `ExerciseSession.user_id`, `.timestamp`, `Exercise.user_id`, `BodyWeight.user_id` | app.py:116-140 |
| 14 | **N+1 Queries** in `/statistics` — fur jede Session wird `s.exercise` lazy geladen (potentiell hunderte Queries) | app.py:1148-1154 |
| 15 | **N+1 Queries** in `training_plan_detail` — Sessions pro Ubung werden einzeln geladen und in Python gefiltert | app.py:1713 |
| 16 | Streak/Deload-Berechnung: bis zu **64 separate DB-Queries pro Dashboard-Aufruf** | app.py:718-733, app.py:1096-1108 |
| 17 | `cleanup_unverified_accounts` lauft bei **jedem Request** (mit interner Stunden-Sperre, aber trotzdem DB-Zugriff) | app.py:289 |

### Datenintegritat
| # | Problem | Stelle |
|---|---------|--------|
| 18 | `ExerciseSession.weight` ist `Integer` — Dezimalgewichte (42.5 kg) nicht moglich, obwohl 2.5er-Progression vorgeschlagen wird | app.py:132 |
| 19 | `BodyWeightForm.weight` ist `IntegerField` mit `step="0.1"` — Dezimalwerte gehen verloren, DB-Feld ist `Float` | app.py:524 |
| 20 | `copy_shared_plan` kopiert `exercise_type` nicht — Ausdauer-Ubungen werden als Kraft kopiert | app.py:1878 |
| 21 | `_moving_average` / `average_weight` / `max_weight` crashen bei `None`-Werten (Cardio-Sessions) | app.py:798-821 |
| 22 | Export fehlen Cardio-Felder (`duration_minutes`, `distance_km`, `warmup_*`) | app.py:3064-3096 |

### Tests
| # | Problem | Stelle |
|---|---------|--------|
| 23 | **~95% der Routes sind ungetestet** — Auth, Dashboard, Stats, Achievements, Calendar, Photos, CRUD, Admin, API | tests/ |
| 24 | `test_import_creates_plan_and_exercises` testet mit regularem User gegen `@trainer_or_admin_required` — bekommt 403 | test_markdown_import.py:279 |
| 25 | Keine `requirements.txt`-Versionierung — Builds nicht reproduzierbar | requirements.txt |

### Migrationen
| # | Problem | Stelle |
|---|---------|--------|
| 26 | `migrate_add_session_notes_rpe.py` und `migrate_to_global_exercises.py` haben hardcoded `DB_PATH = 'fitness.db'` — matcht nicht mit Flask's `instance/`-Ordner | migrate-Dateien |
| 27 | Keine Migration ist reversibel, kein Versions-Tracking | alle migrate*.py |
| 28 | `migrate.py` Dry-Run rollt DDL-Anderungen **nicht** zuruck (nur ORM-Backfill) | migrate.py:171 |

---

## GERING

### Code-Qualitat
| # | Problem | Stelle |
|---|---------|--------|
| 29 | **3141 Zeilen in einer Datei** — Modelle, Forms, Routes, API, Admin alles monolithisch | app.py |
| 30 | `serialize_session` doppelt definiert — lokale Version (vollstandig) vs. globale (ohne Cardio-Felder) | app.py:2118, app.py:2977 |
| 31 | SMTP-Verbindungslogik 3x dupliziert | app.py:247, app.py:2341, app.py:2375 |
| 32 | `User.query.get()` deprecated in SQLAlchemy 2.0 | app.py:340 |
| 33 | Alle Timestamps ohne Timezone (lokale Zeit statt UTC) | app.py:82,133,177 |

### Frontend
| # | Problem | Stelle |
|---|---------|--------|
| 34 | Dashboard `.nav-icon` inline-Farben haben keine Dark-Mode-Overrides | dashboard.html:306-332 |
| 35 | Formular-Validierungsfehler werden auf fast keinem Formular angezeigt (nur `add_session.html` zeigt sie) | diverse Templates |
| 36 | Kalender: `onclick`-Divs ohne Keyboard-Support (`tabindex`, `onkeydown`) | training_calendar.html |
| 37 | Massive Nutzung von Inline-Styles statt CSS-Klassen — erschwert Dark-Mode und Wartung | diverse Templates |
| 38 | Dark-Mode-Toggle ist `<span>` statt `<button>` — nicht per Tastatur/Screenreader bedienbar | base.html:292 |

### Sonstiges
| # | Problem | Stelle |
|---|---------|--------|
| 39 | Tote Templates: `templates_list.html`, `edit_template.html` (referenzieren nicht-existente Routes) | templates/ |
| 40 | Root `index.html` ist ein Kase-Mischung-Rechner aus einem anderen Projekt | index.html |
| 41 | Service Worker pre-cached `/fit` — Route existiert nicht | sw.js:5 |
| 42 | `Textdokument (neu).txt` im Root | Projektroot |
| 43 | Keine `conftest.py` — Test-Fixtures 3x dupliziert | tests/ |

---

## Zusammenfassung

| Schweregrad | Anzahl |
|-------------|--------|
| Kritisch | 7 |
| Wichtig | 20 |
| Gering | 15 |
| **Gesamt** | **42** |

## Top 5 Sofort-Massnahmen

1. `SECRET_KEY` aus Environment-Variable laden, `debug=False` fur Produktion
2. Flash-Messages in `base.html` rendern (`get_flashed_messages()`)
3. CSRF-Tokens auf alle Formulare
4. DB-Indizes auf `ExerciseSession.user_id`, `.timestamp`, `Exercise.user_id`
5. `weight`-Felder auf `Float` umstellen (Session + Formular)
