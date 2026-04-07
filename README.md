# Fitness App – Offline nutzbar mit Templates, Rollen und Beschreibungen

Dies ist ein **komplettes** Flask‑Projekt zum Verwalten von Trainingsplänen, Übungen, Sessions und Vorlagen („Templates“). Die Anwendung ist als Progressive Web App (PWA) konzipiert und kann auch **offline** genutzt werden. Darüber hinaus bietet sie Rollenverwaltung (Admin, Trainer, Standardbenutzer), die Möglichkeit, **Sichtbarkeit** für Vorlagen zu steuern und **Beschreibungen** bei Übungen hinzuzufügen.

## Funktionen

1. **User-Management**  
   - Registrierung (mit optionalem reCAPTCHA)  
   - Erster registrierter Benutzer wird automatisch Admin  
   - Login & Logout (Optionales „Angemeldet bleiben“ via Cookies)  
   - Admin kann andere Benutzer löschen oder deren Passwörter ändern  
   - Admin kann anderen Benutzern den Trainer‑Rang geben oder entziehen

2. **Trainingspläne & Übungen**  
   - Jeder Benutzer kann eigene Trainingspläne erstellen  
   - Zu jedem Plan lassen sich Übungen (mit **Name** und **Beschreibung**) hinzufügen  
   - Für jede Übung können **Sessions** (Sätze) mit Gewicht und Wiederholungen erfasst werden  
   - Übersicht des Verlaufs in Tabellenform & **interaktiver Chart** (Chart.js)  
   - Löschen von Trainingsplänen, Übungen und Sessions

3. **Vorlagen (Template Trainingspläne)**  
   - Admins und Trainer können Template Trainingspläne (mit Übungen + Beschreibung) anlegen, editieren, löschen  
   - Template-Übungen unterstützen ebenfalls eine **Beschreibung**  
   - Sichtbarkeit der Vorlagen steuerbar (`is_visible`)  
   - Alle Benutzer (auch Standardnutzer) können sich **sichtbare** Vorlagen anschauen und diese in ihren Account übernehmen (Übungen werden kopiert)

4. **Offline-Funktionalität (PWA)**  
   - Service Worker (sw.js) und Manifest (manifest.json) ermöglichen das Caching statischer Ressourcen  
   - Offline erstellte Daten (Sessions) können lokal gespeichert und bei Online‑Wiederkehr synchronisiert werden

5. **Rollen**
   - **Admin**: uneingeschränkte Rechte (Benutzerverwaltung, Trainer‑Rang setzen/entziehen, Templates erstellen, Sichtbarkeit umschalten …)
   - **Trainer**: ähnliche Rechte wie Admin für Templates (Erstellen, Editieren, Löschen, Sichtbarkeit …)
   - **Standardbenutzer**: kann eigene Pläne verwalten und Vorlagen übernehmen, sieht jedoch nur sichtbare Vorlagen

## Konfiguration

Die App wird über Umgebungsvariablen konfiguriert:

| Variable | Beschreibung | Pflicht? |
|----------|-------------|----------|
| `SECRET_KEY` | Geheimer Schlüssel für Sessions, CSRF und SMTP-Passwort-Verschlüsselung | **Ja** |
| `FLASK_DEBUG` | Debug-Modus aktivieren (`true`/`false`, Standard: `false`) | Nein |
| `GEWICHTS_TRACKER_DATABASE_URI` | Datenbank-URI (Standard: `sqlite:///fitness.db`) | Nein |

### SECRET_KEY setzen

Der `SECRET_KEY` **muss** gesetzt werden, bevor die App gestartet wird. Ohne gesetzte Variable wird bei jedem Neustart ein zufälliger Key generiert — das invalidiert alle bestehenden Sessions und verschlüsselten SMTP-Passwörter.

**Linux/macOS:**
```bash
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

**Windows (PowerShell):**
```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
python app.py
```

**Windows (CMD):**
```cmd
for /f %i in ('python -c "import secrets; print(secrets.token_hex(32))"') do set SECRET_KEY=%i
python app.py
```

Für Produktion sollte der Key einmalig generiert und dauerhaft gespeichert werden (z.B. in einer `.env`-Datei oder im Hosting-Provider).

## REST API

Alle Endpunkte befinden sich unter dem Präfix `/api` und geben JSON zurück.
Authentifizierung erfolgt über Session-Cookies (`POST /api/login`).

### Auth

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `POST` | `/api/register` | Registrieren (JSON: `username`, `password` min. 8 Zeichen) |
| `POST` | `/api/login` | Anmelden (JSON: `username`, `password`) |
| `POST` | `/api/logout` | Abmelden |

### Dashboard & Statistiken

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/api/dashboard` | Wochen-Stats, Streak, Deload-Warnung, geplante Trainings |
| `GET` | `/api/statistics` | Kraft- & Cardio-Statistiken, Wochenvergleich, Muskelgruppen-Volumen, Frequenz (12 Wochen) |
| `GET` | `/api/achievements` | Freigeschaltete & gesperrte Achievements |

### Trainingspläne

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/api/training_plans` | Alle eigenen Pläne auflisten |
| `POST` | `/api/training_plans` | Neuen Plan erstellen (JSON: `title`, `description`) |
| `GET` | `/api/training_plans/<id>/detail` | Plan-Details mit Übungen, Positionen, Superset-Gruppen |
| `PUT` | `/api/training_plans/<id>` | Plan aktualisieren (JSON: `title`, `description`) |
| `DELETE` | `/api/training_plans/<id>` | Plan löschen |
| `POST` | `/api/training_plans/<id>/set_superset` | Superset-Gruppe setzen (JSON: `exercise_id`, `superset_group`) |
| `POST` | `/api/training_plans/<id>/reorder` | Übung verschieben (JSON: `exercise_id`, `direction`: `up`/`down`) |

### Übungen

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/api/training_plans/<id>/exercises` | Übungen eines Plans auflisten |
| `POST` | `/api/training_plans/<id>/exercises` | Übung hinzufügen (JSON: `name`, `description`) |
| `PUT` | `/api/exercises/<id>` | Übung bearbeiten (JSON: `name`, `description`, `muscle_group`) |
| `DELETE` | `/api/exercises/<id>` | Übung aus Plan entfernen |

### Sessions

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/api/exercises/<id>/sessions` | Sessions auflisten (`?include_aggregates=true` für Stats) |
| `POST` | `/api/exercises/<id>/sessions` | Session hinzufügen — Kraft: `weight`, `repetitions`; Cardio: `duration_minutes`, `distance_km` |
| `DELETE` | `/api/sessions/<id>` | Session löschen |

### Körpergewicht

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/api/body_weight` | Alle Einträge + Statistiken |
| `POST` | `/api/body_weight` | Neuen Eintrag erstellen (JSON: `weight`, `notes`) |
| `DELETE` | `/api/body_weight/<id>` | Eintrag löschen |

### Fortschrittsfotos

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/api/progress_photos` | Alle Fotos auflisten |
| `POST` | `/api/progress_photos` | Foto hochladen (multipart/form-data: `photo`, `notes`, `body_weight`) |
| `DELETE` | `/api/progress_photos/<id>` | Foto löschen |

### Trainingskalender

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/api/calendar` | Kalender-Daten (`?year=2026&month=3`) |
| `POST` | `/api/calendar/plan` | Trainingstag planen (JSON: `date` YYYY-MM-DD, `label`) |
| `POST` | `/api/calendar/unplan` | Trainingstag entfernen (JSON: `date`) |

### Plan-Sharing

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `POST` | `/api/training_plans/<id>/share` | Share-Link generieren |
| `POST` | `/api/training_plans/<id>/unshare` | Teilen deaktivieren |
| `POST` | `/api/shared/<token>/copy` | Geteilten Plan ins eigene Konto kopieren |

### Vorlagen (Template-Pläne)

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/api/template_plans` | Sichtbare Vorlagen auflisten (Admin/Trainer sehen alle) |
| `GET` | `/api/template_plans/<id>` | Vorlage mit Übungen anzeigen |
| `POST` | `/api/template_plans/<id>/add_to_account` | Vorlage ins eigene Konto übernehmen |

### Export

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| `GET` | `/api/export` | Alle Trainingsdaten + Körpergewicht als JSON exportieren |

## Datenbank-Migration auf globale Übungen

Mit dem Skript `migrate_to_global_exercises.py` kannst du eine bestehende
`fitness.db` aktualisieren, um die neuen globalen Übungen und die
Zwischentabelle `plan_exercises` zu verwenden. Führe dazu einfach

```bash
python migrate_to_global_exercises.py
```

aus. Falls die Datenbank bereits angepasst wurde, beendet sich das Skript
ohne weitere Änderungen.

## License

This project is licensed under the PolyForm Noncommercial License
Der Autor mrchaos behält sich das Recht vor, dieses Werk für kommerzielle Zwecke zu nutzen oder Lizenzen für kommerzielle Nutzungen zu vergeben.
