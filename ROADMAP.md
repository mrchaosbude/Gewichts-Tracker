# Roadmap

Reihenfolge nach Nutzen und Risiko. Jede Phase ist ein eigener Pull Request (oder mehrere kleine).
Nach jedem Update auf dem Server: `python update.py` ausführen.

## Phase 1 – Konto-Grundlagen und CI (erledigt)

- [x] CI: `pytest` läuft bei jedem Push und Pull Request (GitHub Actions)
- [x] Passwort selbst ändern (Konto-Seite)
- [x] E-Mail-Adresse selbst hinterlegen/ändern
- [x] „Passwort vergessen“ per E-Mail (Link 1 Stunde gültig, einmal verwendbar)
- [x] Passwortänderung meldet alle anderen Sitzungen ab (auch bei Änderung durch den Admin)

## Phase 2 – Eigene Daten im Griff (erledigt)

- [x] Konto selbst löschen (mit Passwortabfrage, löscht alle Daten und Fotos)
- [x] Export vervollständigen: Körpergewichte, geplante Trainings und Fotos als ZIP
- [x] Import des eigenen Exports (Umzug, Backup auf Nutzerebene)
- [x] Sessions bearbeiten statt nur löschen und neu anlegen

## Phase 3 – Sicherheit nachziehen (erledigt bis auf strikte CSP)

- [x] Erst-Registrierung absichern: Admin über `update.py` anlegen, offene Registrierung abschaltbar
- [x] Zwei-Faktor-Anmeldung (TOTP), verpflichtend für Admins einstellbar
- [x] Logout und „geteilten Plan kopieren“ nur noch per POST
- [x] `/sync` validiert Datentypen wie die API
- [x] Einheitliche Passwortregeln (Web und API: mindestens 8 Zeichen)
- [x] Content-Security-Policy, Stufe 1: fremde Skript-Quellen, Formularziele, Plugins und Einbettung gesperrt
- [ ] Content-Security-Policy, Stufe 2: Inline-Skripte verbieten (setzt voraus: 20 Skript-Blöcke und 52 `on…`-Attribute aus den Templates in Dateien verlagern)
- [x] `ProxyFix` konfigurierbar, damit das Rate-Limit hinter einem Reverse Proxy pro Nutzer zählt
- [x] Fehlende Datenbankspalten werden beim Start selbst ergänzt

## Phase 4 – Umbau für Wartbarkeit

- [ ] `app.py` in Module/Blueprints aufteilen (Modelle, Formulare, Auth, Training, Admin, API)
- [ ] Gemeinsame Logikschicht für Web und API, damit beide nicht auseinanderlaufen
- [ ] Alte `migrate_*.py`-Skripte entfernen, Schema-Änderungen über Alembic
- [ ] Eingecheckte `.pyc`-Dateien und die leere `fitness.db` aus dem Repo nehmen, `uwsgi.ini` korrigieren

## Phase 5 – Betrieb

- [ ] Docker-Setup mit einem Volume für `instance/` (Datenbank, Fotos, Backups) und `.env`
- [ ] Automatisches tägliches Backup mit Aufbewahrungsfrist
- [ ] Health-Check-Endpunkt für Monitoring

## Phase 6 – Trainingsfunktionen

- [ ] Pausen-Timer nach dem Eintragen eines Satzes (mit Vibration)
- [ ] Trainingsmodus: Plan Übung für Übung durchgehen
- [ ] Zielwerte pro Übung (Zielgewicht, Ziel-1RM) mit Fortschrittsanzeige
- [ ] Körpermaße (Bauch, Brust, Arme …) neben dem Gewicht
- [ ] Vorher-Nachher-Vergleich zweier Fortschrittsfotos

## Phase 7 – Trainer

- [ ] Trainer weist Nutzern Pläne zu
- [ ] Trainer sieht den Fortschritt seiner Nutzer (nur mit deren Einwilligung, widerrufbar)
