# Roadmap

Reihenfolge nach Nutzen und Risiko. Jede Phase ist ein eigener Pull Request (oder mehrere kleine).
Nach jedem Update auf dem Server: `python update.py` ausführen.

## Phase 1 – Konto-Grundlagen und CI (in Arbeit)

- [x] CI: `pytest` läuft bei jedem Push und Pull Request (GitHub Actions)
- [x] Passwort selbst ändern (Konto-Seite)
- [x] E-Mail-Adresse selbst hinterlegen/ändern
- [x] „Passwort vergessen“ per E-Mail (Link 1 Stunde gültig, einmal verwendbar)
- [x] Passwortänderung meldet alle anderen Sitzungen ab (auch bei Änderung durch den Admin)

## Phase 2 – Eigene Daten im Griff

- [ ] Konto selbst löschen (mit Passwortabfrage, löscht alle Daten und Fotos)
- [ ] Export vervollständigen: Körpergewichte, geplante Trainings und Fotos als ZIP
- [ ] Import des eigenen Exports (Umzug, Backup auf Nutzerebene)
- [ ] Sessions bearbeiten statt nur löschen und neu anlegen

## Phase 3 – Sicherheit nachziehen

- [ ] Erst-Registrierung absichern: Admin über `update.py` anlegen, offene Registrierung abschaltbar
- [ ] Zwei-Faktor-Anmeldung (TOTP), verpflichtend für Admins einstellbar
- [ ] Logout und „geteilten Plan kopieren“ nur noch per POST
- [ ] `/sync` validiert Datentypen wie die API
- [ ] Einheitliche Passwortregeln (Web und API: mindestens 8 Zeichen)
- [ ] Content-Security-Policy (setzt voraus: Inline-Skripte aus den Templates in Dateien)
- [ ] `ProxyFix` konfigurierbar, damit das Rate-Limit hinter einem Reverse Proxy pro Nutzer zählt

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
