#!/usr/bin/env python3
"""Update-Assistent für Gewichts-Tracker.

Zieht eine bestehende Installation auf den aktuellen Stand:

1. Datenbank finden (auch am alten Ablageort) und sichern
2. Schema aktualisieren (alte Migrationen + fehlende Tabellen/Spalten/Indizes)
3. Altdaten bereinigen (unsichere Links, verwaiste Daten, Besitzer-Zuordnung)
4. Fortschrittsfotos aus dem öffentlichen static/-Ordner in den privaten Ordner verschieben
5. Fehlende Konfiguration abfragen (SECRET_KEY, HTTPS-Cookies, SMTP-Passwort, Admin)

Das Skript kann beliebig oft ausgeführt werden; bereits Erledigtes wird übersprungen.

    python update.py            # interaktiv
    python update.py --yes      # ohne Rückfragen (sichere Standardantworten)
    python update.py --dry-run  # nur anzeigen, arbeitet auf einer Kopie der Datenbank
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import importlib
import os
import secrets
import shutil
import sqlite3
import sys
import tempfile

import env_config

APP_DIR = env_config.APP_DIR
INSTANCE_DIR = os.path.join(APP_DIR, 'instance')
INSECURE_SECRET_KEYS = {'dein_geheimer_schluessel', 'secret', 'changeme', 'change-me', 'dev'}

# Einzige alte Migration, die Daten umbaut (exercise.training_plan_id -> plan_exercises).
LEGACY_SQLITE_MIGRATIONS = [
    ('001_global_exercises', 'migrate_to_global_exercises'),
]
# Diese alten Skripte (Spalten ergänzen, NOT NULL lockern) scheitern auf manchen
# Altständen; ihr Ergebnis stellt sync_schema() her. Danach gelten sie als erledigt.
COVERED_BY_SCHEMA_SYNC = ['002_session_notes_rpe', '003_cardio', '004_client_uuid']
OWNERSHIP_MIGRATION = '005_ownership_backfill'


class Assistant:
    """Console helper: prompts, defaults for --yes / --dry-run, summary."""

    def __init__(self, assume_yes: bool, dry_run: bool):
        self.dry_run = dry_run
        self.interactive = not assume_yes and not dry_run and sys.stdin.isatty()
        self.done = []
        self.todo = []

    def step(self, title):
        print(f'\n=== {title} ===')

    def info(self, text):
        print(f'  {text}')

    def ok(self, text):
        print(f'  [ok] {text}')
        self.done.append(text)

    def warn(self, text):
        print(f'  [!!] {text}')
        self.todo.append(text)

    def confirm(self, question, default=True):
        suffix = '[J/n]' if default else '[j/N]'
        if not self.interactive:
            print(f'  ? {question} {suffix} -> {"ja" if default else "nein"} (Standard)')
            return default
        while True:
            answer = input(f'  ? {question} {suffix} ').strip().lower()
            if not answer:
                return default
            if answer in ('j', 'ja', 'y', 'yes'):
                return True
            if answer in ('n', 'nein', 'no'):
                return False

    def choose(self, question, options, default):
        """options: list of (key, label). Returns the chosen key."""
        if not self.interactive:
            print(f'  ? {question} -> {default} (Standard)')
            return default
        for key, label in options:
            print(f'      {key}) {label}')
        keys = {str(k) for k, _ in options}
        while True:
            answer = input(f'  ? {question} [{default}] ').strip() or str(default)
            if answer in keys:
                return type(options[0][0])(answer)

    def secret(self, question):
        if not self.interactive:
            return None
        while True:
            first = getpass.getpass(f'  ? {question}: ')
            if not first:
                return None
            if getpass.getpass('  ? Wiederholen: ') == first:
                return first
            print('  Eingaben stimmen nicht überein.')


# ---------------------------------------------------------------------------
# 1. Datenbank finden und sichern
# ---------------------------------------------------------------------------

def _table_count(path):
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return 0
    try:
        conn = sqlite3.connect(path)
        try:
            return conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return 0


def locate_database(ui: Assistant, explicit=None):
    """Return the absolute path of the SQLite database the app will use."""
    if explicit:
        return os.path.abspath(explicit)
    uri = os.environ.get('GEWICHTS_TRACKER_DATABASE_URI')
    if uri:
        if not uri.startswith('sqlite:///'):
            sys.exit('GEWICHTS_TRACKER_DATABASE_URI ist keine SQLite-Datenbank; '
                     'dieses Skript unterstützt nur SQLite.')
        path = uri[len('sqlite:///'):]
        # Flask-SQLAlchemy 3 löst relative Pfade gegen instance/ auf
        return path if os.path.isabs(path) else os.path.join(INSTANCE_DIR, path)

    current = os.path.join(INSTANCE_DIR, 'fitness.db')
    legacy = os.path.join(APP_DIR, 'fitness.db')
    if _table_count(current):
        if _table_count(legacy):
            ui.warn(f'Es gibt zusätzlich eine alte Datenbank unter {legacy}. '
                    f'Verwendet wird {current}; die alte bitte prüfen und ggf. löschen.')
        return current
    if _table_count(legacy):
        ui.info(f'Datenbank liegt noch am alten Ort: {legacy}')
        ui.info(f'Die aktuelle Version erwartet sie unter: {current}')
        if ui.confirm('Datenbank dorthin kopieren (Original bleibt erhalten)?', True):
            if not ui.dry_run:
                os.makedirs(INSTANCE_DIR, exist_ok=True)
                shutil.copy2(legacy, current)
                ui.ok(f'Datenbank nach {current} kopiert')
                return current
            return legacy
        ui.warn('Datenbank nicht verschoben - die App startet sonst mit einer leeren Datenbank. '
                'Alternativ GEWICHTS_TRACKER_DATABASE_URI auf den alten Pfad setzen.')
        return legacy
    return current


def backup_database(ui: Assistant, db_path):
    backup_dir = os.path.join(os.path.dirname(db_path), 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    target = os.path.join(backup_dir, f'fitness-{stamp}.db')
    src = sqlite3.connect(db_path)
    try:
        dst = sqlite3.connect(target)
        try:
            src.backup(dst)  # konsistent, auch wenn die App gerade läuft
        finally:
            dst.close()
    finally:
        src.close()
    ui.ok(f'Sicherung erstellt: {target}')
    return target


# ---------------------------------------------------------------------------
# 2. Schema
# ---------------------------------------------------------------------------

def run_legacy_migrations(ui: Assistant, db_path):
    """Run the old sqlite3-based migrations that restructure pre-existing tables."""
    import migration_utils

    conn = sqlite3.connect(db_path)
    try:
        has_exercise = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='exercise'").fetchone()
    finally:
        conn.close()
    if not has_exercise:
        ui.info('Keine alten Tabellen vorhanden - alte Migrationen übersprungen.')
        return
    migration_utils.ensure_schema_version_table(db_path)
    applied = migration_utils.get_applied_migrations(db_path)
    for name, module_name in LEGACY_SQLITE_MIGRATIONS:
        if name in applied:
            continue
        try:
            importlib.import_module(module_name).migrate(db_path=db_path)
            migration_utils.record_migration(db_path, name)
            ui.ok(f'Migration {name} angewendet')
        except Exception as exc:  # weiter mit dem generischen Abgleich
            ui.warn(f'Migration {name} fehlgeschlagen ({exc}). Der Schema-Abgleich versucht es trotzdem.')


def _rebuild_table(engine, table, existing_columns):
    """Recreate *table* from the model definition and copy the data over.

    Nötig, weil SQLite Spalten-Constraints (z.B. NOT NULL) nicht ändern kann.
    """
    from sqlalchemy.schema import CreateIndex, CreateTable

    old_name = f'{table.name}__old'
    common = ', '.join(f'"{c.name}"' for c in table.columns if c.name in existing_columns)
    raw = engine.raw_connection()
    try:
        cur = raw.cursor()
        cur.execute('PRAGMA foreign_keys=OFF')
        cur.execute('PRAGMA legacy_alter_table=ON')  # Verweise anderer Tabellen nicht umschreiben
        cur.execute('BEGIN')
        try:
            for (index_name,) in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL",
                    (table.name,)).fetchall():
                cur.execute(f'DROP INDEX "{index_name}"')
            cur.execute(f'ALTER TABLE "{table.name}" RENAME TO "{old_name}"')
            cur.execute(str(CreateTable(table).compile(engine)))
            cur.execute(f'INSERT INTO "{table.name}" ({common}) SELECT {common} FROM "{old_name}"')
            cur.execute(f'DROP TABLE "{old_name}"')
            for index in table.indexes:
                cur.execute(str(CreateIndex(index).compile(engine)))
            cur.execute('COMMIT')
        except Exception:
            cur.execute('ROLLBACK')
            raise
        finally:
            cur.execute('PRAGMA legacy_alter_table=OFF')
    finally:
        raw.close()


def sync_schema(ui: Assistant, app_module):
    """Create missing tables, columns and indexes so the DB matches the models."""
    from sqlalchemy import inspect, text

    db = app_module.db
    db.create_all()
    engine = db.engine
    inspector = inspect(engine)
    added = 0
    new_columns = set()

    # Reste abgebrochener alter Migrationen (z.B. exercise_session_new)
    model_tables = set(db.metadata.tables)
    leftovers = {f'{name}_new' for name in model_tables} | {f'{name}__old' for name in model_tables}
    for leftover in inspector.get_table_names():
        if leftover in leftovers and leftover not in model_tables:
            with engine.begin() as conn:
                rows = conn.execute(text(f'SELECT COUNT(*) FROM "{leftover}"')).scalar()
                if rows == 0:
                    conn.execute(text(f'DROP TABLE "{leftover}"'))
                    ui.ok(f'Leere Resttabelle {leftover} einer abgebrochenen Migration entfernt')
                else:
                    ui.warn(f'Resttabelle {leftover} enthält {rows} Zeilen - bitte manuell prüfen.')
    inspector = inspect(engine)
    for table in db.metadata.sorted_tables:
        existing = {col['name'] for col in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            ddl = f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {column.type.compile(dialect=engine.dialect)}'
            default = getattr(column.default, 'arg', None)
            if isinstance(default, bool):
                ddl += f' DEFAULT {int(default)}'
            elif isinstance(default, (int, float)):
                ddl += f' DEFAULT {default}'
            elif isinstance(default, str):
                ddl += " DEFAULT '" + default.replace("'", "''") + "'"
            with engine.begin() as conn:
                conn.execute(text(ddl))
            ui.ok(f'Spalte {table.name}.{column.name} ergänzt')
            added += 1
            new_columns.add(f'{table.name}.{column.name}')
            if column.unique:
                # SQLite kann UNIQUE nicht per ALTER TABLE; daher als Index
                with engine.begin() as conn:
                    conn.execute(text(
                        f'CREATE UNIQUE INDEX IF NOT EXISTS "uq_{table.name}_{column.name}" '
                        f'ON "{table.name}" ("{column.name}")'))
    # Spalten, die früher NOT NULL waren und es laut Modell nicht mehr sind
    inspector = inspect(engine)
    for table in db.metadata.sorted_tables:
        db_columns = {col['name']: col for col in inspector.get_columns(table.name)}
        too_strict = [
            c.name for c in table.columns
            if c.name in db_columns and c.nullable and not c.primary_key and not db_columns[c.name]['nullable']
        ]
        if not too_strict:
            continue
        db.session.remove()
        engine.dispose()
        try:
            _rebuild_table(engine, table, set(db_columns))
            ui.ok(f'Tabelle {table.name} neu aufgebaut ({", ".join(too_strict)} dürfen jetzt leer sein)')
            added += 1
        except Exception as exc:
            ui.warn(f'Tabelle {table.name} konnte nicht neu aufgebaut werden: {exc}')
        engine.dispose()

    inspector = inspect(engine)
    for table in db.metadata.sorted_tables:
        have = {idx['name'] for idx in inspector.get_indexes(table.name)}
        for index in table.indexes:
            if index.name not in have:
                try:
                    index.create(bind=engine)
                    ui.ok(f'Index {index.name} angelegt')
                    added += 1
                except Exception as exc:
                    ui.warn(f'Index {index.name} konnte nicht angelegt werden: {exc}')
    if not added:
        ui.info('Schema ist aktuell.')
    return new_columns


# ---------------------------------------------------------------------------
# 3. Altdaten
# ---------------------------------------------------------------------------

def fix_data(ui: Assistant, app_module, new_columns=frozenset()):
    from sqlalchemy import text

    db = app_module.db
    User = app_module.User

    # Bestehende Konten dürfen durch die neue E-Mail-Verifizierung nicht ausgesperrt werden.
    # Wurde die Spalte gerade erst angelegt, gab es die Verifizierung vorher nicht -> alle bestätigt.
    condition = '1 = 1' if 'user.email_confirmed' in new_columns else 'email_confirmed IS NULL'
    result = db.session.execute(text(f'UPDATE user SET email_confirmed = 1 WHERE {condition}'))
    if result.rowcount:
        ui.ok(f'{result.rowcount} bestehende Konten als bestätigt markiert')
    result = db.session.execute(text(
        "UPDATE exercise SET exercise_type = 'kraft' WHERE exercise_type IS NULL OR exercise_type = ''"))
    if result.rowcount:
        ui.ok(f'{result.rowcount} Übungen ohne Typ auf "kraft" gesetzt')
    for table in ('exercise', 'template_exercise'):
        db.session.execute(text(f'UPDATE {table} SET is_separator = 0 WHERE is_separator IS NULL'))
    # Einträge ohne Zeitstempel lassen Dashboard/Statistik abstürzen
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(sep=' ')
    for table, column in (('exercise_session', 'timestamp'), ('body_weight', 'timestamp'),
                          ('progress_photo', 'timestamp'), ('user', 'registration_date')):
        result = db.session.execute(
            text(f'UPDATE "{table}" SET "{column}" = :now WHERE "{column}" IS NULL'), {'now': now})
        if result.rowcount:
            ui.ok(f'{result.rowcount} Einträge in {table} ohne Datum auf heute gesetzt')
    app_module.get_app_settings()
    db.session.commit()

    # Besitzer-Zuordnung für alte Übungen/Sessions
    try:
        import migrate as ownership
        import migration_utils
        exercises = ownership.backfill_exercise_owners()
        sessions = ownership.backfill_session_owners()
        db.session.commit()
        if exercises or sessions:
            ui.ok(f'Besitzer ergänzt: {exercises} Übungen, {sessions} Sessions')
        db_path = db.engine.url.database
        migration_utils.ensure_schema_version_table(db_path)
        applied = migration_utils.get_applied_migrations(db_path)
        for name in COVERED_BY_SCHEMA_SYNC + [OWNERSHIP_MIGRATION]:
            if name not in applied:
                migration_utils.record_migration(db_path, name)
    except Exception as exc:
        db.session.rollback()
        ui.warn(f'Besitzer-Zuordnung fehlgeschlagen: {exc}')
    unowned = app_module.ExerciseSession.query.filter(app_module.ExerciseSession.user_id.is_(None)).count()
    if unowned:
        ui.warn(f'{unowned} Sessions ohne eindeutigen Besitzer - sie sind für niemanden sichtbar.')

    # Unsichere Links (javascript: usw.) aus Altbeständen entfernen
    bad = [ex for ex in app_module.Exercise.query.filter(app_module.Exercise.video_url.isnot(None)).all()
           if app_module.sanitize_external_url(ex.video_url) is None]
    for ex in bad:
        ui.info(f'Unsichere Video-URL bei Übung #{ex.id} "{ex.name}": {ex.video_url[:60]!r}')
        ex.video_url = None
    if bad:
        db.session.commit()
        ui.ok(f'{len(bad)} unsichere Video-URLs entfernt')
    for link in app_module.FooterLink.query.all():
        if app_module.sanitize_external_url(link.url, allow_relative=True) is None:
            if ui.confirm(f'Footer-Link "{link.title}" hat eine ungültige URL ({link.url[:60]!r}). Löschen?', True):
                db.session.delete(link)
                db.session.commit()
                ui.ok(f'Footer-Link "{link.title}" gelöscht')
            else:
                ui.warn(f'Footer-Link "{link.title}" wird nicht mehr als Link angezeigt, bis die URL korrigiert ist.')

    # Verwaiste Daten gelöschter Benutzer (würden sonst bei ID-Wiederverwendung vererbt)
    user_ids = {row[0] for row in db.session.query(User.id).all()}
    orphan_models = [
        ('Fortschrittsfotos', app_module.ProgressPhoto),
        ('Körpergewichte', app_module.BodyWeight),
        ('geplante Trainings', app_module.PlannedTraining),
        ('Sessions', app_module.ExerciseSession),
    ]
    orphans = []
    for label, model in orphan_models:
        rows = [row for row in model.query.filter(model.user_id.isnot(None)).all() if row.user_id not in user_ids]
        if rows:
            orphans.append((label, rows))
    if orphans:
        summary = ', '.join(f'{len(rows)} {label}' for label, rows in orphans)
        ui.info(f'Daten bereits gelöschter Benutzer gefunden: {summary}')
        if ui.confirm('Diese verwaisten Daten endgültig löschen (Sicherung existiert)?', True):
            for label, rows in orphans:
                for row in rows:
                    if isinstance(row, app_module.ProgressPhoto) and not ui.dry_run:
                        app_module.remove_progress_photo_file(row)
                    db.session.delete(row)
            db.session.commit()
            ui.ok(f'Verwaiste Daten gelöscht ({summary})')
        else:
            ui.warn('Verwaiste Daten behalten - ein neuer Benutzer mit derselben ID würde sie sehen.')


# ---------------------------------------------------------------------------
# 4. Fotos
# ---------------------------------------------------------------------------

def migrate_photos(ui: Assistant, app_module):
    legacy = app_module.LEGACY_UPLOAD_FOLDER
    target = app_module.app.config['UPLOAD_FOLDER']
    ui.info(f'Privater Foto-Ordner: {target}')
    legacy_files = [n for n in os.listdir(legacy)] if os.path.isdir(legacy) else []
    legacy_files = [n for n in legacy_files if app_module.allowed_file(n)]
    if legacy_files:
        if ui.dry_run:
            ui.info(f'{len(legacy_files)} Fotos würden aus {legacy} verschoben.')
        else:
            moved = app_module.migrate_legacy_photo_uploads()
            ui.ok(f'{moved} Fotos aus dem öffentlichen Ordner {legacy} verschoben')
            left = [n for n in os.listdir(legacy) if app_module.allowed_file(n)]
            if left:
                ui.warn(f'{len(left)} Fotos liegen weiterhin öffentlich in {legacy} (Namenskonflikt) - bitte manuell prüfen.')
    else:
        ui.info('Keine Fotos im alten öffentlichen Ordner.')

    db = app_module.db
    photos = app_module.ProgressPhoto.query.all()
    missing = [p for p in photos if not os.path.isfile(app_module.progress_photo_path(p))]
    if missing and not (ui.dry_run and legacy_files):
        ui.info(f'{len(missing)} Foto-Einträge ohne Datei (z.B. Nr. {missing[0].id}: {missing[0].filename}).')
        if ui.confirm('Einträge ohne Datei aus der Datenbank entfernen?', False):
            for photo in missing:
                db.session.delete(photo)
            db.session.commit()
            ui.ok(f'{len(missing)} Foto-Einträge ohne Datei entfernt')
        else:
            ui.warn(f'{len(missing)} Fotos werden als defekt angezeigt (Datei fehlt). '
                    'Falls sie woanders liegen: nach ' + target + ' kopieren.')
    if os.path.isdir(target):
        known = {os.path.basename(p.filename or '') for p in photos}
        stray = [n for n in os.listdir(target) if app_module.allowed_file(n) and n not in known]
        if stray:
            ui.info(f'{len(stray)} Dateien im Foto-Ordner gehören zu keinem Eintrag (nicht gelöscht).')


# ---------------------------------------------------------------------------
# 5. Konfiguration
# ---------------------------------------------------------------------------

def configure_secret_key(ui: Assistant):
    """Ensure a persistent SECRET_KEY exists *before* the app is imported."""
    key = os.environ.get('SECRET_KEY')
    if key and key.lower() not in INSECURE_SECRET_KEYS and len(key) >= 16:
        ui.info('SECRET_KEY ist gesetzt.')
        return
    if key:
        ui.info('Der gesetzte SECRET_KEY ist unsicher (bekannter Beispielwert oder zu kurz).')
        question = 'Neuen SECRET_KEY erzeugen und in .env speichern? (alle Nutzer müssen sich neu einloggen)'
    else:
        ui.info('Kein SECRET_KEY gefunden. Ohne festen Key werden bei jedem Neustart alle Logins '
                'ungültig und das SMTP-Passwort unlesbar.')
        ui.info('(Falls der Key woanders gesetzt wird, z.B. in systemd oder uwsgi, hier mit "n" antworten.)')
        question = 'SECRET_KEY jetzt erzeugen und in .env speichern?'
    if not ui.confirm(question, True):
        ui.warn('SECRET_KEY nicht gesetzt - bitte als Umgebungsvariable setzen.')
        return
    if ui.dry_run:
        ui.info('SECRET_KEY würde in .env geschrieben.')
        return
    new_key = secrets.token_hex(32)
    env_config.update_env_file({'SECRET_KEY': new_key})
    os.environ['SECRET_KEY'] = new_key
    ui.ok(f'SECRET_KEY erzeugt und in {env_config.DEFAULT_ENV_PATH} gespeichert')


def configure_cookies(ui: Assistant):
    if os.environ.get('SESSION_COOKIE_SECURE') is not None:
        ui.info(f"SESSION_COOKIE_SECURE={os.environ['SESSION_COOKIE_SECURE']}")
        return
    https = ui.confirm('Läuft die App ausschließlich über HTTPS? (Cookies dann nur verschlüsselt senden)', False)
    if ui.dry_run:
        return
    if not ui.interactive:
        ui.warn('SESSION_COOKIE_SECURE nicht gesetzt - bei HTTPS-Betrieb "SESSION_COOKIE_SECURE=true" in .env eintragen.')
        return
    env_config.update_env_file({'SESSION_COOKIE_SECURE': 'true' if https else 'false'})
    ui.ok(f'SESSION_COOKIE_SECURE={"true" if https else "false"} in .env gespeichert')


def check_smtp_password(ui: Assistant, app_module):
    from cryptography.fernet import InvalidToken

    db = app_module.db
    settings = app_module.get_app_settings()
    if not settings.smtp_password:
        ui.info('Kein SMTP-Passwort gespeichert.')
        return
    try:
        app_module._get_fernet().decrypt(settings.smtp_password.encode())
        ui.info('SMTP-Passwort ist verschlüsselt und lesbar.')
        return
    except (InvalidToken, ValueError, TypeError):
        pass
    looks_encrypted = settings.smtp_password.startswith('gAAAA')
    if looks_encrypted:
        ui.info('Das gespeicherte SMTP-Passwort wurde mit einem anderen SECRET_KEY verschlüsselt und ist nicht mehr lesbar.')
        default = 2
    else:
        ui.info('Das SMTP-Passwort liegt noch im Klartext in der Datenbank.')
        default = 1
    choice = ui.choose('Was soll mit dem SMTP-Passwort passieren?', [
        (1, 'Vorhandenen Wert als Klartext übernehmen und verschlüsseln'),
        (2, 'Passwort neu eingeben'),
        (3, 'Passwort löschen (E-Mail-Versand später im Admin-Bereich neu einrichten)'),
        (4, 'Nichts ändern'),
    ], default if ui.interactive else (1 if not looks_encrypted else 4))
    if choice == 1:
        settings.smtp_password = app_module.encrypt_value(settings.smtp_password)
        db.session.commit()
        ui.ok('SMTP-Passwort verschlüsselt')
    elif choice == 2:
        new_password = ui.secret('Neues SMTP-Passwort (leer = abbrechen)')
        if new_password:
            settings.smtp_password = app_module.encrypt_value(new_password)
            db.session.commit()
            ui.ok('SMTP-Passwort neu gesetzt')
        else:
            ui.warn('SMTP-Passwort unverändert - E-Mail-Versand funktioniert evtl. nicht.')
    elif choice == 3:
        settings.smtp_password = None
        db.session.commit()
        ui.ok('SMTP-Passwort gelöscht')
    else:
        ui.warn('SMTP-Passwort ist nicht lesbar - im Admin-Bereich unter Einstellungen neu eintragen.')


def check_admins(ui: Assistant, app_module):
    from werkzeug.security import generate_password_hash

    db = app_module.db
    User = app_module.User
    users = User.query.order_by(User.id).all()
    if not users:
        ui.info('Noch keine Benutzer vorhanden. Achtung: Der ERSTE registrierte Benutzer wird Admin - '
                'direkt nach dem Start selbst registrieren.')
        return
    admins = [u for u in users if u.is_admin]
    if not admins:
        ui.info('Es gibt keinen Administrator.')
        options = [(u.id, f'{u.username}') for u in users] + [(0, 'Niemanden')]
        choice = ui.choose('Welcher Benutzer soll Admin werden? (ID)', options, users[0].id if ui.interactive else 0)
        chosen = db.session.get(User, choice) if choice else None
        if chosen:
            chosen.is_admin = True
            db.session.commit()
            admins = [chosen]
            ui.ok(f'{chosen.username} ist jetzt Administrator')
        else:
            ui.warn('Kein Administrator vorhanden - update.py erneut interaktiv ausführen.')
    else:
        ui.info('Administratoren: ' + ', '.join(u.username for u in admins))
    for admin in admins:
        if not ui.interactive:
            break
        if ui.confirm(f'Passwort für Admin "{admin.username}" neu setzen? '
                      '(empfohlen, falls die Datenbank je in Git/Backups öffentlich war)', False):
            while True:
                new_password = ui.secret('Neues Passwort (min. 8 Zeichen, leer = abbrechen)')
                if not new_password:
                    ui.info('Passwort nicht geändert.')
                    break
                if len(new_password) < 8:
                    ui.info('Zu kurz - mindestens 8 Zeichen.')
                    continue
                admin.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                db.session.commit()
                ui.ok(f'Passwort für {admin.username} geändert')
                break


# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description='Update-Assistent für Gewichts-Tracker')
    parser.add_argument('--yes', '-y', action='store_true', help='Keine Rückfragen, Standardantworten verwenden')
    parser.add_argument('--dry-run', action='store_true', help='Nichts verändern; arbeitet auf einer Kopie der Datenbank')
    parser.add_argument('--db', help='Pfad zur SQLite-Datenbank (Standard: automatisch finden)')
    args = parser.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors='replace')  # Umlaute dürfen die Ausgabe nie abbrechen
        except (AttributeError, ValueError):
            pass
    os.chdir(APP_DIR)
    if APP_DIR not in sys.path:
        sys.path.insert(0, APP_DIR)
    env_config.load_env_file()
    ui = Assistant(args.yes, args.dry_run)
    if args.dry_run:
        print('TESTLAUF: Es wird nichts dauerhaft verändert.')
    elif not ui.interactive and not args.yes:
        print('Keine interaktive Konsole erkannt - es werden Standardantworten verwendet.')

    ui.step('1/5 Datenbank')
    db_path = locate_database(ui, args.db)
    ui.info(f'Datenbank: {db_path}')
    tmp_dir = None
    existing = _table_count(db_path) > 0
    if existing:
        if args.dry_run:
            tmp_dir = tempfile.mkdtemp(prefix='gewichts_update_')
            work_path = os.path.join(tmp_dir, 'fitness.db')
            shutil.copy2(db_path, work_path)
            db_path = work_path
        else:
            backup_database(ui, db_path)
    else:
        ui.info('Keine bestehende Datenbank - sie wird neu angelegt.')
        if args.dry_run:
            tmp_dir = tempfile.mkdtemp(prefix='gewichts_update_')
            db_path = os.path.join(tmp_dir, 'fitness.db')
        else:
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

    try:
        ui.step('2/5 Konfiguration (SECRET_KEY, Cookies)')
        configure_secret_key(ui)
        configure_cookies(ui)

        ui.step('3/5 Datenbank-Schema')
        if existing:
            run_legacy_migrations(ui, db_path)
        os.environ['GEWICHTS_TRACKER_DATABASE_URI'] = 'sqlite:///' + db_path
        os.environ['GEWICHTS_TRACKER_NO_AUTO_MIGRATE'] = '1'
        import app as app_module  # erst jetzt: nutzt die oben gesetzte Konfiguration

        with app_module.app.app_context():
            new_columns = sync_schema(ui, app_module)

            ui.step('4/5 Altdaten und Fotos')
            fix_data(ui, app_module, new_columns)
            migrate_photos(ui, app_module)

            ui.step('5/5 Zugänge')
            check_smtp_password(ui, app_module)
            check_admins(ui, app_module)
            app_module.db.session.remove()
            app_module.db.engine.dispose()
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    print('\n=== Zusammenfassung ===')
    if args.dry_run:
        print('  Testlauf beendet - die echte Datenbank wurde nicht verändert.')
    print(f'  Erledigt: {len(ui.done)} Schritte' if ui.done else '  Es war nichts zu tun.')
    if ui.todo:
        print('  Noch offen:')
        for item in ui.todo:
            print(f'   - {item}')
    print('  Danach die App neu starten (z.B. uwsgi/systemd-Dienst).')
    return 1 if ui.todo else 0


if __name__ == '__main__':
    sys.exit(main())
