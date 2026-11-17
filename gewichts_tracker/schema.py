"""Datenbank-Schema beim Start anlegen und fehlende Spalten ergänzen."""

import os

from gewichts_tracker.core import app, db


def add_missing_columns():
    """Add columns that exist in the models but not yet in the database.

    Damit startet die App nach einem Update auch dann, wenn update.py noch nicht
    gelaufen ist. Größere Umbauten (alte Tabellen neu aufbauen, Altdaten) macht
    weiterhin nur update.py. Gibt die ergänzten Spalten als "tabelle.spalte" zurück.
    """
    from sqlalchemy import inspect, text

    engine = db.engine
    inspector = inspect(engine)
    added = set()
    for table in db.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
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
                if column.unique:
                    conn.execute(text(
                        f'CREATE UNIQUE INDEX IF NOT EXISTS "uq_{table.name}_{column.name}" '
                        f'ON "{table.name}" ("{column.name}")'))
            added.add(f'{table.name}.{column.name}')
    if 'user.email_confirmed' in added:
        # Die Verifizierung gab es vorher nicht: bestehende Konten nicht aussperren
        with engine.begin() as conn:
            conn.execute(text('UPDATE "user" SET email_confirmed = 1'))
    return added


def _ensure_database_setup_once() -> None:
    """Ensure database tables exist once per application lifecycle."""

    if getattr(app, '_database_setup_ran', False):
        return

    try:
        with app.app_context():
            db.create_all()
            if not os.environ.get('GEWICHTS_TRACKER_NO_AUTO_MIGRATE'):  # update.py macht das selbst
                added = add_missing_columns()
                if added:
                    app.logger.warning('Added missing database columns: %s', ', '.join(sorted(added)))
    except Exception as exc:  # pragma: no cover - defensive logging
        app.logger.warning('Failed to ensure database tables: %s', exc)

    app._database_setup_ran = True
