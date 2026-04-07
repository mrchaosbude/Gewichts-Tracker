"""Shared utilities for migration scripts."""

import os
import sqlite3
import datetime


def resolve_db_path() -> str:
    """Resolve the SQLite database path.

    Priority:
    1. GEWICHTS_TRACKER_DATABASE_URI env var (parse sqlite:/// prefix)
    2. instance/fitness.db (if exists)
    3. fitness.db (default)
    """
    uri = os.getenv('GEWICHTS_TRACKER_DATABASE_URI')
    if uri and uri.startswith('sqlite:///'):
        return uri[len('sqlite:///'):]

    instance_path = os.path.join('instance', 'fitness.db')
    if os.path.exists(instance_path):
        return instance_path
    return 'fitness.db'


# --- Schema version tracking ---

MIGRATIONS = [
    ('001_global_exercises', 'migrate_to_global_exercises'),
    ('002_session_notes_rpe', 'migrate_add_session_notes_rpe'),
    ('003_cardio', 'migrate_cardio'),
    ('004_client_uuid', 'migrate_client_uuid'),
    ('005_ownership_backfill', 'migrate'),
]


def ensure_schema_version_table(db_path: str) -> None:
    """Create the schema_version table if it does not exist."""
    conn = sqlite3.connect(db_path)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS schema_version (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            migration_name TEXT NOT NULL UNIQUE,
            applied_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def get_applied_migrations(db_path: str) -> set:
    """Return the set of migration names that have been applied."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute('SELECT migration_name FROM schema_version').fetchall()
    conn.close()
    return {row[0] for row in rows}


def record_migration(db_path: str, name: str) -> None:
    """Record a migration as applied."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        'INSERT INTO schema_version (migration_name, applied_at) VALUES (?, ?)',
        (name, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
