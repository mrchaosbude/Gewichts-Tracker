import sqlite3

from migration_utils import resolve_db_path

DB_PATH = resolve_db_path()


def migrate(db_path=None):
    """Add client_uuid columns and indexes. Safe to run on empty or populated DBs."""
    if db_path is None:
        db_path = DB_PATH
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        tables = [t[0] for t in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

        # --- exercise_session ---
        if 'exercise_session' in tables:
            es_cols = [row[1] for row in cursor.execute("PRAGMA table_info(exercise_session)").fetchall()]
            if 'client_uuid' not in es_cols:
                cursor.execute("ALTER TABLE exercise_session ADD COLUMN client_uuid VARCHAR(36) UNIQUE;")
                print("Added column exercise_session.client_uuid")
            else:
                print("exercise_session.client_uuid already present.")

            cursor.execute("CREATE INDEX IF NOT EXISTS ix_exercise_session_user_id ON exercise_session(user_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_exercise_session_timestamp ON exercise_session(timestamp);")
            print("Indexes on exercise_session ensured.")
        else:
            print("Table exercise_session not found (will be created on app start).")

        # --- body_weight ---
        if 'body_weight' in tables:
            bw_cols = [row[1] for row in cursor.execute("PRAGMA table_info(body_weight)").fetchall()]
            if 'client_uuid' not in bw_cols:
                cursor.execute("ALTER TABLE body_weight ADD COLUMN client_uuid VARCHAR(36) UNIQUE;")
                print("Added column body_weight.client_uuid")
            else:
                print("body_weight.client_uuid already present.")

            cursor.execute("CREATE INDEX IF NOT EXISTS ix_body_weight_user_id ON body_weight(user_id);")
            print("Index on body_weight ensured.")
        else:
            print("Table body_weight not found (will be created on app start).")

        # --- exercise ---
        if 'exercise' in tables:
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_exercise_user_id ON exercise(user_id);")
            print("Index on exercise ensured.")
        else:
            print("Table exercise not found (will be created on app start).")

        conn.commit()
        print("Migration completed successfully.")
    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
        raise
    finally:
        conn.close()


if __name__ == '__main__':
    print(f"Using database: {DB_PATH}")
    migrate()
