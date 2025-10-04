import sqlite3

DB_PATH = 'fitness.db'


def migrate(db_path=DB_PATH):
    """Add notes and perceived_exertion columns to exercise_session if missing."""
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        columns = [row[1] for row in cursor.execute("PRAGMA table_info(exercise_session)").fetchall()]
        added = False
        if 'notes' not in columns:
            cursor.execute('ALTER TABLE exercise_session ADD COLUMN notes TEXT;')
            added = True
        if 'perceived_exertion' not in columns:
            cursor.execute('ALTER TABLE exercise_session ADD COLUMN perceived_exertion INTEGER;')
            added = True
        conn.commit()
        if added:
            print('Migration completed: columns added.')
        else:
            print('Database already up to date.')
    finally:
        conn.close()


if __name__ == '__main__':
    migrate()
