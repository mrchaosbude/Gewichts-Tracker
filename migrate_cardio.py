import sqlite3
import os

DB_PATH = os.path.join('instance', 'fitness.db') if os.path.exists(os.path.join('instance', 'fitness.db')) else 'fitness.db'


def migrate(db_path=None):
    """Add cardio/endurance and warm-up fields to exercise and exercise_session tables.
    Also makes repetitions and weight nullable (SQLite requires table rebuild for this)."""
    if db_path is None:
        db_path = DB_PATH
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = OFF;")

        # --- exercise table ---
        exercise_exists = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='exercise';"
        ).fetchone()
        if not exercise_exists:
            print("Table 'exercise' does not exist. Skipping exercise migration.")
        else:
            ex_cols = [row[1] for row in cursor.execute("PRAGMA table_info(exercise)").fetchall()]
            if 'exercise_type' not in ex_cols:
                cursor.execute("ALTER TABLE exercise ADD COLUMN exercise_type VARCHAR(20) DEFAULT 'kraft';")
                print("Added column exercise.exercise_type")
            else:
                print("exercise.exercise_type already present.")

        # --- exercise_session table ---
        session_exists = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='exercise_session';"
        ).fetchone()
        if not session_exists:
            print("Table 'exercise_session' does not exist. Skipping session migration.")
        else:
            sess_cols = [row[1] for row in cursor.execute("PRAGMA table_info(exercise_session)").fetchall()]

            # Add new columns if missing
            if 'duration_minutes' not in sess_cols:
                cursor.execute("ALTER TABLE exercise_session ADD COLUMN duration_minutes INTEGER;")
                print("Added column exercise_session.duration_minutes")
            else:
                print("exercise_session.duration_minutes already present.")

            if 'distance_km' not in sess_cols:
                cursor.execute("ALTER TABLE exercise_session ADD COLUMN distance_km FLOAT;")
                print("Added column exercise_session.distance_km")
            else:
                print("exercise_session.distance_km already present.")

            if 'warmup_activity' not in sess_cols:
                cursor.execute("ALTER TABLE exercise_session ADD COLUMN warmup_activity VARCHAR(100);")
                print("Added column exercise_session.warmup_activity")
            else:
                print("exercise_session.warmup_activity already present.")

            if 'warmup_duration' not in sess_cols:
                cursor.execute("ALTER TABLE exercise_session ADD COLUMN warmup_duration INTEGER;")
                print("Added column exercise_session.warmup_duration")
            else:
                print("exercise_session.warmup_duration already present.")

            # --- Make repetitions and weight nullable ---
            # SQLite cannot ALTER COLUMN, so we rebuild the table
            col_info = cursor.execute("PRAGMA table_info(exercise_session)").fetchall()
            notnull_map = {row[1]: row[3] for row in col_info}  # name -> notnull flag
            if notnull_map.get('repetitions', 0) == 1 or notnull_map.get('weight', 0) == 1:
                print("Rebuilding exercise_session to make repetitions/weight nullable...")
                cursor.execute("""
                    CREATE TABLE exercise_session_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        exercise_id INTEGER NOT NULL REFERENCES exercise(id),
                        repetitions INTEGER,
                        weight INTEGER,
                        timestamp DATETIME,
                        notes TEXT,
                        perceived_exertion INTEGER,
                        user_id INTEGER REFERENCES "user"(id),
                        duration_minutes INTEGER,
                        distance_km FLOAT,
                        warmup_activity VARCHAR(100),
                        warmup_duration INTEGER
                    );
                """)
                cursor.execute("""
                    INSERT INTO exercise_session_new
                        (id, exercise_id, repetitions, weight, timestamp, notes,
                         perceived_exertion, user_id, duration_minutes, distance_km,
                         warmup_activity, warmup_duration)
                    SELECT id, exercise_id, repetitions, weight, timestamp, notes,
                           perceived_exertion, user_id, duration_minutes, distance_km,
                           warmup_activity, warmup_duration
                    FROM exercise_session;
                """)
                cursor.execute("DROP TABLE exercise_session;")
                cursor.execute("ALTER TABLE exercise_session_new RENAME TO exercise_session;")
                print("Table rebuilt: repetitions and weight are now nullable.")
            else:
                print("repetitions/weight already nullable.")

        conn.commit()
        cursor.execute("PRAGMA foreign_keys = ON;")
        print("Migration finished.")
    finally:
        conn.close()


if __name__ == '__main__':
    migrate()
