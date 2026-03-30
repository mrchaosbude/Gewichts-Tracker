import sqlite3

DB_PATH = 'fitness.db'

# This simple script migrates the old Exercise table (with training_plan_id)
# to the new global Exercise table with the plan_exercises association table.

def ensure_plan_exercises_schema(cursor):
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS plan_exercises (
            training_plan_id INTEGER NOT NULL,
            exercise_id INTEGER NOT NULL,
            PRIMARY KEY(training_plan_id, exercise_id),
            FOREIGN KEY(training_plan_id) REFERENCES training_plan(id),
            FOREIGN KEY(exercise_id) REFERENCES exercise(id)
        );
    ''')

    plan_exercises_columns = {
        row[1] for row in cursor.execute('PRAGMA table_info(plan_exercises);').fetchall()
    }
    expected_plan_exercises = {'training_plan_id', 'exercise_id'}
    if not expected_plan_exercises.issubset(plan_exercises_columns):
        missing = expected_plan_exercises - plan_exercises_columns
        raise RuntimeError(
            f"Existing plan_exercises table missing required columns: {', '.join(sorted(missing))}"
        )


def ensure_exercise_session_schema(cursor):
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS exercise_session (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exercise_id INTEGER NOT NULL,
            repetitions INTEGER NOT NULL,
            weight INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            perceived_exertion INTEGER,
            FOREIGN KEY(exercise_id) REFERENCES exercise(id)
        );
    ''')

    session_columns = {
        row[1] for row in cursor.execute('PRAGMA table_info(exercise_session);').fetchall()
    }
    required_session_columns = {
        'id',
        'exercise_id',
        'repetitions',
        'weight',
        'timestamp',
        'notes',
        'perceived_exertion',
    }
    missing_session_columns = required_session_columns - session_columns
    if missing_session_columns:
        alterable = {'notes', 'perceived_exertion'}
        for column in sorted(missing_session_columns & alterable):
            column_type = 'TEXT' if column == 'notes' else 'INTEGER'
            cursor.execute(f'ALTER TABLE exercise_session ADD COLUMN {column} {column_type};')
        remaining_missing = missing_session_columns - alterable
        if remaining_missing:
            raise RuntimeError(
                'Existing exercise_session table missing non-optional columns: '
                + ', '.join(sorted(remaining_missing))
            )


def migrate(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    columns = [row[1] for row in c.execute("PRAGMA table_info(exercise)").fetchall()]
    already_migrated = 'training_plan_id' not in columns

    if already_migrated:
        ensure_plan_exercises_schema(c)
        ensure_exercise_session_schema(c)
        conn.commit()
        print('Database already migrated.')
        conn.close()
        return

    c.execute('ALTER TABLE exercise RENAME TO exercise_old;')
    c.execute('CREATE TABLE exercise (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT);')
    c.execute('CREATE TABLE plan_exercises (training_plan_id INTEGER NOT NULL, exercise_id INTEGER NOT NULL, PRIMARY KEY(training_plan_id, exercise_id));')
    c.execute('''
        CREATE TABLE IF NOT EXISTS exercise_session (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exercise_id INTEGER NOT NULL,
            repetitions INTEGER NOT NULL,
            weight INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            perceived_exertion INTEGER,
            FOREIGN KEY(exercise_id) REFERENCES exercise(id)
        );
    ''')

    for row in c.execute('SELECT id, name, description, training_plan_id FROM exercise_old;').fetchall():
        ex_id, name, desc, plan_id = row
        c.execute('INSERT INTO exercise (id, name, description) VALUES (?, ?, ?);', (ex_id, name, desc))
        c.execute('INSERT INTO plan_exercises (training_plan_id, exercise_id) VALUES (?, ?);', (plan_id, ex_id))

    conn.commit()
    c.execute('DROP TABLE exercise_old;')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    migrate()
