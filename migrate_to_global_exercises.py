import sqlite3

DB_PATH = 'fitness.db'

# This simple script migrates the old Exercise table (with training_plan_id)
# to the new global Exercise table with the plan_exercises association table.

def migrate(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # rename old table if it still has training_plan_id column
    columns = [row[1] for row in c.execute("PRAGMA table_info(exercise)").fetchall()]
    if 'training_plan_id' not in columns:
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
