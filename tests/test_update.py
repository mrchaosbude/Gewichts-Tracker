"""update.py must bring a very old database to the current schema without losing data."""
import os
import sqlite3
import subprocess
import sys

from env_config import parse_env_file, update_env_file

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OLD_SCHEMA = """
CREATE TABLE user (id INTEGER PRIMARY KEY, username VARCHAR(150) NOT NULL UNIQUE, password VARCHAR(150) NOT NULL,
                   registration_date DATETIME, last_login DATETIME, is_admin BOOLEAN, is_trainer BOOLEAN);
CREATE TABLE training_plan (id INTEGER PRIMARY KEY, title VARCHAR(150) NOT NULL, description VARCHAR(300),
                            user_id INTEGER NOT NULL);
CREATE TABLE exercise (id INTEGER PRIMARY KEY, name VARCHAR(150) NOT NULL, description VARCHAR(300),
                       training_plan_id INTEGER NOT NULL);
CREATE TABLE exercise_session (id INTEGER PRIMARY KEY, exercise_id INTEGER NOT NULL, repetitions INTEGER NOT NULL,
                               weight INTEGER NOT NULL, timestamp DATETIME);
INSERT INTO user VALUES (1, 'alt', 'x', NULL, NULL, 1, 0);
INSERT INTO training_plan VALUES (1, 'Plan', NULL, 1);
INSERT INTO exercise VALUES (1, 'Kniebeuge', NULL, 1);
INSERT INTO exercise_session VALUES (1, 1, 5, 100, '2025-01-01 10:00:00');
"""


def _run_update(db_path, tmp_path, *extra):
    env = dict(
        os.environ,
        SECRET_KEY='0123456789abcdef0123456789abcdef',
        SESSION_COOKIE_SECURE='false',
        GEWICHTS_TRACKER_UPLOAD_FOLDER=str(tmp_path / 'photos'),
        PYTHONIOENCODING='utf-8',
    )
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, 'update.py'), '--yes', '--db', str(db_path), *extra],
        env=env, capture_output=True, text=True, encoding='utf-8', timeout=120,
    )


def test_update_migrates_old_database(tmp_path):
    db_path = tmp_path / 'fitness.db'
    conn = sqlite3.connect(db_path)
    conn.executescript(OLD_SCHEMA)
    conn.close()

    dry = _run_update(db_path, tmp_path, '--dry-run')
    assert dry.returncode == 0, dry.stdout + dry.stderr
    conn = sqlite3.connect(db_path)
    assert 'training_plan_id' in [r[1] for r in conn.execute('PRAGMA table_info(exercise)')]  # unverändert
    conn.close()

    first = _run_update(db_path, tmp_path)
    assert first.returncode == 0, first.stdout + first.stderr
    second = _run_update(db_path, tmp_path)  # idempotent
    assert second.returncode == 0, second.stdout + second.stderr

    conn = sqlite3.connect(db_path)
    session_cols = {r[1]: r for r in conn.execute('PRAGMA table_info(exercise_session)')}
    assert {'user_id', 'client_uuid', 'duration_minutes', 'notes'} <= set(session_cols)
    assert session_cols['weight'][3] == 0 and session_cols['repetitions'][3] == 0  # nullable
    assert conn.execute('SELECT weight, repetitions, user_id FROM exercise_session').fetchall() == [(100, 5, 1)]
    assert conn.execute('SELECT training_plan_id, exercise_id FROM plan_exercises').fetchall() == [(1, 1)]
    assert conn.execute('SELECT user_id, exercise_type FROM exercise').fetchall() == [(1, 'kraft')]
    assert conn.execute('SELECT email_confirmed FROM user').fetchone()[0] == 1
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {'body_weight', 'progress_photo', 'app_settings', 'planned_training'} <= tables
    conn.close()
    assert len(list((tmp_path / 'backups').iterdir())) == 2


def test_env_file_roundtrip(tmp_path):
    path = str(tmp_path / '.env')
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write('# Kommentar\nFOO="bar"\nSECRET_KEY=alt\n')
    update_env_file({'SECRET_KEY': 'neu', 'EXTRA': '1'}, path)
    assert parse_env_file(path) == {'FOO': 'bar', 'SECRET_KEY': 'neu', 'EXTRA': '1'}
    assert open(path, encoding='utf-8').read().startswith('# Kommentar\n')
