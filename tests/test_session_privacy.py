import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import app, db, User, TrainingPlan, Exercise, ExerciseSession, generate_password_hash


@pytest.fixture
def client_with_shared_exercise():
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
        WTF_CSRF_ENABLED=False,
    )

    with app.app_context():
        db.drop_all()
        db.create_all()

        user_a = User(username='alice', password=generate_password_hash('secret-a'))
        user_b = User(username='bob', password=generate_password_hash('secret-b'))
        db.session.add_all([user_a, user_b])
        db.session.commit()

        plan_a = TrainingPlan(title='Plan A', description='', user_id=user_a.id)
        plan_b = TrainingPlan(title='Plan B', description='', user_id=user_b.id)
        db.session.add_all([plan_a, plan_b])
        db.session.flush()

        shared_exercise = Exercise(name='Bankdrücken', description='Flachbank')
        db.session.add(shared_exercise)
        db.session.flush()

        plan_a.exercises.append(shared_exercise)
        plan_b.exercises.append(shared_exercise)
        db.session.flush()

        session_a = ExerciseSession(
            exercise_id=shared_exercise.id,
            repetitions=8,
            weight=80,
            user_id=user_a.id,
        )
        session_b = ExerciseSession(
            exercise_id=shared_exercise.id,
            repetitions=5,
            weight=100,
            user_id=user_b.id,
        )
        db.session.add_all([session_a, session_b])
        db.session.commit()

        exercise_id = shared_exercise.id

    with app.test_client() as client:
        yield client, exercise_id


def test_users_only_see_their_own_sessions(client_with_shared_exercise):
    client, exercise_id = client_with_shared_exercise

    login_a = client.post('/api/login', json={'username': 'alice', 'password': 'secret-a'})
    assert login_a.status_code == 200

    response_a = client.get(f'/api/exercises/{exercise_id}/sessions')
    assert response_a.status_code == 200
    data_a = response_a.get_json()
    assert [entry['weight'] for entry in data_a] == [80]

    client.post('/api/logout')

    login_b = client.post('/api/login', json={'username': 'bob', 'password': 'secret-b'})
    assert login_b.status_code == 200

    response_b = client.get(f'/api/exercises/{exercise_id}/sessions')
    assert response_b.status_code == 200
    data_b = response_b.get_json()
    assert [entry['weight'] for entry in data_b] == [100]
