import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import (
    app,
    db,
    User,
    TrainingPlan,
    Exercise,
    ExerciseSession,
    generate_password_hash,
)


@pytest.fixture
def client():
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
        WTF_CSRF_ENABLED=False,
    )
    with app.app_context():
        db.drop_all()
        db.create_all()
        user = User(username='tester', password=generate_password_hash('secret'))
        db.session.add(user)
        db.session.commit()

        plan = TrainingPlan(title='Hypertrophy', description='8 Wochen', user_id=user.id)
        db.session.add(plan)
        db.session.flush()

        exercise = Exercise(name='Kniebeuge', description='Langhantel')
        db.session.add(exercise)
        db.session.flush()
        plan.exercises.append(exercise)
        db.session.flush()

        session = ExerciseSession(
            exercise_id=exercise.id,
            repetitions=5,
            weight=100,
            notes='Saubere Technik',
            perceived_exertion=8,
        )
        db.session.add(session)
        db.session.commit()

    with app.test_client() as client:
        response = client.post('/api/login', json={'username': 'tester', 'password': 'secret'})
        assert response.status_code == 200
        yield client


def test_json_export_contains_expected_structure(client):
    response = client.get('/export/training-data')
    assert response.status_code == 200
    payload = json.loads(response.data)
    assert payload['format'] == 'json'
    assert len(payload['training_plans']) == 1
    plan = payload['training_plans'][0]
    assert plan['title'] == 'Hypertrophy'
    assert plan['exercises'][0]['sessions'][0]['weight'] == 100


def test_csv_export_returns_rows(client):
    response = client.get('/export/training-data?format=csv')
    assert response.status_code == 200
    body = response.data.decode('utf-8')
    lines = [line for line in body.splitlines() if line.strip()]
    assert lines[0].startswith('plan_id')
    assert any('Hypertrophy' in line for line in lines[1:])
