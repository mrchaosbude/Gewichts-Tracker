"""Tests für die neuen Offline-Sync-Endpoints und Deduplication."""
import json
import datetime
import pytest
from app import app, db, User, TrainingPlan, Exercise, ExerciseSession, BodyWeight
from werkzeug.security import generate_password_hash


@pytest.fixture()
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
    with app.app_context():
        db.create_all()
        # Test-User anlegen
        user = User(
            username='synctest',
            password=generate_password_hash('test123'),
            is_admin=False,
        )
        db.session.add(user)
        db.session.flush()
        # Trainingsplan + Übung
        plan = TrainingPlan(title='Testplan', user_id=user.id)
        db.session.add(plan)
        db.session.flush()
        exercise = Exercise(name='Bankdrücken')
        exercise.training_plans.append(plan)
        db.session.add(exercise)
        db.session.commit()

    with app.test_client() as c:
        with c.session_transaction() as sess:
            with app.app_context():
                u = User.query.filter_by(username='synctest').first()
                sess['_user_id'] = str(u.id)
        yield c

    with app.app_context():
        db.drop_all()


def _get_exercise_id(client):
    with app.app_context():
        u = User.query.filter_by(username='synctest').first()
        plan = TrainingPlan.query.filter_by(user_id=u.id).first()
        return plan.exercises[0].id


# =============================================
# /sync Endpoint
# =============================================

class TestSyncSessions:
    def test_sync_session_success(self, client):
        eid = _get_exercise_id(client)
        resp = client.post('/sync', data=json.dumps({
            'sessions': [{
                'uuid': 'sess-001',
                'exercise_id': eid,
                'repetitions': 10,
                'weight': 50,
                'timestamp': datetime.datetime.now().isoformat(),
                'notes': 'Testnotiz',
                'perceived_exertion': 7,
            }]
        }), content_type='application/json')
        data = resp.get_json()
        assert resp.status_code == 200
        assert data['status'] == 'success'
        assert 'sess-001' in data['synced_uuids']
        with app.app_context():
            s = ExerciseSession.query.filter_by(client_uuid='sess-001').first()
            assert s is not None
            assert s.repetitions == 10
            assert s.weight == 50

    def test_sync_dedup(self, client):
        eid = _get_exercise_id(client)
        payload = json.dumps({
            'sessions': [{
                'uuid': 'dedup-001',
                'exercise_id': eid,
                'repetitions': 5,
                'weight': 60,
                'timestamp': datetime.datetime.now().isoformat(),
            }]
        })
        # Erstes Mal
        client.post('/sync', data=payload, content_type='application/json')
        # Zweites Mal (Dedup)
        resp = client.post('/sync', data=json.dumps({
            'sessions': [{
                'uuid': 'dedup-001',
                'exercise_id': eid,
                'repetitions': 99,
                'weight': 999,
                'timestamp': datetime.datetime.now().isoformat(),
            }]
        }), content_type='application/json')
        data = resp.get_json()
        assert data['status'] == 'success'
        assert 'dedup-001' in data['synced_uuids']
        with app.app_context():
            count = ExerciseSession.query.filter_by(client_uuid='dedup-001').count()
            assert count == 1
            s = ExerciseSession.query.filter_by(client_uuid='dedup-001').first()
            assert s.weight == 60  # Original, nicht überschrieben

    def test_sync_invalid_exercise(self, client):
        resp = client.post('/sync', data=json.dumps({
            'sessions': [{
                'uuid': 'bad-ex',
                'exercise_id': 99999,
                'repetitions': 5,
                'weight': 50,
                'timestamp': datetime.datetime.now().isoformat(),
            }]
        }), content_type='application/json')
        assert resp.status_code == 400

    def test_sync_invalid_json_returns_400(self, client):
        resp = client.post('/sync', data='not-json', content_type='application/json')
        assert resp.status_code == 400

    def test_sync_multiple_sessions(self, client):
        eid = _get_exercise_id(client)
        resp = client.post('/sync', data=json.dumps({
            'sessions': [
                {'uuid': 'multi-1', 'exercise_id': eid, 'repetitions': 10, 'weight': 40, 'timestamp': datetime.datetime.now().isoformat()},
                {'uuid': 'multi-2', 'exercise_id': eid, 'repetitions': 8, 'weight': 45, 'timestamp': datetime.datetime.now().isoformat()},
            ]
        }), content_type='application/json')
        data = resp.get_json()
        assert data['status'] == 'success'
        assert 'multi-1' in data['synced_uuids']
        assert 'multi-2' in data['synced_uuids']


# =============================================
# /sync_weights Endpoint
# =============================================

class TestSyncWeights:
    def test_sync_weight_success(self, client):
        resp = client.post('/sync_weights', data=json.dumps({
            'weights': [{
                'uuid': 'wt-001',
                'weight': 82.5,
                'notes': 'Morgens',
                'timestamp': datetime.datetime.now().isoformat(),
            }]
        }), content_type='application/json')
        data = resp.get_json()
        assert resp.status_code == 200
        assert data['status'] == 'success'
        assert 'wt-001' in data['synced_uuids']
        with app.app_context():
            w = BodyWeight.query.filter_by(client_uuid='wt-001').first()
            assert w is not None
            assert w.weight == 82.5
            assert w.notes == 'Morgens'

    def test_sync_weight_dedup(self, client):
        payload = json.dumps({
            'weights': [{
                'uuid': 'wt-dedup',
                'weight': 80.0,
                'timestamp': datetime.datetime.now().isoformat(),
            }]
        })
        client.post('/sync_weights', data=payload, content_type='application/json')
        resp = client.post('/sync_weights', data=json.dumps({
            'weights': [{
                'uuid': 'wt-dedup',
                'weight': 999,
                'timestamp': datetime.datetime.now().isoformat(),
            }]
        }), content_type='application/json')
        data = resp.get_json()
        assert data['status'] == 'success'
        with app.app_context():
            count = BodyWeight.query.filter_by(client_uuid='wt-dedup').count()
            assert count == 1
            w = BodyWeight.query.filter_by(client_uuid='wt-dedup').first()
            assert w.weight == 80.0

    def test_sync_weight_validation(self, client):
        resp = client.post('/sync_weights', data=json.dumps({
            'weights': [
                {'uuid': 'too-low', 'weight': 10, 'timestamp': datetime.datetime.now().isoformat()},
                {'uuid': 'too-high', 'weight': 600, 'timestamp': datetime.datetime.now().isoformat()},
                {'uuid': 'no-weight', 'weight': None, 'timestamp': datetime.datetime.now().isoformat()},
                {'uuid': 'valid', 'weight': 75, 'timestamp': datetime.datetime.now().isoformat()},
            ]
        }), content_type='application/json')
        data = resp.get_json()
        assert data['status'] == 'success'
        assert 'valid' in data['synced_uuids']
        assert 'too-low' not in data['synced_uuids']
        assert 'too-high' not in data['synced_uuids']
        assert 'no-weight' not in data['synced_uuids']

    def test_sync_weight_empty(self, client):
        resp = client.post('/sync_weights', data=json.dumps({
            'weights': []
        }), content_type='application/json')
        data = resp.get_json()
        assert resp.status_code == 200
        assert data['status'] == 'success'
        assert data['synced_uuids'] == []

    def test_sync_weights_invalid_json_returns_400(self, client):
        resp = client.post('/sync_weights', data='not-json', content_type='application/json')
        assert resp.status_code == 400

    def test_sync_weight_no_auth(self):
        """Ohne Login sollte /sync_weights fehlschlagen."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
        with app.test_client() as c:
            resp = c.post('/sync_weights', data=json.dumps({
                'weights': [{'uuid': 'noauth', 'weight': 80, 'timestamp': datetime.datetime.now().isoformat()}]
            }), content_type='application/json')
            # Sollte redirect zu Login oder 401/302 sein
            assert resp.status_code in (302, 401)
