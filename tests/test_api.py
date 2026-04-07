"""Tests for REST API endpoints."""
import io
import json
import pytest
import datetime
from app import db, User, TrainingPlan, Exercise, ExerciseSession, BodyWeight, AppSettings, ProgressPhoto
from werkzeug.security import generate_password_hash


class TestApiAuth:
    def test_api_register(self, client):
        resp = client.post('/api/register', json={
            'username': 'apiuser',
            'password': 'secure123',
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['message'] == 'registered'

    def test_api_register_short_password(self, client):
        resp = client.post('/api/register', json={
            'username': 'short',
            'password': 'abc',
        })
        assert resp.status_code == 400

    def test_api_login(self, client, regular_user):
        resp = client.post('/api/login', json={
            'username': 'user',
            'password': 'pass123',
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['message'] == 'logged in'

    def test_api_login_wrong_password(self, client, regular_user):
        resp = client.post('/api/login', json={
            'username': 'user',
            'password': 'wrong',
        })
        assert resp.status_code == 401

    def test_api_register_requires_email_when_verification_enabled(self, client):
        db.session.add(AppSettings(require_email_verification=True))
        db.session.commit()
        resp = client.post('/api/register', json={
            'username': 'needsmail',
            'password': 'secure123',
        })
        assert resp.status_code == 400

    def test_api_register_marks_user_unconfirmed_when_verification_enabled(self, client, regular_user):
        db.session.add(AppSettings(require_email_verification=True))
        db.session.commit()
        resp = client.post('/api/register', json={
            'username': 'mailuser',
            'password': 'secure123',
            'email': 'mailuser@example.com',
        })
        assert resp.status_code == 201
        user = User.query.filter_by(username='mailuser').first()
        assert user is not None
        assert user.email_confirmed is False
        assert user.email == 'mailuser@example.com'

    def test_api_login_requires_confirmed_email_when_enabled(self, client):
        db.session.add(AppSettings(require_email_verification=True))
        user = User(
            username='pending',
            password=generate_password_hash('secure123'),
            email='pending@example.com',
            email_confirmed=False,
        )
        db.session.add(user)
        db.session.commit()
        resp = client.post('/api/login', json={
            'username': 'pending',
            'password': 'secure123',
        })
        assert resp.status_code == 403

    def test_api_logout(self, logged_in_client):
        resp = logged_in_client.post('/api/logout')
        assert resp.status_code == 200


class TestApiTrainingPlans:
    def test_list_plans(self, logged_in_client, sample_plan):
        resp = logged_in_client.get('/api/training_plans')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) >= 1

    def test_create_plan(self, logged_in_client):
        resp = logged_in_client.post('/api/training_plans', json={
            'title': 'API Plan',
            'description': 'Via API erstellt',
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['title'] == 'API Plan'

    def test_get_plan_detail(self, logged_in_client, sample_plan):
        resp = logged_in_client.get(f'/api/training_plans/{sample_plan.id}/detail')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['title'] == 'Testplan'

    def test_update_plan(self, logged_in_client, sample_plan):
        resp = logged_in_client.put(f'/api/training_plans/{sample_plan.id}', json={
            'title': 'Umbenannt',
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['title'] == 'Umbenannt'

    def test_delete_plan(self, logged_in_client, sample_plan):
        pid = sample_plan.id
        resp = logged_in_client.delete(f'/api/training_plans/{pid}')
        assert resp.status_code == 200
        assert db.session.get(TrainingPlan, pid) is None

    def test_list_exercises(self, logged_in_client, sample_plan):
        resp = logged_in_client.get(f'/api/training_plans/{sample_plan.id}/exercises')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) >= 1

    def test_add_exercise(self, logged_in_client, sample_plan):
        resp = logged_in_client.post(f'/api/training_plans/{sample_plan.id}/exercises', json={
            'name': 'API Übung',
            'description': 'Test',
        })
        assert resp.status_code == 201

    def test_plan_other_user(self, client, admin_user, sample_plan):
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin_user.id)
        resp = client.get(f'/api/training_plans/{sample_plan.id}/detail')
        assert resp.status_code == 403


class TestApiExercises:
    def test_get_sessions(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        resp = logged_in_client.get(f'/api/exercises/{exercise.id}/sessions')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)

    def test_add_session(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        resp = logged_in_client.post(f'/api/exercises/{exercise.id}/sessions', json={
            'weight': 70,
            'repetitions': 12,
            'notes': 'API Session',
        })
        assert resp.status_code == 201

    def test_add_session_invalid_weight_returns_400(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        resp = logged_in_client.post(f'/api/exercises/{exercise.id}/sessions', json={
            'weight': 'abc',
            'repetitions': 12,
        })
        assert resp.status_code == 400

    def test_update_exercise(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        resp = logged_in_client.put(f'/api/exercises/{exercise.id}', json={
            'name': 'Neuer Name',
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['name'] == 'Neuer Name'

    def test_delete_exercise(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        eid = exercise.id
        resp = logged_in_client.delete(f'/api/exercises/{eid}')
        assert resp.status_code == 200

    def test_delete_session(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        session = ExerciseSession.query.filter_by(exercise_id=exercise.id).first()
        resp = logged_in_client.delete(f'/api/sessions/{session.id}')
        assert resp.status_code == 200


class TestApiBodyWeight:
    def test_get_body_weight(self, logged_in_client):
        resp = logged_in_client.get('/api/body_weight')
        assert resp.status_code == 200

    def test_add_body_weight(self, logged_in_client):
        resp = logged_in_client.post('/api/body_weight', json={
            'weight': 81.5,
            'notes': 'API',
        })
        assert resp.status_code == 201

    def test_delete_body_weight(self, logged_in_client, regular_user):
        entry = BodyWeight(user_id=regular_user.id, weight=80.0)
        db.session.add(entry)
        db.session.commit()
        resp = logged_in_client.delete(f'/api/body_weight/{entry.id}')
        assert resp.status_code == 200


class TestApiCalendar:
    def test_get_calendar(self, logged_in_client):
        resp = logged_in_client.get('/api/calendar')
        assert resp.status_code == 200

    def test_get_calendar_invalid_month(self, logged_in_client):
        resp = logged_in_client.get('/api/calendar?year=2026&month=13')
        assert resp.status_code == 400

    def test_plan_calendar(self, logged_in_client):
        resp = logged_in_client.post('/api/calendar/plan', json={
            'date': '2026-04-15',
        })
        assert resp.status_code in (200, 201)

    def test_unplan_calendar(self, logged_in_client):
        logged_in_client.post('/api/calendar/plan', json={'date': '2026-04-15'})
        resp = logged_in_client.post('/api/calendar/unplan', json={
            'date': '2026-04-15',
        })
        assert resp.status_code == 200


class TestApiDashboard:
    def test_dashboard(self, logged_in_client, sample_plan):
        resp = logged_in_client.get('/api/dashboard')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'streak' in data
        assert 'training_plans' in data

    def test_statistics(self, logged_in_client, sample_plan):
        resp = logged_in_client.get('/api/statistics')
        assert resp.status_code == 200

    def test_achievements(self, logged_in_client, sample_plan):
        resp = logged_in_client.get('/api/achievements')
        assert resp.status_code == 200


class TestApiExport:
    def test_export(self, logged_in_client, sample_plan):
        resp = logged_in_client.get('/api/export')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'training_plans' in data


class TestApiProgressPhotos:
    def test_upload_progress_photo_invalid_body_weight(self, logged_in_client, app, tmp_path, regular_user):
        app.config['UPLOAD_FOLDER'] = str(tmp_path)
        resp = logged_in_client.post(
            '/api/progress_photos',
            data={
                'photo': (io.BytesIO(b'fake-image'), 'progress.jpg'),
                'body_weight': 'abc',
            },
            content_type='multipart/form-data',
        )
        assert resp.status_code == 400
        assert ProgressPhoto.query.filter_by(user_id=regular_user.id).count() == 0
        assert list(tmp_path.iterdir()) == []


class TestApiRequiresAuth:
    """Verify API endpoints reject unauthenticated requests."""
    def test_plans_require_auth(self, client):
        resp = client.get('/api/training_plans')
        assert resp.status_code == 302

    def test_body_weight_requires_auth(self, client):
        resp = client.get('/api/body_weight')
        assert resp.status_code == 302

    def test_dashboard_requires_auth(self, client):
        resp = client.get('/api/dashboard')
        assert resp.status_code == 302
