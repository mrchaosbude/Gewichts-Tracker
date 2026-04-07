"""Tests for exercise and session CRUD routes."""
import pytest
from app import db, Exercise, ExerciseSession


class TestAddExercise:
    def test_add_exercise_page(self, logged_in_client, sample_plan):
        resp = logged_in_client.get(f'/training_plan/{sample_plan.id}/add_exercise')
        assert resp.status_code == 200

    def test_add_exercise_success(self, logged_in_client, sample_plan):
        resp = logged_in_client.post(f'/training_plan/{sample_plan.id}/add_exercise', data={
            'name': 'Kniebeugen',
            'description': 'Beine',
            'muscle_group': 'Beine',
        }, follow_redirects=True)
        assert resp.status_code == 200
        ex = Exercise.query.filter_by(name='Kniebeugen').first()
        assert ex is not None


class TestExerciseDetail:
    def test_exercise_detail(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        resp = logged_in_client.get(f'/exercise/{exercise.id}/detail')
        assert resp.status_code == 200

    def test_exercise_detail_other_user(self, client, admin_user, sample_plan):
        exercise = sample_plan.exercises[0]
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin_user.id)
        resp = client.get(f'/exercise/{exercise.id}/detail')
        assert resp.status_code == 403


class TestEditExercise:
    def test_edit_exercise_page(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        resp = logged_in_client.get(f'/exercise/{exercise.id}/edit')
        assert resp.status_code == 200

    def test_edit_exercise_success(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        resp = logged_in_client.post(f'/exercise/{exercise.id}/edit', data={
            'name': 'Neuer Name',
            'description': 'Neue Beschreibung',
        }, follow_redirects=True)
        assert resp.status_code == 200
        db.session.refresh(exercise)
        assert exercise.name == 'Neuer Name'


class TestDeleteExercise:
    def test_delete_exercise(self, logged_in_client, sample_plan, regular_user):
        exercise = sample_plan.exercises[0]
        eid = exercise.id
        resp = logged_in_client.post(f'/exercise/{eid}/delete', follow_redirects=True)
        assert resp.status_code == 200
        assert db.session.get(Exercise, eid) is None


class TestAddSession:
    def test_add_session_page(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        resp = logged_in_client.get(f'/exercise/{exercise.id}/add_session')
        assert resp.status_code == 200

    def test_add_session_kraft(self, logged_in_client, sample_plan, regular_user):
        exercise = sample_plan.exercises[0]
        before = ExerciseSession.query.filter_by(exercise_id=exercise.id, user_id=regular_user.id).count()
        resp = logged_in_client.post(f'/exercise/{exercise.id}/add_session', data={
            'weight': '80.0',
            'repetitions': '8',
            'perceived_exertion': '7',
            'notes': 'Gut',
        }, follow_redirects=True)
        assert resp.status_code == 200
        after = ExerciseSession.query.filter_by(exercise_id=exercise.id, user_id=regular_user.id).count()
        assert after == before + 1

    def test_add_session_cardio(self, logged_in_client, sample_plan, regular_user):
        cardio = [e for e in sample_plan.exercises if e.exercise_type == 'ausdauer'][0]
        resp = logged_in_client.post(f'/exercise/{cardio.id}/add_session', data={
            'duration_minutes': '30',
            'distance_km': '5.5',
        }, follow_redirects=True)
        assert resp.status_code == 200


class TestDeleteSession:
    def test_delete_session(self, logged_in_client, sample_plan, regular_user):
        exercise = sample_plan.exercises[0]
        session = ExerciseSession.query.filter_by(exercise_id=exercise.id).first()
        sid = session.id
        resp = logged_in_client.post(f'/session/{sid}/delete', follow_redirects=True)
        assert resp.status_code == 200
        assert db.session.get(ExerciseSession, sid) is None

    def test_delete_session_other_user(self, client, admin_user, sample_plan):
        exercise = sample_plan.exercises[0]
        session = ExerciseSession.query.filter_by(exercise_id=exercise.id).first()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin_user.id)
        resp = client.post(f'/session/{session.id}/delete')
        assert resp.status_code == 403
