"""Tests for training plan CRUD routes."""
import pytest
from app import db, TrainingPlan, Exercise, User
from werkzeug.security import generate_password_hash


class TestCreatePlan:
    def test_create_plan_page(self, logged_in_client):
        resp = logged_in_client.get('/create_training_plan')
        assert resp.status_code == 200

    def test_create_plan_success(self, logged_in_client, regular_user):
        resp = logged_in_client.post('/create_training_plan', data={
            'title': 'Neuer Plan',
            'description': 'Testbeschreibung',
        }, follow_redirects=True)
        assert resp.status_code == 200
        plan = TrainingPlan.query.filter_by(title='Neuer Plan').first()
        assert plan is not None
        assert plan.user_id == regular_user.id

    def test_create_plan_requires_login(self, client):
        resp = client.post('/create_training_plan', data={'title': 'X'})
        assert resp.status_code == 302


class TestPlanDetail:
    def test_plan_detail(self, logged_in_client, sample_plan):
        resp = logged_in_client.get(f'/training_plan/{sample_plan.id}')
        assert resp.status_code == 200
        assert b'Testplan' in resp.data

    def test_plan_detail_other_user(self, client, admin_user, sample_plan):
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin_user.id)
        resp = client.get(f'/training_plan/{sample_plan.id}')
        assert resp.status_code == 403

    def test_plan_detail_not_found(self, logged_in_client):
        resp = logged_in_client.get('/training_plan/99999')
        assert resp.status_code == 404


class TestDeletePlan:
    def test_delete_plan(self, logged_in_client, sample_plan):
        plan_id = sample_plan.id
        resp = logged_in_client.post(f'/training_plan/{plan_id}/delete', follow_redirects=True)
        assert resp.status_code == 200
        assert db.session.get(TrainingPlan, plan_id) is None

    def test_delete_plan_other_user(self, client, admin_user, sample_plan):
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin_user.id)
        resp = client.post(f'/training_plan/{sample_plan.id}/delete')
        assert resp.status_code == 403


class TestSharePlan:
    def test_share_plan(self, logged_in_client, sample_plan):
        resp = logged_in_client.post(f'/training_plan/{sample_plan.id}/share', follow_redirects=True)
        assert resp.status_code == 200
        db.session.refresh(sample_plan)
        assert sample_plan.share_token is not None

    def test_unshare_plan(self, logged_in_client, sample_plan):
        logged_in_client.post(f'/training_plan/{sample_plan.id}/share')
        resp = logged_in_client.post(f'/training_plan/{sample_plan.id}/unshare', follow_redirects=True)
        assert resp.status_code == 200
        db.session.refresh(sample_plan)
        assert sample_plan.share_token is None

    def test_copy_shared_plan(self, app, admin_user, logged_in_client, sample_plan):
        # Share plan first as regular user
        logged_in_client.post(f'/training_plan/{sample_plan.id}/share')
        db.session.refresh(sample_plan)
        token = sample_plan.share_token
        assert token is not None
        # Login as admin via POST (session_transaction _user_id switch
        # doesn't update Flask-Login's current_user after prior requests)
        with app.test_client() as other_client:
            other_client.post('/login', data={'username': 'admin', 'password': 'admin123'})
            resp = other_client.get(f'/shared/{token}')
            assert resp.status_code == 302
        copied = TrainingPlan.query.filter_by(user_id=admin_user.id).first()
        assert copied is not None
        assert 'kopiert' in copied.title


class TestPrintPlan:
    def test_print_plan(self, logged_in_client, sample_plan):
        resp = logged_in_client.get(f'/training_plan/{sample_plan.id}/print')
        assert resp.status_code == 200

    def test_print_plan_with_sessions(self, logged_in_client, sample_plan):
        resp = logged_in_client.get(f'/training_plan/{sample_plan.id}/print?include_sessions=1')
        assert resp.status_code == 200
