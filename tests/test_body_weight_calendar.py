"""Tests for body weight tracking and training calendar routes."""
import pytest
import datetime
from app import db, BodyWeight


class TestBodyWeight:
    def test_body_weight_requires_login(self, client):
        resp = client.get('/body_weight')
        assert resp.status_code == 302

    def test_body_weight_page(self, logged_in_client):
        resp = logged_in_client.get('/body_weight')
        assert resp.status_code == 200

    def test_add_body_weight(self, logged_in_client, regular_user):
        resp = logged_in_client.post('/body_weight', data={
            'weight': '82.5',
            'notes': 'Morgens',
        }, follow_redirects=True)
        assert resp.status_code == 200
        entry = BodyWeight.query.filter_by(user_id=regular_user.id).first()
        assert entry is not None
        assert entry.weight == 82.5

    def test_add_body_weight_invalid(self, logged_in_client, regular_user):
        resp = logged_in_client.post('/body_weight', data={
            'weight': '10',  # zu leicht (min 20)
        }, follow_redirects=True)
        assert resp.status_code == 200
        count = BodyWeight.query.filter_by(user_id=regular_user.id).count()
        assert count == 0

    def test_delete_body_weight(self, logged_in_client, regular_user):
        entry = BodyWeight(user_id=regular_user.id, weight=80.0)
        db.session.add(entry)
        db.session.commit()
        eid = entry.id
        resp = logged_in_client.post(f'/body_weight/{eid}/delete', follow_redirects=True)
        assert resp.status_code == 200
        assert db.session.get(BodyWeight, eid) is None

    def test_delete_body_weight_other_user(self, client, admin_user, regular_user):
        entry = BodyWeight(user_id=regular_user.id, weight=80.0)
        db.session.add(entry)
        db.session.commit()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin_user.id)
        resp = client.post(f'/body_weight/{entry.id}/delete')
        assert resp.status_code == 403

    def test_body_weight_with_chart(self, logged_in_client, regular_user):
        for i in range(3):
            db.session.add(BodyWeight(
                user_id=regular_user.id, weight=80.0 + i,
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(days=i),
            ))
        db.session.commit()
        resp = logged_in_client.get('/body_weight')
        assert resp.status_code == 200


class TestCalendar:
    def test_calendar_requires_login(self, client):
        resp = client.get('/calendar')
        assert resp.status_code == 302

    def test_calendar_loads(self, logged_in_client):
        resp = logged_in_client.get('/calendar')
        assert resp.status_code == 200

    def test_calendar_with_params(self, logged_in_client):
        resp = logged_in_client.get('/calendar?year=2026&month=3')
        assert resp.status_code == 200

    def test_calendar_invalid_month(self, logged_in_client):
        resp = logged_in_client.get('/calendar?year=2026&month=13')
        assert resp.status_code == 400

    def test_plan_training(self, logged_in_client):
        resp = logged_in_client.post('/calendar/plan', data={
            'date': '2026-04-10',
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_unplan_training(self, logged_in_client):
        logged_in_client.post('/calendar/plan', data={'date': '2026-04-10'})
        resp = logged_in_client.post('/calendar/unplan', data={
            'date': '2026-04-10',
        }, follow_redirects=True)
        assert resp.status_code == 200
