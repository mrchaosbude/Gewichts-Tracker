"""Tests for authentication routes: register, login, logout, email confirmation."""
import pytest
from app import db, User
from werkzeug.security import generate_password_hash


class TestIndex:
    def test_index_unauthenticated(self, client):
        resp = client.get('/')
        assert resp.status_code == 200

    def test_index_authenticated_redirects(self, logged_in_client):
        resp = logged_in_client.get('/')
        assert resp.status_code == 302
        assert '/dashboard' in resp.headers['Location']


class TestRegister:
    def test_register_page(self, client):
        resp = client.get('/register')
        assert resp.status_code == 200

    def test_register_success(self, client):
        resp = client.post('/register', data={
            'username': 'newuser',
            'password': 'securepass123',
            'confirm': 'securepass123',
        }, follow_redirects=True)
        assert resp.status_code == 200
        user = User.query.filter_by(username='newuser').first()
        assert user is not None

    def test_register_short_password(self, client):
        resp = client.post('/register', data={
            'username': 'shortpw',
            'password': 'abc',
            'confirm': 'abc',
        }, follow_redirects=True)
        assert resp.status_code == 200
        user = User.query.filter_by(username='shortpw').first()
        assert user is None

    def test_register_duplicate_username(self, client, regular_user):
        resp = client.post('/register', data={
            'username': 'user',
            'password': 'pass12345',
            'confirm': 'pass12345',
        }, follow_redirects=True)
        assert resp.status_code == 200
        count = User.query.filter_by(username='user').count()
        assert count == 1

    def test_register_password_mismatch(self, client):
        resp = client.post('/register', data={
            'username': 'mismatch',
            'password': 'pass12345',
            'confirm': 'different',
        }, follow_redirects=True)
        assert resp.status_code == 200
        user = User.query.filter_by(username='mismatch').first()
        assert user is None


class TestLogin:
    def test_login_page(self, client):
        resp = client.get('/login')
        assert resp.status_code == 200

    def test_login_success(self, client, regular_user):
        resp = client.post('/login', data={
            'username': 'user',
            'password': 'pass123',
        })
        assert resp.status_code == 302  # redirect to dashboard

    def test_login_wrong_password(self, client, regular_user):
        resp = client.post('/login', data={
            'username': 'user',
            'password': 'wrongpass',
        }, follow_redirects=True)
        assert resp.status_code == 200  # stays on login page

    def test_login_nonexistent_user(self, client):
        resp = client.post('/login', data={
            'username': 'ghost',
            'password': 'pass123',
        }, follow_redirects=True)
        assert resp.status_code == 200


class TestLogout:
    def test_logout(self, logged_in_client):
        resp = logged_in_client.get('/logout')
        assert resp.status_code == 302

    def test_logout_unauthenticated(self, client):
        resp = client.get('/logout')
        assert resp.status_code == 302  # redirect to login


class TestEmailConfirmation:
    def test_confirm_invalid_token(self, client):
        resp = client.get('/confirm/invalidtoken', follow_redirects=True)
        assert resp.status_code == 200

    def test_confirm_expired_token(self, client):
        import datetime, secrets
        user = User(
            username='unconfirmed',
            password=generate_password_hash('pass123'),
            email='test@test.com',
            email_token=secrets.token_urlsafe(32),
            email_token_created=datetime.datetime.utcnow() - datetime.timedelta(hours=25),
        )
        db.session.add(user)
        db.session.commit()
        resp = client.get(f'/confirm/{user.email_token}', follow_redirects=True)
        assert resp.status_code == 200
        db.session.refresh(user)
        assert user.email_confirmed is not True
