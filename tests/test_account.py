"""Account self-service: change password/e-mail, forgot password, session invalidation."""
import re

import pytest
from flask import g
from werkzeug.security import check_password_hash, generate_password_hash

import app as app_module
from gewichts_tracker import mail, security
from gewichts_tracker.views import auth as auth_views
from app import User, db, make_password_reset_token, verify_password_reset_token


def _fresh(client_or_none=None):
    """The app fixture keeps one app context open; Flask-Login caches the user in g."""
    g.pop('_login_user', None)


@pytest.fixture()
def user(app):
    u = User(username='anna', password=generate_password_hash('altes-passwort'), email='anna@example.com')
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture()
def smtp(app, monkeypatch):
    """Pretend SMTP is configured and capture outgoing mails."""
    settings = app_module.get_app_settings()
    settings.smtp_server = 'smtp.example.com'
    settings.smtp_sender_email = 'noreply@example.com'
    settings.base_url = 'https://fit.example.test'
    db.session.commit()
    sent = []
    monkeypatch.setattr(mail, 'send_app_email', lambda to, subject, body: sent.append((to, subject, body)) or True)
    auth_views._reset_mail_last_sent.clear()
    return sent


def _login(client, u):
    with client.session_transaction() as sess:
        sess['_user_id'] = u.get_id()
    _fresh()


class TestChangePassword:
    def test_requires_login(self, client):
        assert client.get('/account').status_code in (302, 401)

    def test_change_password(self, client, user):
        _login(client, user)
        assert client.get('/account').status_code == 200
        resp = client.post('/account/password', data={
            'pw-current_password': 'altes-passwort', 'pw-new_password': 'neues-passwort', 'pw-confirm': 'neues-passwort'})
        assert resp.status_code == 302
        assert check_password_hash(db.session.get(User, user.id).password, 'neues-passwort')
        _fresh()
        assert client.get('/account').status_code == 200  # eigene Sitzung bleibt gültig

    @pytest.mark.parametrize('data', [
        {'pw-current_password': 'falsch', 'pw-new_password': 'neues-passwort', 'pw-confirm': 'neues-passwort'},
        {'pw-current_password': 'altes-passwort', 'pw-new_password': 'kurz', 'pw-confirm': 'kurz'},
        {'pw-current_password': 'altes-passwort', 'pw-new_password': 'neues-passwort', 'pw-confirm': 'anders-passwort'},
    ])
    def test_rejects_bad_input(self, client, user, data):
        _login(client, user)
        assert client.post('/account/password', data=data).status_code == 400
        assert check_password_hash(db.session.get(User, user.id).password, 'altes-passwort')

    def test_other_sessions_are_logged_out(self, app, client, user):
        other_device = app.test_client()
        _login(other_device, user)
        assert other_device.get('/dashboard').status_code == 200
        _login(client, user)
        client.post('/account/password', data={
            'pw-current_password': 'altes-passwort', 'pw-new_password': 'neues-passwort', 'pw-confirm': 'neues-passwort'})
        _fresh()
        assert other_device.get('/dashboard').status_code in (302, 401)

    def test_admin_password_change_logs_user_out(self, app, client, user, admin_user):
        victim_device = app.test_client()
        _login(victim_device, user)
        _login(client, admin_user)
        client.post(f'/admin/user/{user.id}/change_password', data={'new_password': 'vom-admin-gesetzt', 'confirm': 'vom-admin-gesetzt'})
        _fresh()
        assert victim_device.get('/dashboard').status_code in (302, 401)

    def test_session_without_fingerprint_is_rejected(self, client, user):
        with client.session_transaction() as sess:
            sess['_user_id'] = f'{user.id}'  # altes Format ohne Passwort-Fingerabdruck
        _fresh()
        assert client.get('/dashboard').status_code in (302, 401)

    def test_api_change_password(self, client, user):
        _login(client, user)
        assert client.post('/api/account/password', json={'current_password': 'falsch', 'new_password': 'neues-passwort'}).status_code == 403
        assert client.post('/api/account/password', json={'current_password': 'altes-passwort', 'new_password': 'kurz'}).status_code == 400
        assert client.post('/api/account/password', json={'current_password': 'altes-passwort', 'new_password': 'neues-passwort'}).status_code == 200
        assert check_password_hash(db.session.get(User, user.id).password, 'neues-passwort')


class TestChangeEmail:
    def test_change_email(self, client, user):
        _login(client, user)
        resp = client.post('/account/email', data={'mail-email': 'neu@example.com', 'mail-current_password': 'altes-passwort'})
        assert resp.status_code == 302
        assert db.session.get(User, user.id).email == 'neu@example.com'

    @pytest.mark.parametrize('email,password', [
        ('neu@example.com', 'falsch'),
        ('keine-adresse', 'altes-passwort'),
        ('BELEGT@example.com', 'altes-passwort'),
    ])
    def test_rejects_bad_input(self, client, user, email, password):
        db.session.add(User(username='bob', password='x', email='belegt@example.com'))
        db.session.commit()
        _login(client, user)
        resp = client.post('/account/email', data={'mail-email': email, 'mail-current_password': password})
        assert resp.status_code == 400
        assert db.session.get(User, user.id).email == 'anna@example.com'


class TestForgotPassword:
    def _token_from(self, sent):
        return re.search(r'/reset-password/([^"<\s]+)', sent[-1][2]).group(1)

    def test_full_flow(self, client, user, smtp):
        resp = client.post('/forgot-password', data={'identifier': 'anna'})
        assert resp.status_code == 302
        assert len(smtp) == 1 and smtp[0][0] == 'anna@example.com'
        token = self._token_from(smtp)

        assert client.get(f'/reset-password/{token}').status_code == 200
        resp = client.post(f'/reset-password/{token}', data={'new_password': 'ganz-neues-pw', 'confirm': 'ganz-neues-pw'})
        assert resp.status_code == 302
        assert check_password_hash(db.session.get(User, user.id).password, 'ganz-neues-pw')
        # Link ist nur einmal verwendbar
        assert client.get(f'/reset-password/{token}').status_code == 302
        assert verify_password_reset_token(token) is None

    def test_lookup_by_email_and_cooldown(self, client, user, smtp):
        client.post('/forgot-password', data={'identifier': 'ANNA@example.com'})
        client.post('/forgot-password', data={'identifier': 'anna'})
        assert len(smtp) == 1  # zweite Anfrage innerhalb der Sperrzeit sendet nichts

    def test_unknown_user_gets_same_response(self, client, user, smtp):
        known = client.post('/forgot-password', data={'identifier': 'anna'})
        unknown = client.post('/forgot-password', data={'identifier': 'gibtsnicht'})
        assert known.status_code == unknown.status_code == 302
        assert known.headers['Location'] == unknown.headers['Location']
        assert len(smtp) == 1

    def test_user_without_email_gets_no_mail(self, client, user, smtp):
        user.email = None
        db.session.commit()
        client.post('/forgot-password', data={'identifier': 'anna'})
        assert smtp == []

    def test_not_available_without_smtp(self, client, user):
        resp = client.get('/forgot-password')
        assert resp.status_code == 200
        assert 'nicht eingerichtet' in resp.get_data(as_text=True)

    def test_invalid_and_expired_tokens(self, client, user, monkeypatch):
        assert client.get('/reset-password/unsinn').status_code == 302
        token = make_password_reset_token(user)
        assert verify_password_reset_token(token).id == user.id
        monkeypatch.setattr(security, 'PASSWORD_RESET_MAX_AGE', -1)
        assert verify_password_reset_token(token) is None

    def test_token_of_other_secret_is_rejected(self, app, user):
        from itsdangerous import URLSafeTimedSerializer
        forged = URLSafeTimedSerializer('anderer-key', salt='password-reset').dumps({'uid': user.id, 'fp': 'x'})
        assert verify_password_reset_token(forged) is None
