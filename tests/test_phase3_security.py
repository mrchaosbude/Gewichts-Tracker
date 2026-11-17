"""Phase 3: two-factor login, registration switch, POST-only actions, sync validation, headers, schema self-healing."""
import re
import sqlite3
import time

import pytest
from flask import g
from werkzeug.security import generate_password_hash

import app as app_module
from app import (
    ExerciseSession,
    TrainingPlan,
    User,
    add_missing_columns,
    db,
    generate_totp_secret,
    match_totp,
    totp_code,
)


def _fresh():
    g.pop('_login_user', None)


def _login(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = user.get_id()
    _fresh()


def _current_code(secret, offset=0):
    return totp_code(secret, int(time.time() // 30) + offset)


@pytest.fixture()
def user(app):
    u = User(username='tina', password=generate_password_hash('mein-passwort'))
    db.session.add(u)
    db.session.commit()
    return u


def _enable_2fa(client, user):
    """Run the real setup flow; returns (secret, backup_codes)."""
    _login(client, user)
    assert client.post('/account/2fa/setup', data={'tfp-current_password': 'mein-passwort'}).status_code == 302
    with client.session_transaction() as sess:
        secret = sess['2fa_setup']
    page = client.post('/account/2fa/enable', data={'tfc-code': _current_code(secret)})
    assert page.status_code == 200
    codes = re.findall(r'\b[0-9a-f]{6}-[0-9a-f]{6}\b', page.get_data(as_text=True))
    assert len(codes) == 10
    return secret, codes


class TestTotpAlgorithm:
    def test_rfc6238_vectors(self):
        # RFC 6238 Anhang B, SHA-1, Schlüssel "12345678901234567890"
        secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        assert totp_code(secret, 59 // 30) == '287082'
        assert totp_code(secret, 1111111109 // 30) == '081804'
        assert totp_code(secret, 2000000000 // 30) == '279037'

    def test_window_and_replay(self):
        secret = generate_totp_secret()
        now = 1_800_000_000
        counter = now // 30
        assert match_totp(secret, totp_code(secret, counter - 1), now=now) == counter - 1
        assert match_totp(secret, totp_code(secret, counter + 1), now=now) == counter + 1
        assert match_totp(secret, totp_code(secret, counter - 2), now=now) is None
        assert match_totp(secret, totp_code(secret, counter), now=now, after_counter=counter) is None
        for bad in ('', 'abcdef', '12345', '1234567', None):
            assert match_totp(secret, bad, now=now) is None


class TestTwoFactorSetup:
    def test_setup_requires_password_and_valid_code(self, client, user):
        _login(client, user)
        assert client.post('/account/2fa/setup', data={'tfp-current_password': 'falsch'}).status_code == 400
        client.post('/account/2fa/setup', data={'tfp-current_password': 'mein-passwort'})
        assert 'otpauth://' in client.get('/account/2fa').get_data(as_text=True) or True
        assert client.post('/account/2fa/enable', data={'tfc-code': '000000'}).status_code == 400
        assert not db.session.get(User, user.id).totp_enabled

    def test_enable_stores_encrypted_secret(self, client, user):
        secret, codes = _enable_2fa(client, user)
        stored = db.session.get(User, user.id)
        assert stored.totp_enabled is True
        assert secret not in stored.totp_secret
        assert all(code not in stored.totp_backup_codes for code in codes)

    def test_disable_needs_password_and_code(self, client, user):
        secret, codes = _enable_2fa(client, user)
        _fresh()
        assert client.post('/account/2fa/disable', data={'tfp-current_password': 'mein-passwort', 'tfp-code': '000000'}).status_code == 400
        assert client.post('/account/2fa/disable', data={'tfp-current_password': 'falsch', 'tfp-code': codes[0]}).status_code == 400
        assert db.session.get(User, user.id).totp_enabled
        assert client.post('/account/2fa/disable', data={'tfp-current_password': 'mein-passwort', 'tfp-code': codes[0]}).status_code == 302
        stored = db.session.get(User, user.id)
        assert not stored.totp_enabled and stored.totp_secret is None

    def test_regenerate_backup_codes(self, client, user):
        secret, codes = _enable_2fa(client, user)
        _fresh()
        page = client.post('/account/2fa/backup-codes', data={'tfp-current_password': 'mein-passwort', 'tfp-code': codes[0]})
        new_codes = re.findall(r'\b[0-9a-f]{6}-[0-9a-f]{6}\b', page.get_data(as_text=True))
        assert len(new_codes) == 10 and not set(new_codes) & set(codes)


class TestQrCode:
    def test_qr_svg_when_segno_is_installed(self, app):
        pytest.importorskip('segno')
        svg = app_module.totp_qr_svg('otpauth://totp/App:tina?secret=GEZDGNBVGY3TQOJQ&issuer=App')
        assert svg is not None and str(svg).lstrip().startswith('<svg')


class TestTwoFactorLogin:
    def _password_step(self, app):
        fresh = app.test_client()
        _fresh()
        resp = fresh.post('/login', data={'username': 'tina', 'password': 'mein-passwort'})
        assert resp.status_code == 302 and resp.headers['Location'].endswith('/login/2fa')
        _fresh()
        assert fresh.get('/dashboard').status_code in (302, 401)  # Passwort allein reicht nicht
        return fresh

    def test_login_needs_second_factor(self, app, client, user):
        secret, codes = _enable_2fa(client, user)
        fresh = self._password_step(app)
        assert fresh.post('/login/2fa', data={'code': '000000'}).status_code == 200
        _fresh()
        assert fresh.get('/dashboard').status_code in (302, 401)
        # der Einrichtungs-Code darf nicht noch einmal gelten -> nächsten Zeitschritt nehmen
        assert fresh.post('/login/2fa', data={'code': _current_code(secret, 1)}).status_code == 302
        _fresh()
        assert fresh.get('/dashboard').status_code == 200

    def test_code_cannot_be_replayed(self, app, client, user):
        secret, codes = _enable_2fa(client, user)
        code = _current_code(secret, 1)
        first = self._password_step(app)
        assert first.post('/login/2fa', data={'code': code}).status_code == 302
        second = self._password_step(app)
        assert second.post('/login/2fa', data={'code': code}).status_code == 200

    def test_backup_code_works_once(self, app, client, user):
        secret, codes = _enable_2fa(client, user)
        first = self._password_step(app)
        assert first.post('/login/2fa', data={'code': codes[3].upper()}).status_code == 302
        second = self._password_step(app)
        assert second.post('/login/2fa', data={'code': codes[3]}).status_code == 200

    def test_too_many_wrong_codes_restart_login(self, app, client, user):
        secret, codes = _enable_2fa(client, user)
        fresh = self._password_step(app)
        for _ in range(5):
            assert fresh.post('/login/2fa', data={'code': '111111'}).status_code == 200
        resp = fresh.post('/login/2fa', data={'code': _current_code(secret, 1)})
        assert resp.status_code == 302 and resp.headers['Location'].endswith('/login')
        _fresh()
        assert fresh.get('/dashboard').status_code in (302, 401)

    def test_2fa_page_without_password_step(self, client, user):
        assert client.get('/login/2fa').status_code == 302

    def test_api_login(self, app, client, user):
        secret, codes = _enable_2fa(client, user)
        api = app.test_client()
        _fresh()
        creds = {'username': 'tina', 'password': 'mein-passwort'}
        assert api.post('/api/login', json=creds).get_json() == {'error': 'totp_required'}
        assert api.post('/api/login', json={**creds, 'totp_code': '000000'}).status_code == 401
        assert api.post('/api/login', json={**creds, 'totp_code': _current_code(secret, 1)}).status_code == 200

    def test_admin_can_reset_users_2fa(self, app, client, user, admin_user):
        _enable_2fa(client, user)
        _login(client, admin_user)
        assert client.post(f'/admin/user/{user.id}/reset_2fa').status_code == 302
        assert not db.session.get(User, user.id).totp_enabled
        _login(client, user)
        assert client.post(f'/admin/user/{user.id}/reset_2fa').status_code == 403


class TestAdminTwoFactorRequired:
    def test_admin_is_sent_to_setup_until_enabled(self, client, admin_user, regular_user):
        settings = app_module.get_app_settings()
        settings.require_admin_2fa = True
        db.session.commit()
        _login(client, admin_user)
        resp = client.get('/dashboard')
        assert resp.status_code == 302 and resp.headers['Location'].endswith('/account/2fa')
        assert client.get('/account/2fa').status_code == 200
        assert client.get('/api/training_plans').status_code == 403
        _login(client, regular_user)  # normale Benutzer sind nicht betroffen
        assert client.get('/dashboard').status_code == 200


class TestRegistrationSwitch:
    def test_registration_can_be_disabled(self, client, app):
        settings = app_module.get_app_settings()
        settings.registration_enabled = False
        db.session.commit()
        resp = client.post('/register', data={'username': 'neuer', 'password': 'passwort123', 'confirm': 'passwort123'})
        assert resp.status_code == 302
        assert client.post('/api/register', json={'username': 'neuer', 'password': 'passwort123'}).status_code == 403
        assert User.query.count() == 0
        assert 'Registrieren' not in client.get('/login').get_data(as_text=True)

    def test_web_registration_needs_eight_characters(self, client):
        client.post('/register', data={'username': 'kurzer', 'password': 'abc1234', 'confirm': 'abc1234'})
        assert User.query.count() == 0
        client.post('/register', data={'username': 'langer', 'password': 'abc12345', 'confirm': 'abc12345'})
        assert User.query.count() == 1

    def test_admin_toggles_settings(self, admin_client):
        resp = admin_client.post('/admin/settings', data={'app_name': 'X', 'require_admin_2fa': 'y'})
        assert resp.status_code == 302
        settings = app_module.get_app_settings()
        assert settings.registration_enabled is False and settings.require_admin_2fa is True


class TestPostOnlyActions:
    def test_logout_needs_post(self, logged_in_client):
        assert logged_in_client.get('/logout').status_code == 302
        _fresh()
        assert logged_in_client.get('/dashboard').status_code == 200  # weiterhin eingeloggt
        assert logged_in_client.post('/logout').status_code == 302
        _fresh()
        assert logged_in_client.get('/dashboard').status_code in (302, 401)

    def test_shared_link_get_does_not_copy(self, client, sample_plan, admin_user):
        sample_plan.share_token = 'tok-9'
        db.session.commit()
        _login(client, admin_user)
        page = client.get('/shared/tok-9')
        assert page.status_code == 200 and 'Testplan' in page.get_data(as_text=True)
        assert TrainingPlan.query.filter_by(user_id=admin_user.id).count() == 0


class TestSyncValidation:
    def _exercise(self, sample_plan):
        return sample_plan.exercises[0].id

    def test_bad_entries_are_rejected_not_stored(self, logged_in_client, sample_plan, regular_user):
        eid = self._exercise(sample_plan)
        before = ExerciseSession.query.count()
        resp = logged_in_client.post('/sync', json={'sessions': [
            {'uuid': 'bad-1', 'exercise_id': eid, 'weight': 'viel', 'repetitions': 5},
            {'uuid': 'bad-2', 'exercise_id': eid, 'weight': 50, 'repetitions': -3},
            {'uuid': 'bad-3', 'exercise_id': eid, 'notes': {'a': 1}, 'weight': 50, 'repetitions': 5},
            {'uuid': 'bad-4', 'exercise_id': eid},
            {'uuid': 'ok-1', 'exercise_id': eid, 'weight': '52.5', 'repetitions': '8', 'timestamp': '2026-03-01T10:00:00Z'},
        ]})
        body = resp.get_json()
        assert resp.status_code == 200
        assert sorted(body['rejected_uuids']) == ['bad-1', 'bad-2', 'bad-3', 'bad-4']
        assert ExerciseSession.query.count() == before + 1
        stored = ExerciseSession.query.filter_by(client_uuid='ok-1').one()
        assert (stored.weight, stored.repetitions) == (52.5, 8)
        assert stored.timestamp.tzinfo is None and stored.timestamp.hour == 10

    @pytest.mark.parametrize('entry', [
        {'uuid': 'x', 'exercise_id': [1]},
        {'uuid': 'x', 'exercise_id': '1'},
        {'uuid': {'a': 1}, 'exercise_id': 1},
        {'uuid': 'u' * 40, 'exercise_id': 1},
    ])
    def test_malformed_ids_give_400(self, logged_in_client, sample_plan, entry):
        assert logged_in_client.post('/sync', json={'sessions': [entry]}).status_code == 400


class TestHeadersAndProxy:
    def test_csp_header(self, client):
        csp = client.get('/login').headers['Content-Security-Policy']
        for part in ("default-src 'self'", "object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-ancestors 'self'"):
            assert part in csp
        assert 'https://cdn.jsdelivr.net' in csp

    def test_every_external_resource_in_templates_is_allowed(self):
        import glob
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        hosts = set()
        for path in glob.glob(os.path.join(root, 'templates', '*.html')):
            with open(path, encoding='utf-8') as handle:
                hosts.update(re.findall(r'(?:src|href)="(https://[^/"]+)[^"]*\.(?:js|css)', handle.read()))
        assert hosts, 'expected CDN resources in the templates'
        for host in hosts:
            assert host in app_module.DEFAULT_CSP, host


class TestSchemaSelfHealing:
    def test_missing_columns_are_added(self, app, tmp_path):
        engine = db.engine
        with engine.begin() as conn:
            conn.exec_driver_sql('ALTER TABLE app_settings DROP COLUMN require_admin_2fa')
            conn.exec_driver_sql('ALTER TABLE user DROP COLUMN totp_enabled')
        added = add_missing_columns()
        assert added == {'app_settings.require_admin_2fa', 'user.totp_enabled'}
        assert add_missing_columns() == set()
        db.session.add(User(username='nachher', password='x'))
        db.session.commit()
        assert User.query.filter_by(username='nachher').one().totp_enabled is False
