"""Regression tests for the findings of the second security audit."""
import io
import re

import pytest
from flask import g
from werkzeug.security import generate_password_hash

import app as app_module
from gewichts_tracker import accounts, mail
from gewichts_tracker.crypto import encrypt_value
from gewichts_tracker.security import generate_totp_secret
from gewichts_tracker.views import auth as auth_views

flask_31 = pytest.mark.skipif(not hasattr(__import__('flask').Request, 'max_content_length')
                              or isinstance(getattr(__import__('flask').Request, 'max_content_length'), property)
                              and getattr(__import__('flask').Request, 'max_content_length').fset is None,
                              reason='needs Flask >= 3.1 (requirements.txt)')


def _fresh():
    g.pop('_login_user', None)


def _login(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = user.get_id()
    _fresh()


@pytest.fixture()
def victim(app):
    user = app_module.User(username='opfer', email='opfer@example.com', email_confirmed=True,
                           password=generate_password_hash('richtiges-pw'))
    app_module.db.session.add(user)
    app_module.db.session.commit()
    return user


@pytest.fixture()
def outbox(app, monkeypatch):
    settings = app_module.get_app_settings()
    settings.smtp_server = 'smtp.example.test'
    settings.smtp_sender_email = 'noreply@example.test'
    app_module.db.session.commit()
    sent = []
    monkeypatch.setattr(mail, 'send_app_email', lambda to, subject, body: sent.append((to, body)) or True)
    monkeypatch.delenv(mail.BASE_URL_ENV, raising=False)
    auth_views._reset_mail_last_sent.clear()
    return sent


@pytest.fixture()
def rate_limits():
    limiter = app_module.limiter
    limiter.enabled = True
    limiter.reset()
    yield
    limiter.reset()
    limiter.enabled = False


class TestMailLinksUseConfiguredAddress:
    @flask_31  # Flask 3.0 lehnt fremde Hosts im Test wegen SERVER_NAME schon vorher ab
    def test_host_header_cannot_redirect_reset_link(self, client, victim, outbox):
        app_module.get_app_settings().base_url = 'https://fit.example.de'
        app_module.db.session.commit()
        client.post('/forgot-password', data={'identifier': 'opfer'}, headers={'Host': 'angreifer.example'})
        assert len(outbox) == 1
        links = re.findall(r'href="([^"]+)"', outbox[0][1])
        assert links and all(link.startswith('https://fit.example.de/reset-password/') for link in links)
        assert 'angreifer' not in outbox[0][1]

    def test_environment_variable_wins(self, client, victim, outbox, monkeypatch):
        app_module.get_app_settings().base_url = 'https://alt.example.de'
        app_module.db.session.commit()
        monkeypatch.setenv(mail.BASE_URL_ENV, 'https://neu.example.de/')
        client.post('/forgot-password', data={'identifier': 'opfer'})
        assert 'https://neu.example.de/reset-password/' in outbox[0][1]

    def test_without_address_no_mail_is_sent(self, client, victim, outbox):
        page = client.get('/forgot-password').get_data(as_text=True)
        assert 'nicht eingerichtet' in page
        client.post('/forgot-password', data={'identifier': 'opfer'})
        assert outbox == []

    @pytest.mark.parametrize('value,expected', [
        ('https://fit.example.de', 'https://fit.example.de'),
        ('https://fit.example.de/', 'https://fit.example.de'),
        ('http://192.168.1.5:1024', 'http://192.168.1.5:1024'),
        ('fit.example.de', None), ('javascript:alert(1)', None), ('https://a@evil.example', None),
        ('https://fit.example.de/pfad', None), ('https://fit.example.de?x=1', None), ('', None), (None, None),
    ])
    def test_normalize(self, value, expected):
        assert mail.normalize_base_url(value) == expected

    def test_admin_settings_suggest_and_validate(self, admin_client):
        page = admin_client.get('/admin/settings', base_url='https://localhost').get_data(as_text=True)
        assert 'value="https://localhost"' in page and 'Vorschlag' in page
        assert app_module.get_app_settings().base_url is None  # erst nach Speichern
        admin_client.post('/admin/settings', data={'app_name': 'X', 'base_url': 'kein url'})
        assert app_module.get_app_settings().base_url is None
        admin_client.post('/admin/settings', data={'app_name': 'X', 'base_url': 'https://fit.example.de/'})
        assert app_module.get_app_settings().base_url == 'https://fit.example.de'

    @flask_31
    def test_allowed_hosts(self, app, client):
        app.config['TRUSTED_HOSTS'] = ['fit.example.de']
        try:
            assert client.get('/login', headers={'Host': 'angreifer.example'}).status_code == 400
            assert client.get('/login', headers={'Host': 'fit.example.de'}).status_code == 200
        finally:
            app.config['TRUSTED_HOSTS'] = None


class TestPerAccountLimits:
    def test_lockout_after_ten_failures_even_with_right_password(self, app, victim, rate_limits):
        for i in range(10):
            # jede Anfrage von "anderer IP", damit nur das Konto-Limit greift
            resp = app.test_client().post('/login', data={'username': 'opfer', 'password': f'falsch-{i}'},
                                          environ_base={'REMOTE_ADDR': f'10.0.0.{i}'})
            assert resp.status_code == 200
        blocked = app.test_client().post('/login', data={'username': 'opfer', 'password': 'richtiges-pw'},
                                         environ_base={'REMOTE_ADDR': '10.0.1.1'})
        assert blocked.status_code == 429 and 'Zu viele Versuche' in blocked.get_data(as_text=True)
        api = app.test_client().post('/api/login', json={'username': 'opfer', 'password': 'richtiges-pw'},
                                     headers={'X-Requested-With': 'XMLHttpRequest'}, environ_base={'REMOTE_ADDR': '10.0.1.2'})
        assert api.status_code == 429  # Web und API teilen sich den Zähler
        other = app.test_client().post('/login', data={'username': 'jemand', 'password': 'x'},
                                       environ_base={'REMOTE_ADDR': '10.0.1.3'})
        assert other.status_code == 200  # andere Konten sind nicht betroffen

    def test_successful_logins_do_not_count(self, app, victim, rate_limits):
        for i in range(12):
            client = app.test_client()
            resp = client.post('/login', data={'username': 'opfer', 'password': 'richtiges-pw'},
                               environ_base={'REMOTE_ADDR': f'10.0.2.{i}'})
            assert resp.status_code == 302

    def test_unknown_accounts_are_limited_the_same_way(self, app, rate_limits):
        codes = [app.test_client().post('/login', data={'username': 'gibtsnicht', 'password': 'x'},
                                        environ_base={'REMOTE_ADDR': f'10.0.3.{i}'}).status_code for i in range(11)]
        assert codes == [200] * 10 + [429]

    def test_two_factor_guesses_limited_server_side(self, app, victim, rate_limits):
        victim.totp_secret = encrypt_value(generate_totp_secret())
        victim.totp_enabled = True
        app_module.db.session.commit()
        attacker = app.test_client()
        attacker.post('/login', data={'username': 'opfer', 'password': 'richtiges-pw'}, environ_base={'REMOTE_ADDR': '10.0.4.1'})
        fresh_cookie = attacker.get_cookie('session').value
        codes = []
        for i in range(7):
            attacker.set_cookie('session', fresh_cookie)  # Fehlversuch-Zähler im Cookie zurückdrehen
            codes.append(attacker.post('/login/2fa', data={'code': f'{i:06d}'},
                                       environ_base={'REMOTE_ADDR': f'10.0.5.{i}'}).status_code)
        assert codes[:5] == [200] * 5 and codes[5:] == [429, 429]


class TestRequestSize:
    @flask_31
    def test_chunked_body_over_limit_is_rejected(self, logged_in_client, app, tmp_path, regular_user):
        app.config['UPLOAD_FOLDER'] = str(tmp_path)
        boundary = 'XyZ'
        payload = b'\x89PNG\r\n\x1a\n' + b'\0' * (11 * 1024 * 1024)
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="photo"; filename="a.png"\r\n'
                f'Content-Type: image/png\r\n\r\n').encode() + payload + f'\r\n--{boundary}--\r\n'.encode()
        resp = logged_in_client.post('/progress_photos', input_stream=io.BytesIO(body),
                                     content_type=f'multipart/form-data; boundary={boundary}',
                                     headers={'Transfer-Encoding': 'chunked'}, environ_overrides={'wsgi.input_terminated': True})
        assert resp.status_code == 413
        assert app_module.ProgressPhoto.query.count() == 0
        assert list(tmp_path.iterdir()) == []


class TestEmailChangeNeedsConfirmation:
    def test_new_address_only_after_link(self, app, client, victim, outbox):
        settings = app_module.get_app_settings()
        settings.require_email_verification = True
        settings.base_url = 'https://fit.example.de'
        app_module.db.session.commit()
        _login(client, victim)
        resp = client.post('/account/email', data={'mail-email': 'neu@example.org', 'mail-current_password': 'richtiges-pw'})
        assert resp.status_code == 302
        user = app_module.db.session.get(app_module.User, victim.id)
        assert (user.email, user.pending_email, user.email_confirmed) == ('opfer@example.com', 'neu@example.org', True)
        assert outbox[0][0] == 'neu@example.org'
        link = re.search(r'href="https://fit\.example\.de(/confirm/[^"]+)"', outbox[0][1]).group(1)
        _fresh()
        client.get(link)
        user = app_module.db.session.get(app_module.User, victim.id)
        assert (user.email, user.pending_email, user.email_token) == ('neu@example.org', None, None)

    def test_without_verification_setting_change_is_direct(self, client, victim):
        _login(client, victim)
        client.post('/account/email', data={'mail-email': 'direkt@example.org', 'mail-current_password': 'richtiges-pw'})
        assert app_module.db.session.get(app_module.User, victim.id).email == 'direkt@example.org'


class TestNoAccountEnumeration:
    def test_unknown_user_still_checks_a_password_hash(self, client, monkeypatch):
        calls = []
        original = accounts.check_password_hash
        monkeypatch.setattr(accounts, 'check_password_hash', lambda h, p: calls.append(h) or original(h, p))
        client.post('/login', data={'username': 'gibtsnicht', 'password': 'irgendwas'})
        client.post('/api/login', json={'username': 'gibtsnicht', 'password': 'irgendwas'})
        assert calls == [accounts._DUMMY_PASSWORD_HASH] * 2

    def test_resend_confirmation_answers_the_same(self, app, victim, outbox):
        texts = []
        for name in ('opfer', 'gibtsnicht'):
            client = app.test_client()
            client.post('/resend-confirmation', data={'username': name})
            with client.session_transaction() as sess:
                texts.append([m for _, m in sess.get('_flashes', [])])
        assert texts[0] == texts[1] and texts[0]


class TestHttpsHeaders:
    def test_hsts_only_with_secure_cookies(self, app, client):
        assert 'Strict-Transport-Security' not in client.get('/login').headers
        app.config['SESSION_COOKIE_SECURE'] = True
        try:
            assert client.get('/login').headers['Strict-Transport-Security'] == 'max-age=31536000'
        finally:
            app.config['SESSION_COOKIE_SECURE'] = False

    def test_remember_cookie_lasts_30_days(self, app):
        assert app.config['REMEMBER_COOKIE_DURATION'].days == 30
