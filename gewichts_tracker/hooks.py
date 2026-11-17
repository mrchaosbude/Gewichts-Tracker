"""Request-Hooks: CSRF-Herkunftsprüfung, Header, Größenlimit, 2FA-Pflicht, Login-Loader."""

import hmac

from flask import abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user
from urllib.parse import urlparse

from gewichts_tracker.core import app, CONTENT_SECURITY_POLICY, db, login_manager, MAX_REQUEST_BYTES
from gewichts_tracker.crypto import password_fingerprint
from gewichts_tracker.models import FooterLink, FooterPage, get_app_settings, User
from gewichts_tracker.schema import _ensure_database_setup_once


def _is_trusted_state_changing_request():
    if app.testing or not app.config.get('WTF_CSRF_ENABLED', True):
        return True
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True

    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')
    expected = urlparse(request.host_url)

    def _matches(url_value: str) -> bool:
        parsed = urlparse(url_value)
        return parsed.scheme == expected.scheme and parsed.netloc == expected.netloc

    if origin:
        return _matches(origin)
    if referer:
        return _matches(referer)
    return False


@app.before_request
def protect_session_api_requests():
    if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return None
    if request.blueprint != 'api' and request.endpoint not in {'sync', 'sync_weights'}:
        return None
    if _is_trusted_state_changing_request():
        return None
    return jsonify({'error': 'trusted same-origin request required'}), 403


## cleanup_unverified_accounts is called from login() and register(), not before_request


@app.after_request
def set_cache_headers(response):
    """Prevent SW from caching authenticated HTML pages."""
    if current_user.is_authenticated and response.content_type and 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-store'
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    if CONTENT_SECURITY_POLICY:
        response.headers.setdefault('Content-Security-Policy', CONTENT_SECURITY_POLICY)
    if app.config.get('SESSION_COOKIE_SECURE'):
        # Nur bei HTTPS-Betrieb: Browser sollen die Seite ein Jahr lang nur noch per HTTPS öffnen
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000')
    return response


@app.before_request
def limit_request_size():
    if request.endpoint == 'account_import':
        return None
    if (request.content_length or 0) > MAX_REQUEST_BYTES:
        abort(413)
    # Gilt auch für Uploads ohne Größenangabe (Transfer-Encoding: chunked)
    try:
        request.max_content_length = MAX_REQUEST_BYTES
    except AttributeError:  # pragma: no cover - Flask < 3.1 kennt das pro Anfrage nicht
        pass
    return None


@app.errorhandler(429)
def too_many_requests(error):
    if request.blueprint == 'api' or request.path.startswith(('/api/', '/sync')):
        return jsonify({'error': 'too many requests, please wait and try again'}), 429
    return render_template('too_many_requests.html'), 429


@app.context_processor
def inject_footer_pages():
    """Provide footer pages and app name to all templates."""

    _ensure_database_setup_once()
    settings = get_app_settings()
    return {
        "footer_pages": FooterPage.query.all(),
        "footer_links": FooterLink.query.all(),
        "app_name": settings.app_name or 'Gewichts-Tracker',
        "registration_open": settings.registration_enabled is not False,
    }


@login_manager.user_loader
def load_user(user_id):
    raw_id, _, fingerprint = str(user_id).partition(':')
    try:
        user = db.session.get(User, int(raw_id))
    except ValueError:
        return None
    if user is None or not hmac.compare_digest(fingerprint, password_fingerprint(user.password)):
        return None  # Passwort wurde geändert (oder alte Sitzung) -> neu einloggen
    return user


@app.before_request
def enforce_admin_two_factor():
    """If configured, admins without 2FA may only reach the setup pages."""
    if not current_user.is_authenticated or not current_user.is_admin or current_user.totp_enabled:
        return None
    allowed = {'account_two_factor', 'account_two_factor_setup', 'account_two_factor_enable',
               'logout', 'api.api_logout', 'static', 'service_worker'}
    if request.endpoint in allowed or request.endpoint is None:
        return None
    if not get_app_settings().require_admin_2fa:
        return None
    if request.blueprint == 'api':
        return jsonify({'error': 'two-factor authentication must be set up first'}), 403
    flash('Für Administratoren ist die Zwei-Faktor-Anmeldung Pflicht. Bitte jetzt einrichten.', 'warning')
    return redirect(url_for('account_two_factor'))
