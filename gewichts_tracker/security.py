"""Zwei-Faktor-Anmeldung, Passwort-Reset-Tokens und URL-Prüfung."""

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time

from itsdangerous import BadSignature, URLSafeTimedSerializer
from markupsafe import Markup
from urllib.parse import urlparse

from gewichts_tracker.core import app, db
from gewichts_tracker.crypto import _get_fernet, password_fingerprint
from gewichts_tracker.models import User


PASSWORD_MIN_LENGTH = 8


# ----- Zwei-Faktor-Anmeldung (TOTP nach RFC 6238: SHA-1, 6 Stellen, 30 Sekunden) -----
TOTP_STEP = 30
TWO_FACTOR_PENDING_SECONDS = 300
TWO_FACTOR_MAX_TRIES = 5


def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp_code(secret_b32, counter):
    key = base64.b32decode(secret_b32, casefold=True)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f'{number % 1000000:06d}'


def match_totp(secret_b32, code, *, after_counter=None, now=None):
    """Return the matching time-step counter (current step +/- 1) or None."""
    code = re.sub(r'\s', '', code or '')
    if not re.fullmatch(r'\d{6}', code):
        return None
    current = int((now if now is not None else time.time()) // TOTP_STEP)
    for counter in (current, current - 1, current + 1):
        if after_counter is not None and counter <= after_counter:
            continue
        try:
            if hmac.compare_digest(totp_code(secret_b32, counter), code):
                return counter
        except (ValueError, TypeError):
            return None
    return None


def _user_totp_secret(user):
    if not user.totp_secret:
        return None
    try:
        return _get_fernet().decrypt(user.totp_secret.encode()).decode()
    except Exception:
        return None  # anderer SECRET_KEY -> 2FA muss neu eingerichtet werden


def _hash_backup_code(code):
    normalized = re.sub(r'[^0-9a-z]', '', (code or '').lower())
    return hashlib.sha256(('backup:' + normalized).encode()).hexdigest()


def generate_backup_codes(user, count=10):
    """Create fresh one-time backup codes; returns the plain codes (shown once)."""
    codes = [f'{secrets.token_hex(3)}-{secrets.token_hex(3)}' for _ in range(count)]
    user.totp_backup_codes = json.dumps([_hash_backup_code(c) for c in codes])
    return codes


def verify_second_factor(user, code):
    """Check a TOTP code or a backup code. Consumes it on success (caller commits)."""
    secret = _user_totp_secret(user)
    if secret:
        counter = match_totp(secret, code, after_counter=user.totp_last_counter)
        if counter is not None:
            user.totp_last_counter = counter
            return True
    try:
        hashes = json.loads(user.totp_backup_codes or '[]')
    except ValueError:
        hashes = []
    candidate = _hash_backup_code(code)
    if len(re.sub(r'[^0-9a-z]', '', (code or '').lower())) == 12 and candidate in hashes:
        hashes.remove(candidate)
        user.totp_backup_codes = json.dumps(hashes)
        return True
    return False


def disable_two_factor(user):
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_last_counter = None
    user.totp_backup_codes = None


def totp_qr_svg(uri):
    """Inline SVG QR code if the optional 'segno' package is installed, else None."""
    try:
        import segno
    except ImportError:
        return None
    try:
        return Markup(segno.make(uri, error='m').svg_inline(scale=5, border=2, dark='#000', light='#fff'))
    except Exception as exc:  # pragma: no cover - QR ist nur Komfort, der Schlüssel steht daneben
        app.logger.warning('Could not render 2FA QR code: %s', exc)
        return None


PASSWORD_RESET_MAX_AGE = 3600  # Sekunden
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _password_reset_serializer():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='password-reset')


def make_password_reset_token(user):
    return _password_reset_serializer().dumps({'uid': user.id, 'fp': password_fingerprint(user.password)})


def verify_password_reset_token(token):
    """Return the user for a valid, unexpired, unused reset token, else None."""
    try:
        data = _password_reset_serializer().loads(token, max_age=PASSWORD_RESET_MAX_AGE)
    except (BadSignature, ValueError, TypeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get('uid'), int):
        return None
    user = db.session.get(User, data['uid'])
    if user is None or not hmac.compare_digest(str(data.get('fp', '')), password_fingerprint(user.password)):
        return None
    return user


def sanitize_external_url(value, *, allow_relative=False, max_length=500):
    """Return ``value`` if it is a plain http(s) URL, otherwise ``None``.

    Blockt ``javascript:``, ``data:`` & Co., die sonst als klickbarer Link
    (href) im Browser des Opfers Skripte ausführen würden.
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > max_length:
        return None
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7f for ch in value):
        return None
    if allow_relative and value.startswith('/') and not value.startswith('//') and '\\' not in value:
        return value
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme.lower() not in ('http', 'https') or not parsed.netloc:
        return None
    return value


@app.template_filter('safe_url')
def _safe_url_filter(value):
    """Jinja-Filter: nur http(s)-URLs bzw. lokale Pfade durchlassen, sonst leer."""
    return sanitize_external_url(value, allow_relative=True) or ''
