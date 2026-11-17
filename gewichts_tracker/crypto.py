"""Verschlüsselung gespeicherter Geheimnisse und Passwort-Fingerabdruck für Sitzungen."""

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken

from gewichts_tracker.core import app


def _get_fernet():
    key = hashlib.sha256(app.config['SECRET_KEY'].encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_value(plaintext):
    if not plaintext:
        return None
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(encrypted):
    if not encrypted:
        return None
    try:
        return _get_fernet().decrypt(encrypted.encode()).decode()
    except (InvalidToken, Exception):
        return encrypted


def password_fingerprint(password_hash):
    """Short keyed digest of a password hash.

    Steckt in der Login-Sitzung und im Reset-Link: Ändert sich das Passwort,
    werden alle alten Sitzungen und Links automatisch ungültig.
    """
    key = app.config['SECRET_KEY'].encode()
    return hmac.new(key, (password_hash or '').encode(), hashlib.sha256).hexdigest()[:16]
