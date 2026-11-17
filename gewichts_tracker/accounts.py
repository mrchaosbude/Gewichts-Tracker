"""Konten anlegen, aufräumen und vollständig löschen."""

import datetime
import hashlib

from flask import request, session as flask_session
from werkzeug.security import check_password_hash, generate_password_hash

from gewichts_tracker.core import _utcnow, app, db, limiter
from gewichts_tracker.models import (
    BodyWeight,
    Exercise,
    ExerciseSession,
    get_app_settings,
    PlannedTraining,
    ProgressPhoto,
    TemplateTrainingPlan,
    User,
)
from gewichts_tracker.photos import remove_progress_photo_file


_last_cleanup = None

# Für unbekannte Benutzernamen wird trotzdem ein Hash geprüft, damit die Antwortzeit
# nicht verrät, ob es das Konto gibt.
_DUMMY_PASSWORD_HASH = generate_password_hash('timing-dummy-password', method='pbkdf2:sha256')

# Fehlversuche pro Konto (zusätzlich zum Limit pro IP-Adresse). Zählt nur fehlgeschlagene
# Anmeldungen; Web-Login und API teilen sich den Zähler. Unbekannte Namen werden genauso
# behandelt, damit die Sperre nicht verrät, welche Konten es gibt.
LOGIN_FAILURES_PER_ACCOUNT = '10 per 15 minutes'
TWO_FACTOR_FAILURES_PER_ACCOUNT = '5 per 15 minutes'


def authenticate(username, password):
    """Return the user if username and password match, else None (constant work either way)."""
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    user = User.query.filter_by(username=username).first()
    if user is None:
        check_password_hash(_DUMMY_PASSWORD_HASH, password)
        return None
    return user if check_password_hash(user.password, password) else None


def _login_account_key():
    if request.is_json:
        data = request.get_json(silent=True)
        name = data.get('username') if isinstance(data, dict) else ''
    else:
        name = request.form.get('username', '')
    name = name.strip().lower() if isinstance(name, str) else ''
    return 'login-account:' + hashlib.sha256(name.encode('utf-8')).hexdigest()


def _login_failed(response):
    if response.status_code == 200:      # Web: Formular erneut angezeigt
        return True
    if response.status_code == 401:      # API
        body = response.get_json(silent=True) or {}
        return body.get('error') != 'totp_required'
    return False


def _two_factor_key():
    pending = flask_session.get('2fa_pending')
    uid = pending.get('uid') if isinstance(pending, dict) else None
    return f'2fa-account:{uid}'


# Als Decorator unter @app.route verwenden.
login_account_limit = limiter.shared_limit(
    LOGIN_FAILURES_PER_ACCOUNT, scope='login-account', key_func=_login_account_key,
    methods=['POST'], deduct_when=_login_failed)
two_factor_account_limit = limiter.shared_limit(
    TWO_FACTOR_FAILURES_PER_ACCOUNT, scope='2fa-account', key_func=_two_factor_key,
    methods=['POST'], deduct_when=lambda response: response.status_code == 200)


def cleanup_unverified_accounts():
    """Delete unverified accounts older than 7 days. Runs at most once per hour."""
    global _last_cleanup
    now = _utcnow()
    if _last_cleanup and (now - _last_cleanup).total_seconds() < 3600:
        return
    _last_cleanup = now

    settings = get_app_settings()
    if not settings.require_email_verification:
        return

    cutoff = now - datetime.timedelta(days=7)
    expired_users = User.query.filter(
        User.email_confirmed == False,
        User.is_admin == False,
        User.registration_date < cutoff,
    ).all()
    for u in expired_users:
        app.logger.info('Deleting unverified account: %s (registered %s)', u.username, u.registration_date)
        delete_user_with_data(u)
    if expired_users:
        db.session.commit()


def delete_user_with_data(user):
    """Delete a user including personal data that is only linked via user_id.

    Ohne das bleiben Fotos, Körpergewichte und Sessions als Waisen zurück und
    würden einem später neu registrierten Benutzer mit derselben (von SQLite
    wiederverwendeten) ID zugeordnet.
    """
    for photo in ProgressPhoto.query.filter_by(user_id=user.id).all():
        remove_progress_photo_file(photo)
        db.session.delete(photo)
    BodyWeight.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    PlannedTraining.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    ExerciseSession.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    for exercise in Exercise.query.filter_by(user_id=user.id).all():
        # Übungen, die auch in Plänen anderer Benutzer hängen (Altbestand), bleiben erhalten
        if all(plan.user_id == user.id for plan in exercise.training_plans):
            db.session.delete(exercise)
    TemplateTrainingPlan.query.filter_by(creator_id=user.id).update(
        {'creator_id': None}, synchronize_session=False)
    db.session.delete(user)


def registration_open(settings=None):
    settings = settings or get_app_settings()
    return settings.registration_enabled is not False


def _is_last_admin(user):
    return bool(user.is_admin) and User.query.filter(User.is_admin == True, User.id != user.id).count() == 0
