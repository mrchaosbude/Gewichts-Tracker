"""Konten anlegen, aufräumen und vollständig löschen."""

import datetime

from gewichts_tracker.core import _utcnow, app, db
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
