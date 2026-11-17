"""Zugriffs-Decorators und Besitzprüfungen."""

from flask import abort
from flask_login import current_user


# ----------------------------------------------------
# Decorators
# ----------------------------------------------------
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def trainer_or_admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not (current_user.is_admin or current_user.is_trainer):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# Helper to check if an exercise belongs only to the current user
def exercise_owned_exclusively_by(user_id, exercise):
    """Return True if the exercise is only linked to plans of the given user."""
    return all(p.user_id == user_id for p in exercise.training_plans)
