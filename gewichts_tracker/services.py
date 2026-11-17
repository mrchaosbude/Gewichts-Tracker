"""Gemeinsame Logik für Web-Seiten und API.

Web-Routen und API-Endpunkte rufen dieselben Funktionen auf, damit Prüfungen
nicht auseinanderlaufen. Die Funktionen ändern nur die Session (``flush``);
``commit`` macht der Aufrufer. Ungültige Eingaben melden sie als ``ValueError``
mit einer Meldung, die direkt angezeigt werden kann.
"""

import datetime
import math

from gewichts_tracker.core import db
from gewichts_tracker.models import BodyWeight, Exercise, PlannedTraining, ProgressPhoto, TrainingPlan
from gewichts_tracker.photos import allowed_file, remove_progress_photo_file, save_progress_photo_file
from gewichts_tracker.security import sanitize_external_url

BODY_WEIGHT_MIN = 20
BODY_WEIGHT_MAX = 500
SUPERSET_MAX = 1000
PLAN_LABEL_MAX = 100
NOTES_MAX = 5000


# ----------------------------------------------------
# Pläne kopieren (geteilter Link, Vorlage)
# ----------------------------------------------------
def copy_shared_plan_for(source_plan, user_id):
    """Copy a shared plan with its exercises (without sessions) into *user_id*'s account."""
    new_plan = TrainingPlan(title=(source_plan.title + ' (kopiert)')[:150], description=source_plan.description,
                            user_id=user_id)
    db.session.add(new_plan)
    db.session.flush()
    for exercise in source_plan.exercises:
        copy = Exercise(
            name=exercise.name,
            description=exercise.description,
            video_url=sanitize_external_url(exercise.video_url),
            muscle_group=exercise.muscle_group,
            is_separator=exercise.is_separator,
            exercise_type=exercise.exercise_type,
            user_id=user_id,
        )
        db.session.add(copy)
        db.session.flush()
        new_plan.exercises.append(copy)
    return new_plan


def copy_template_for(template, user_id):
    """Create a training plan for *user_id* from a template plan."""
    new_plan = TrainingPlan(title=template.title, description=template.description, user_id=user_id)
    db.session.add(new_plan)
    db.session.flush()
    for template_exercise in template.exercises:
        exercise = Exercise(
            name=template_exercise.name,
            description=template_exercise.description,
            is_separator=template_exercise.is_separator,
            user_id=user_id,
        )
        db.session.add(exercise)
        db.session.flush()
        new_plan.exercises.append(exercise)
    return new_plan


def template_visible_to(template, user):
    return bool(template.is_visible) or bool(user.is_admin or user.is_trainer)


# ----------------------------------------------------
# Übungen innerhalb eines Plans
# ----------------------------------------------------
def _plan_exercise_id(value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError('exercise_id muss eine ganze Zahl sein.')
    return value


def set_superset_group(plan, exercise_id, group):
    """Assign (or with an empty group remove) a superset group. Returns the stored group."""
    exercise_id = _plan_exercise_id(exercise_id)
    if group in (None, '', 0, False):
        group = None
    elif isinstance(group, bool) or not isinstance(group, int) or not 1 <= group <= SUPERSET_MAX:
        raise ValueError(f'Superset-Gruppe muss eine Zahl zwischen 1 und {SUPERSET_MAX} sein.')
    db.session.execute(
        db.text('UPDATE plan_exercises SET superset_group = :grp WHERE training_plan_id = :pid AND exercise_id = :eid'),
        {'grp': group, 'pid': plan.id, 'eid': exercise_id})
    return group


def move_exercise(plan, exercise_id, direction):
    """Swap an exercise with its neighbour. Returns False if it is not part of the plan."""
    exercise_id = _plan_exercise_id(exercise_id)
    if direction not in ('up', 'down'):
        raise ValueError('direction muss "up" oder "down" sein.')
    rows = db.session.execute(
        db.text('SELECT exercise_id, position FROM plan_exercises WHERE training_plan_id = :pid '
                'ORDER BY COALESCE(position, 999999), exercise_id'),
        {'pid': plan.id}).fetchall()
    ordered = [row[0] for row in rows]
    if exercise_id not in ordered:
        return False
    idx = ordered.index(exercise_id)
    if direction == 'up' and idx > 0:
        ordered[idx], ordered[idx - 1] = ordered[idx - 1], ordered[idx]
    elif direction == 'down' and idx < len(ordered) - 1:
        ordered[idx], ordered[idx + 1] = ordered[idx + 1], ordered[idx]
    for position, eid in enumerate(ordered):
        db.session.execute(
            db.text('UPDATE plan_exercises SET position = :pos WHERE training_plan_id = :pid AND exercise_id = :eid'),
            {'pos': position, 'pid': plan.id, 'eid': eid})
    return True


def user_plan_for_exercise(exercise, user_id):
    return next((plan for plan in exercise.training_plans if plan.user_id == user_id), None)


def remove_exercise_from_plan(plan, exercise):
    """Detach the exercise from the plan; delete it once no plan uses it any more."""
    plan.exercises.remove(exercise)
    if not exercise.training_plans:
        db.session.delete(exercise)


# ----------------------------------------------------
# Kalender
# ----------------------------------------------------
def parse_plan_date(value):
    if not isinstance(value, str) or not value:
        raise ValueError('Datum fehlt (Format JJJJ-MM-TT).')
    try:
        return datetime.datetime.strptime(value, '%Y-%m-%d').date()
    except ValueError:
        raise ValueError('Ungültiges Datum (Format JJJJ-MM-TT).')


def plan_training_day(user_id, day, label):
    if label is not None and not isinstance(label, str):
        raise ValueError('Die Bezeichnung muss Text sein.')
    label = (label or '').strip()[:PLAN_LABEL_MAX] or None
    entry = PlannedTraining.query.filter_by(user_id=user_id, date=day).first()
    if entry:
        entry.label = label
    else:
        entry = PlannedTraining(user_id=user_id, date=day, label=label)
        db.session.add(entry)
    return entry


def unplan_training_day(user_id, day):
    """Returns the number of removed entries (0 or 1)."""
    return PlannedTraining.query.filter_by(user_id=user_id, date=day).delete()


# ----------------------------------------------------
# Körpergewicht und Fortschrittsfotos
# ----------------------------------------------------
def parse_body_weight(value, *, required=True):
    """Validate a body weight in kg (20-500). Accepts numbers and numeric strings."""
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise ValueError('Gewicht fehlt.')
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError('Gewicht muss eine Zahl sein.')
    try:
        weight = float(value.replace(',', '.') if isinstance(value, str) else value)
    except ValueError:
        raise ValueError('Gewicht muss eine Zahl sein.')
    if not math.isfinite(weight) or not BODY_WEIGHT_MIN <= weight <= BODY_WEIGHT_MAX:
        raise ValueError(f'Gewicht muss zwischen {BODY_WEIGHT_MIN} und {BODY_WEIGHT_MAX} kg liegen.')
    return weight


def _clean_notes(notes):
    if notes is None:
        return None
    if not isinstance(notes, str):
        raise ValueError('Notizen müssen Text sein.')
    return notes.strip()[:NOTES_MAX] or None


def add_body_weight(user_id, weight, notes=None):
    entry = BodyWeight(user_id=user_id, weight=parse_body_weight(weight), notes=_clean_notes(notes))
    db.session.add(entry)
    db.session.flush()
    return entry


def create_progress_photo(user_id, file, notes=None, body_weight=None):
    """Validate and store an uploaded photo plus its database entry."""
    if file is None or not file.filename:
        raise ValueError('Keine Datei ausgewählt.')
    if not allowed_file(file.filename):
        raise ValueError('Ungültiges Dateiformat. Erlaubt: PNG, JPG, JPEG, WebP')
    weight = parse_body_weight(body_weight, required=False)
    notes = _clean_notes(notes)
    filename = save_progress_photo_file(file, user_id)  # prüft den Inhalt, wirft ValueError
    photo = ProgressPhoto(user_id=user_id, filename=filename, notes=notes, body_weight=weight)
    db.session.add(photo)
    db.session.flush()
    return photo


def delete_progress_photo(photo):
    remove_progress_photo_file(photo)
    db.session.delete(photo)
