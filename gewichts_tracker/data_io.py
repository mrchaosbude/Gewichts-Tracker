"""Vollständiger Export und Import der eigenen Daten."""

import datetime
import json
import math
import os
import zipfile

from gewichts_tracker.core import _utcnow, app, db, MAX_REQUEST_BYTES
from gewichts_tracker.models import (
    BodyWeight,
    Exercise,
    ExerciseSession,
    MUSCLE_GROUPS,
    PlannedTraining,
    ProgressPhoto,
    TrainingPlan,
)
from gewichts_tracker.security import sanitize_external_url
from gewichts_tracker.photos import progress_photo_path, save_progress_photo_bytes


# ----------------------------------------------------
# Vollständiger Export / Import der eigenen Daten
# ----------------------------------------------------
EXPORT_FORMAT = 'gewichts-tracker-export'
EXPORT_VERSION = 1
IMPORT_LIMITS = {
    'training_plans': 500, 'exercises': 5000, 'sessions': 300000,
    'body_weights': 20000, 'planned_trainings': 20000, 'progress_photos': 2000,
}
IMPORT_MAX_JSON_BYTES = 30 * 1024 * 1024
IMPORT_MAX_UNPACKED_BYTES = 1024 * 1024 * 1024


def _iso(value):
    return value.isoformat() if value else None


def build_user_export(user):
    """Return (data_dict, [(archive_name, absolute_path), ...]) with everything the user owns."""
    plans = TrainingPlan.query.filter_by(user_id=user.id).order_by(TrainingPlan.id).all()
    exercises = {}
    plans_out = []
    for plan in plans:
        rows = db.session.execute(
            db.text('SELECT exercise_id, superset_group, position FROM plan_exercises WHERE training_plan_id = :pid'),
            {'pid': plan.id}).fetchall()
        link = {row[0]: (row[1], row[2]) for row in rows}
        ordered = sorted(plan.exercises, key=lambda ex: (link.get(ex.id, (None, None))[1] if link.get(ex.id, (None, None))[1] is not None else 999999, ex.id))
        refs = []
        for exercise in ordered:
            exercises.setdefault(exercise.id, exercise)
            superset_group, position = link.get(exercise.id, (None, None))
            refs.append({'key': exercise.id, 'superset_group': superset_group, 'position': position})
        plans_out.append({'title': plan.title, 'description': plan.description, 'exercises': refs})

    sessions_by_exercise = {}
    if exercises:
        for sess in (ExerciseSession.query
                     .filter(ExerciseSession.user_id == user.id, ExerciseSession.exercise_id.in_(list(exercises)))
                     .order_by(ExerciseSession.timestamp.asc(), ExerciseSession.id.asc()).all()):
            sessions_by_exercise.setdefault(sess.exercise_id, []).append(sess)
    exercises_out = []
    for key, exercise in exercises.items():
        exercises_out.append({
            'key': key,
            'name': exercise.name,
            'description': exercise.description,
            'video_url': exercise.video_url,
            'muscle_group': exercise.muscle_group,
            'exercise_type': exercise.exercise_type or 'kraft',
            'is_separator': bool(exercise.is_separator),
            'sessions': [{
                'timestamp': _iso(sess.timestamp),
                'weight': sess.weight,
                'repetitions': sess.repetitions,
                'duration_minutes': sess.duration_minutes,
                'distance_km': sess.distance_km,
                'warmup_activity': sess.warmup_activity,
                'warmup_duration': sess.warmup_duration,
                'perceived_exertion': sess.perceived_exertion,
                'notes': sess.notes,
            } for sess in sessions_by_exercise.get(key, [])],
        })

    photo_files = []
    photos_out = []
    for photo in ProgressPhoto.query.filter_by(user_id=user.id).order_by(ProgressPhoto.timestamp.asc()).all():
        path = progress_photo_path(photo)
        archive_name = None
        if os.path.isfile(path):
            archive_name = 'photos/' + os.path.basename(path)
            photo_files.append((archive_name, path))
        photos_out.append({
            'file': archive_name,
            'timestamp': _iso(photo.timestamp),
            'notes': photo.notes,
            'body_weight': photo.body_weight,
        })

    data = {
        'format': EXPORT_FORMAT,
        'version': EXPORT_VERSION,
        'exported_at': _utcnow().isoformat(),
        'profile': {'username': user.username, 'email': user.email},
        'training_plans': plans_out,
        'exercises': exercises_out,
        'body_weights': [
            {'timestamp': _iso(e.timestamp), 'weight': e.weight, 'notes': e.notes}
            for e in BodyWeight.query.filter_by(user_id=user.id).order_by(BodyWeight.timestamp.asc()).all()],
        'planned_trainings': [
            {'date': p.date.isoformat(), 'label': p.label}
            for p in PlannedTraining.query.filter_by(user_id=user.id).order_by(PlannedTraining.date.asc()).all()],
        'progress_photos': photos_out,
    }
    return data, photo_files


def _imp_list(data, key):
    value = data.get(key) or []
    if not isinstance(value, list):
        raise ValueError(f'"{key}" muss eine Liste sein.')
    if len(value) > IMPORT_LIMITS.get(key, 100000):
        raise ValueError(f'Zu viele Einträge in "{key}".')
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f'Ungültiger Eintrag in "{key}".')
    return value


def _imp_str(value, max_len, field, required=False):
    if value is None or value == '':
        if required:
            raise ValueError(f'{field} fehlt.')
        return None
    if not isinstance(value, str):
        raise ValueError(f'{field} muss Text sein.')
    value = value.strip()[:max_len]
    if not value and required:
        raise ValueError(f'{field} fehlt.')
    return value or None


def _imp_num(value, field, *, integer, minimum, maximum):
    if value is None or value == '':
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f'{field} muss eine Zahl sein.')
    try:
        number = float(value)
    except ValueError:
        raise ValueError(f'{field} muss eine Zahl sein.')
    if not math.isfinite(number) or number < minimum or number > maximum:
        raise ValueError(f'{field} liegt außerhalb des erlaubten Bereichs.')
    if integer:
        if number != int(number):
            raise ValueError(f'{field} muss eine ganze Zahl sein.')
        return int(number)
    return number


def _imp_timestamp(value, field):
    if value is None or value == '':
        return _utcnow()
    if not isinstance(value, str):
        raise ValueError(f'{field}: ungültiges Datum.')
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(f'{field}: ungültiges Datum.')
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return parsed


def import_user_data(user, data, read_photo=None):
    """Add the contents of an export to *user*'s account. Returns counts.

    Der Import fügt nur hinzu und überschreibt nichts. Wirft ValueError bei
    ungültigen Daten; der Aufrufer macht dann ein Rollback und löscht die
    in ``created_files`` (Attribut der Exception) genannten Fotos.
    """
    if not isinstance(data, dict):
        raise ValueError('Die Datei enthält keinen gültigen Export.')
    if data.get('format') not in (EXPORT_FORMAT, 'json', None):
        raise ValueError('Unbekanntes Dateiformat.')
    if data.get('format') == EXPORT_FORMAT and data.get('version') != EXPORT_VERSION:
        raise ValueError('Diese Export-Version wird nicht unterstützt.')

    counts = {'plans': 0, 'exercises': 0, 'sessions': 0, 'body_weights': 0, 'planned_trainings': 0, 'photos': 0}
    created_files = []
    try:
        # Übungen: entweder oben gelistet (neues Format) oder direkt im Plan (alter Trainingsdaten-Export)
        definitions = {}
        for item in _imp_list(data, 'exercises'):
            definitions[item.get('key')] = item
        created = {}
        session_total = 0

        def get_exercise(entry):
            nonlocal session_total
            definition = definitions.get(entry.get('key')) if 'name' not in entry else entry
            if definition is None:
                raise ValueError('Ein Plan verweist auf eine unbekannte Übung.')
            cache_key = entry.get('key') if 'name' not in entry else ('inline', id(entry))
            if cache_key in created:
                return created[cache_key]
            if len(created) >= IMPORT_LIMITS['exercises']:
                raise ValueError('Zu viele Übungen.')
            is_separator = bool(definition.get('is_separator'))
            exercise_type = definition.get('exercise_type') or 'kraft'
            if exercise_type not in ('kraft', 'ausdauer'):
                raise ValueError('Unbekannter Übungstyp.')
            muscle_group = definition.get('muscle_group')
            exercise = Exercise(
                name=_imp_str(definition.get('name'), 150, 'Übungsname', required=True),
                description=_imp_str(definition.get('description'), 300, 'Beschreibung'),
                video_url=sanitize_external_url(definition.get('video_url')),
                muscle_group=muscle_group if muscle_group in MUSCLE_GROUPS else None,
                exercise_type=exercise_type,
                is_separator=is_separator,
                user_id=user.id,
            )
            db.session.add(exercise)
            db.session.flush()
            counts['exercises'] += 0 if is_separator else 1
            sessions = definition.get('sessions') or []
            if not isinstance(sessions, list):
                raise ValueError('"sessions" muss eine Liste sein.')
            session_total += len(sessions)
            if session_total > IMPORT_LIMITS['sessions']:
                raise ValueError('Zu viele Sessions.')
            for raw in sessions if not is_separator else []:
                if not isinstance(raw, dict):
                    raise ValueError('Ungültige Session.')
                weight = _imp_num(raw.get('weight'), 'Gewicht', integer=False, minimum=0, maximum=5000)
                repetitions = _imp_num(raw.get('repetitions'), 'Wiederholungen', integer=True, minimum=1, maximum=100000)
                duration = _imp_num(raw.get('duration_minutes'), 'Dauer', integer=True, minimum=1, maximum=100000)
                if not ((weight is not None and repetitions is not None) or duration is not None):
                    raise ValueError(f'Session von "{exercise.name}" hat weder Gewicht/Wiederholungen noch Dauer.')
                db.session.add(ExerciseSession(
                    exercise_id=exercise.id,
                    user_id=user.id,
                    timestamp=_imp_timestamp(raw.get('timestamp'), 'Session'),
                    weight=weight,
                    repetitions=repetitions,
                    duration_minutes=duration,
                    distance_km=_imp_num(raw.get('distance_km'), 'Distanz', integer=False, minimum=0, maximum=100000),
                    warmup_activity=_imp_str(raw.get('warmup_activity'), 100, 'Aufwärm-Aktivität'),
                    warmup_duration=_imp_num(raw.get('warmup_duration'), 'Aufwärm-Dauer', integer=True, minimum=1, maximum=100000),
                    perceived_exertion=_imp_num(raw.get('perceived_exertion'), 'RPE', integer=True, minimum=1, maximum=10),
                    notes=_imp_str(raw.get('notes'), 5000, 'Notizen'),
                ))
                counts['sessions'] += 1
            created[cache_key] = exercise
            return exercise

        existing_titles = {p.title for p in TrainingPlan.query.filter_by(user_id=user.id).all()}
        for plan_data in _imp_list(data, 'training_plans'):
            title = _imp_str(plan_data.get('title'), 150, 'Plantitel', required=True)
            if title in existing_titles:
                title = (title[:140] + ' (Import)')
            existing_titles.add(title)
            plan = TrainingPlan(title=title, description=_imp_str(plan_data.get('description'), 300, 'Planbeschreibung'), user_id=user.id)
            db.session.add(plan)
            db.session.flush()
            counts['plans'] += 1
            entries = plan_data.get('exercises') or []
            if not isinstance(entries, list):
                raise ValueError('"exercises" eines Plans muss eine Liste sein.')
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    raise ValueError('Ungültige Übung im Plan.')
                exercise = get_exercise(entry)
                if exercise in plan.exercises:
                    continue
                plan.exercises.append(exercise)
                db.session.flush()
                position = _imp_num(entry.get('position'), 'Position', integer=True, minimum=0, maximum=1000000)
                db.session.execute(
                    db.text('UPDATE plan_exercises SET superset_group = :grp, position = :pos '
                            'WHERE training_plan_id = :pid AND exercise_id = :eid'),
                    {'grp': _imp_num(entry.get('superset_group'), 'Superset', integer=True, minimum=1, maximum=1000),
                     'pos': position if position is not None else index,
                     'pid': plan.id, 'eid': exercise.id})

        known_weights = {(e.timestamp, e.weight) for e in BodyWeight.query.filter_by(user_id=user.id).all()}
        for raw in _imp_list(data, 'body_weights'):
            weight = _imp_num(raw.get('weight'), 'Körpergewicht', integer=False, minimum=20, maximum=500)
            if weight is None:
                raise ValueError('Körpergewicht fehlt.')
            timestamp = _imp_timestamp(raw.get('timestamp'), 'Körpergewicht')
            if (timestamp, weight) in known_weights:
                continue
            known_weights.add((timestamp, weight))
            db.session.add(BodyWeight(user_id=user.id, weight=weight, timestamp=timestamp,
                                      notes=_imp_str(raw.get('notes'), 5000, 'Notizen')))
            counts['body_weights'] += 1

        known_dates = {p.date for p in PlannedTraining.query.filter_by(user_id=user.id).all()}
        for raw in _imp_list(data, 'planned_trainings'):
            try:
                day = datetime.date.fromisoformat(raw.get('date'))
            except (TypeError, ValueError):
                raise ValueError('Geplantes Training: ungültiges Datum.')
            if day in known_dates:
                continue
            known_dates.add(day)
            db.session.add(PlannedTraining(user_id=user.id, date=day, label=_imp_str(raw.get('label'), 100, 'Bezeichnung')))
            counts['planned_trainings'] += 1

        known_photo_times = {p.timestamp for p in ProgressPhoto.query.filter_by(user_id=user.id).all()}
        for raw in _imp_list(data, 'progress_photos'):
            name = raw.get('file')
            if not name or read_photo is None:
                continue
            timestamp = _imp_timestamp(raw.get('timestamp'), 'Foto')
            if timestamp in known_photo_times:
                continue
            content = read_photo(str(name))
            if content is None:
                continue
            filename = save_progress_photo_bytes(content, user.id)
            created_files.append(filename)
            known_photo_times.add(timestamp)
            db.session.add(ProgressPhoto(
                user_id=user.id, filename=filename, timestamp=timestamp,
                notes=_imp_str(raw.get('notes'), 5000, 'Notizen'),
                body_weight=_imp_num(raw.get('body_weight'), 'Körpergewicht', integer=False, minimum=20, maximum=500)))
            counts['photos'] += 1
        db.session.flush()
    except Exception as exc:
        exc.created_files = created_files
        raise
    return counts


def _cleanup_import_files(filenames):
    for name in filenames or []:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(name)))
        except OSError:
            pass


def load_import_upload(file_storage):
    """Parse an uploaded .json or .zip export. Returns (data, read_photo, closer)."""
    head = file_storage.stream.read(4)
    file_storage.stream.seek(0)
    if head[:2] != b'PK':
        raw = file_storage.stream.read(IMPORT_MAX_JSON_BYTES + 1)
        if len(raw) > IMPORT_MAX_JSON_BYTES:
            raise ValueError('Die JSON-Datei ist zu groß.')
        try:
            return json.loads(raw.decode('utf-8-sig')), None, (lambda: None)
        except (ValueError, UnicodeDecodeError):
            raise ValueError('Die Datei ist weder ein ZIP-Export noch gültiges JSON.')
    try:
        archive = zipfile.ZipFile(file_storage.stream)
    except zipfile.BadZipFile:
        raise ValueError('Die ZIP-Datei ist beschädigt.')
    infos = {info.filename: info for info in archive.infolist() if not info.is_dir()}
    if len(infos) > IMPORT_LIMITS['progress_photos'] + 10:
        raise ValueError('Die ZIP-Datei enthält zu viele Dateien.')
    if sum(info.file_size for info in infos.values()) > IMPORT_MAX_UNPACKED_BYTES:
        raise ValueError('Die ZIP-Datei ist entpackt zu groß.')
    json_name = next((n for n in ('data.json', 'training-data.json') if n in infos), None)
    if json_name is None or infos[json_name].file_size > IMPORT_MAX_JSON_BYTES:
        raise ValueError('Die ZIP-Datei enthält keine gültige data.json.')
    try:
        data = json.loads(archive.read(json_name).decode('utf-8-sig'))
    except (ValueError, UnicodeDecodeError, zipfile.BadZipFile):
        raise ValueError('data.json ist nicht lesbar.')

    def read_photo(name):
        # Nur Einträge direkt unter photos/, nie Pfade aus dem Archiv auf die Platte übernehmen
        wanted = 'photos/' + os.path.basename(name.replace('\\', '/'))
        info = infos.get(wanted)
        if info is None or info.file_size > MAX_REQUEST_BYTES:
            return None
        with archive.open(info) as handle:
            content = handle.read(MAX_REQUEST_BYTES + 1)
        return content if len(content) <= MAX_REQUEST_BYTES else None

    return data, read_photo, archive.close
