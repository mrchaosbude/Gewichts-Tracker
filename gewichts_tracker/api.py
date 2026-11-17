"""REST-API unter /api."""

import datetime
import secrets
import uuid

from flask import abort, flash, jsonify, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from gewichts_tracker import services
from gewichts_tracker.core import _utcnow, api_bp, app, csrf, db, limiter
from gewichts_tracker.models import (
    BodyWeight,
    Exercise,
    ExerciseSession,
    get_app_settings,
    PlannedTraining,
    ProgressPhoto,
    TemplateTrainingPlan,
    TrainingPlan,
    User,
)
from gewichts_tracker.security import PASSWORD_MIN_LENGTH, verify_second_factor
from gewichts_tracker.parsing import (
    _get_json_payload,
    _parse_calendar_month_args,
    _parse_float_field,
    _parse_int_field,
)


from gewichts_tracker.serializers import serialize_exercise, serialize_session, serialize_training_plan
from gewichts_tracker.permissions import exercise_owned_exclusively_by
from gewichts_tracker.stats import (
    _session_volume,
    _session_weight,
    ACHIEVEMENTS,
    calculate_exercise_statistics,
    check_deload_reminder,
    check_new_personal_records,
    serialize_personal_bests,
    serialize_summary,
)
from gewichts_tracker.mail import send_verification_email
from gewichts_tracker.accounts import _is_last_admin, delete_user_with_data, registration_open
from gewichts_tracker.data_io import _imp_num, _imp_str, _imp_timestamp


# ----------------------------------------------------
# REST API Endpunkte
# ----------------------------------------------------

@api_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def api_register():
    data, error_response, status_code = _get_json_payload()
    if error_response is not None:
        return error_response, status_code
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({'error': 'username and password must be strings'}), 400
    if data.get('email') is not None and not isinstance(data.get('email'), str):
        return jsonify({'error': 'email must be a string'}), 400
    if len(password) < 8:
        return jsonify({'error': 'password must be at least 8 characters'}), 400
    if len(username) < 3 or len(username) > 150:
        return jsonify({'error': 'username must be between 3 and 150 characters'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'username exists'}), 400
    settings = get_app_settings()
    if not registration_open(settings):
        return jsonify({'error': 'registration is disabled'}), 403
    email = (data.get('email') or '').strip() or None
    email_required = settings.require_email_verification
    if email_required and not email:
        return jsonify({'error': 'email required when email verification is enabled'}), 400
    if email and User.query.filter_by(email=email).first():
        return jsonify({'error': 'email exists'}), 400
    is_first_user = User.query.first() is None
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(
        username=username,
        password=hashed_password,
        is_admin=is_first_user,
        email=email,
    )
    if email_required and not is_first_user:
        new_user.email_confirmed = False
        new_user.email_token = secrets.token_urlsafe(32)
        new_user.email_token_created = _utcnow()
    else:
        new_user.email_confirmed = True
    db.session.add(new_user)
    db.session.commit()
    if email_required and not is_first_user:
        send_verification_email(new_user)
        return jsonify({'message': 'registered', 'email_verification_required': True}), 201
    return jsonify({'message': 'registered'}), 201


@api_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def api_login():
    data, error_response, status_code = _get_json_payload()
    if error_response is not None:
        return error_response, status_code
    username = data.get('username')
    password = data.get('password')
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({'error': 'invalid credentials'}), 401
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        settings = get_app_settings()
        if settings.require_email_verification and not user.email_confirmed:
            return jsonify({'error': 'email confirmation required'}), 403
        if user.totp_enabled:
            totp = data.get('totp_code')
            if totp in (None, ''):
                return jsonify({'error': 'totp_required'}), 401
            if not isinstance(totp, str) or not verify_second_factor(user, totp):
                db.session.rollback()
                return jsonify({'error': 'invalid totp_code'}), 401
        login_user(user)
        user.last_login = _utcnow()
        db.session.commit()
        return jsonify({'message': 'logged in'})
    return jsonify({'error': 'invalid credentials'}), 401


@api_bp.route('/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({'message': 'logged out'})


@api_bp.route('/account/password', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def api_change_password():
    data, error_response, status_code = _get_json_payload()
    if error_response is not None:
        return error_response, status_code
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    if not isinstance(current_password, str) or not isinstance(new_password, str):
        return jsonify({'error': 'current_password and new_password required'}), 400
    if len(new_password) < PASSWORD_MIN_LENGTH:
        return jsonify({'error': f'password must be at least {PASSWORD_MIN_LENGTH} characters'}), 400
    user = db.session.get(User, current_user.id)
    if not check_password_hash(user.password, current_password):
        return jsonify({'error': 'current password is wrong'}), 403
    user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
    db.session.commit()
    login_user(user)
    return jsonify({'message': 'password changed'})


@api_bp.route('/training_plans', methods=['GET'])
@login_required
def api_get_plans():
    plans = TrainingPlan.query.filter_by(user_id=current_user.id).all()
    return jsonify([serialize_training_plan(p) for p in plans])


@api_bp.route('/training_plans', methods=['POST'])
@login_required
def api_create_plan():
    data = request.get_json() or {}
    title = data.get('title')
    if not title:
        return jsonify({'error': 'title required'}), 400
    plan = TrainingPlan(title=title, description=data.get('description', ''), user_id=current_user.id)
    db.session.add(plan)
    db.session.commit()
    return jsonify({'id': plan.id, 'title': plan.title, 'description': plan.description}), 201


@api_bp.route('/training_plans/<int:plan_id>/exercises', methods=['GET'])
@login_required
def api_list_exercises(plan_id):
    plan = TrainingPlan.query.get_or_404(plan_id)
    if plan.user_id != current_user.id:
        abort(403)
    return jsonify([serialize_exercise(ex) for ex in plan.exercises])


@api_bp.route('/training_plans/<int:plan_id>/exercises', methods=['POST'])
@login_required
def api_add_exercise(plan_id):
    plan = TrainingPlan.query.get_or_404(plan_id)
    if plan.user_id != current_user.id:
        abort(403)
    data = request.get_json() or {}
    name = data.get('name')
    if not name:
        return jsonify({'error': 'name required'}), 400
    desc = data.get('description')
    exercise = (
        Exercise.query
        .filter_by(name=name, description=desc, user_id=current_user.id)
        .first()
    )
    if not exercise:
        exercise = Exercise(name=name, description=desc, user_id=current_user.id)
        db.session.add(exercise)
        db.session.flush()
    if exercise not in plan.exercises:
        plan.exercises.append(exercise)
        db.session.commit()
    return jsonify({'id': exercise.id, 'name': exercise.name, 'description': exercise.description}), 201


@api_bp.route('/exercises/<int:exercise_id>/sessions', methods=['GET'])
@login_required
def api_get_sessions(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    if not any(p.user_id == current_user.id for p in exercise.training_plans):
        abort(403)
    sessions = (
        ExerciseSession.query
        .filter_by(exercise_id=exercise_id, user_id=current_user.id)
        .order_by(ExerciseSession.timestamp.asc())
        .all()
    )
    include_aggregates = request.args.get('include_aggregates', '').lower() in ('1', 'true', 'yes')
    serialized_sessions = [serialize_session(s) for s in sessions]
    if not include_aggregates:
        return jsonify(serialized_sessions)

    stats = calculate_exercise_statistics(sessions)
    return jsonify({
        'sessions': serialized_sessions,
        'chart_data': stats['chart_data'],
        'summary': serialize_summary(stats['summary']),
        'personal_bests': serialize_personal_bests(stats['personal_bests']),
        'moving_window': stats['moving_window'],
    })


@api_bp.route('/exercises/<int:exercise_id>/sessions', methods=['POST'])
@login_required
def api_add_session(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    if not any(p.user_id == current_user.id for p in exercise.training_plans):
        abort(403)
    data, error_response, status_code = _get_json_payload()
    if error_response is not None:
        return error_response, status_code
    is_cardio = (exercise.exercise_type == 'ausdauer')
    repetitions = data.get('repetitions')
    weight = data.get('weight')
    notes = data.get('notes')
    perceived_exertion = data.get('perceived_exertion')
    duration_minutes = data.get('duration_minutes')
    distance_km = data.get('distance_km')
    warmup_activity = data.get('warmup_activity')
    warmup_duration = data.get('warmup_duration')
    if is_cardio:
        if duration_minutes is None:
            return jsonify({'error': 'duration_minutes required for cardio exercises'}), 400
        try:
            duration_minutes = _parse_int_field(duration_minutes, 'duration_minutes', minimum=1)
            if distance_km not in (None, ''):
                distance_km = _parse_float_field(distance_km, 'distance_km', minimum=0)
            else:
                distance_km = None
        except ValueError as exc:
            return jsonify({'error': str(exc)}), 400
    else:
        if repetitions is None or weight is None:
            return jsonify({'error': 'repetitions and weight required'}), 400
        try:
            repetitions = _parse_int_field(repetitions, 'repetitions', minimum=1)
            weight = _parse_float_field(weight, 'weight', minimum=0)
        except ValueError as exc:
            return jsonify({'error': str(exc)}), 400
    if perceived_exertion == '' or perceived_exertion is None:
        perceived_exertion = None
    else:
        try:
            perceived_exertion = _parse_int_field(perceived_exertion, 'perceived_exertion', minimum=1, maximum=10)
        except ValueError as exc:
            return jsonify({'error': str(exc)}), 400
    if warmup_duration not in (None, ''):
        try:
            warmup_duration = _parse_int_field(warmup_duration, 'warmup_duration', minimum=1)
        except ValueError as exc:
            return jsonify({'error': str(exc)}), 400
    else:
        warmup_duration = None
    pr_records = []
    if not is_cardio:
        pr_records = check_new_personal_records(
            exercise_id, current_user.id, int(weight), repetitions
        )
    new_session = ExerciseSession(
        exercise_id=exercise_id,
        repetitions=repetitions if not is_cardio else None,
        weight=weight if not is_cardio else None,
        duration_minutes=duration_minutes if is_cardio else None,
        distance_km=distance_km if is_cardio else None,
        warmup_activity=warmup_activity,
        warmup_duration=warmup_duration,
        timestamp=_utcnow(),
        notes=notes,
        perceived_exertion=perceived_exertion,
        user_id=current_user.id,
    )
    db.session.add(new_session)
    db.session.commit()
    for pr in pr_records:
        flash(pr, 'warning')
    return jsonify({'id': new_session.id, 'personal_records': pr_records}), 201


# ----------------------------------------------------
# API: Sessions DELETE
# ----------------------------------------------------

@api_bp.route('/sessions/<int:session_id>', methods=['PUT'])
@login_required
def api_update_session(session_id):
    session = ExerciseSession.query.get_or_404(session_id)
    if session.user_id != current_user.id:
        abort(403)
    data, error_response, status_code = _get_json_payload()
    if error_response is not None:
        return error_response, status_code
    is_cardio = (session.exercise.exercise_type == 'ausdauer')
    numeric = {
        'weight': dict(integer=False, minimum=0, maximum=5000),
        'repetitions': dict(integer=True, minimum=1, maximum=100000),
        'duration_minutes': dict(integer=True, minimum=1, maximum=100000),
        'distance_km': dict(integer=False, minimum=0, maximum=100000),
        'warmup_duration': dict(integer=True, minimum=1, maximum=100000),
        'perceived_exertion': dict(integer=True, minimum=1, maximum=10),
    }
    try:
        for field, rules in numeric.items():
            if field in data:
                setattr(session, field, _imp_num(data[field], field, **rules))
        if 'notes' in data:
            session.notes = _imp_str(data['notes'], 5000, 'notes')
        if 'warmup_activity' in data:
            session.warmup_activity = _imp_str(data['warmup_activity'], 100, 'warmup_activity')
        if 'timestamp' in data:
            if not data['timestamp']:
                raise ValueError('timestamp must not be empty')
            session.timestamp = _imp_timestamp(data['timestamp'], 'timestamp')
        if is_cardio and session.duration_minutes is None:
            raise ValueError('duration_minutes required for cardio exercises')
        if not is_cardio and (session.weight is None or session.repetitions is None):
            raise ValueError('repetitions and weight required')
    except ValueError as exc:
        db.session.rollback()
        return jsonify({'error': str(exc)}), 400
    db.session.commit()
    return jsonify(serialize_session(session))


@api_bp.route('/account', methods=['DELETE'])
@login_required
@limiter.limit("5 per minute")
def api_delete_account():
    data, error_response, status_code = _get_json_payload()
    if error_response is not None:
        return error_response, status_code
    password = data.get('current_password')
    user = db.session.get(User, current_user.id)
    if not isinstance(password, str) or not check_password_hash(user.password, password):
        return jsonify({'error': 'current password is wrong'}), 403
    if _is_last_admin(user):
        return jsonify({'error': 'the only administrator cannot be deleted'}), 409
    logout_user()
    delete_user_with_data(user)
    db.session.commit()
    return jsonify({'message': 'account deleted'})


@api_bp.route('/sessions/<int:session_id>', methods=['DELETE'])
@login_required
def api_delete_session(session_id):
    session = ExerciseSession.query.get_or_404(session_id)
    if session.user_id != current_user.id:
        abort(403)
    db.session.delete(session)
    db.session.commit()
    return jsonify({'message': 'session deleted'})


# ----------------------------------------------------
# API: Training Plans UPDATE / DELETE
# ----------------------------------------------------

@api_bp.route('/training_plans/<int:plan_id>', methods=['PUT'])
@login_required
def api_update_plan(plan_id):
    plan = TrainingPlan.query.get_or_404(plan_id)
    if plan.user_id != current_user.id:
        abort(403)
    data = request.get_json() or {}
    if 'title' in data:
        plan.title = data['title']
    if 'description' in data:
        plan.description = data['description']
    db.session.commit()
    return jsonify({'id': plan.id, 'title': plan.title, 'description': plan.description})


@api_bp.route('/training_plans/<int:plan_id>', methods=['DELETE'])
@login_required
def api_delete_plan(plan_id):
    plan = TrainingPlan.query.get_or_404(plan_id)
    if plan.user_id != current_user.id:
        abort(403)
    db.session.delete(plan)
    db.session.commit()
    return jsonify({'message': 'training plan deleted'})


@api_bp.route('/training_plans/<int:plan_id>/detail', methods=['GET'])
@login_required
def api_plan_detail(plan_id):
    plan = TrainingPlan.query.get_or_404(plan_id)
    if plan.user_id != current_user.id:
        abort(403)
    rows = db.session.execute(
        db.text('SELECT exercise_id, superset_group, position FROM plan_exercises WHERE training_plan_id = :pid'),
        {'pid': plan_id}
    ).fetchall()
    superset_map = {}
    position_map = {}
    for row in rows:
        if row[1] is not None:
            superset_map[row[0]] = row[1]
        position_map[row[0]] = row[2] if row[2] is not None else 999999
    sorted_exercises = sorted(plan.exercises, key=lambda ex: (position_map.get(ex.id, 999999), ex.id))
    exercises_out = []
    for ex in sorted_exercises:
        ex_data = serialize_exercise(ex)
        ex_data['exercise_type'] = ex.exercise_type
        ex_data['muscle_group'] = ex.muscle_group
        ex_data['superset_group'] = superset_map.get(ex.id)
        ex_data['position'] = position_map.get(ex.id, 999999)
        exercises_out.append(ex_data)
    return jsonify({
        'id': plan.id,
        'title': plan.title,
        'description': plan.description,
        'share_token': plan.share_token,
        'exercises': exercises_out,
    })


# ----------------------------------------------------
# API: Exercises UPDATE / DELETE
# ----------------------------------------------------

@api_bp.route('/exercises/<int:exercise_id>', methods=['PUT'])
@login_required
def api_update_exercise(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    if not any(p.user_id == current_user.id for p in exercise.training_plans):
        abort(403)
    if not exercise_owned_exclusively_by(current_user.id, exercise):
        return jsonify({'error': 'exercise is shared and cannot be edited'}), 403
    data = request.get_json() or {}
    if 'name' in data:
        exercise.name = data['name']
    if 'description' in data:
        exercise.description = data['description']
    if 'muscle_group' in data:
        exercise.muscle_group = data['muscle_group'] or None
    db.session.commit()
    return jsonify(serialize_exercise(exercise))


@api_bp.route('/exercises/<int:exercise_id>', methods=['DELETE'])
@login_required
def api_delete_exercise(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    user_plan = services.user_plan_for_exercise(exercise, current_user.id)
    if not user_plan:
        abort(403)
    services.remove_exercise_from_plan(user_plan, exercise)
    db.session.commit()
    return jsonify({'message': 'exercise deleted'})


# ----------------------------------------------------
# API: Superset / Reorder
# ----------------------------------------------------

@api_bp.route('/training_plans/<int:plan_id>/set_superset', methods=['POST'])
@login_required
def api_set_superset(plan_id):
    plan = TrainingPlan.query.get_or_404(plan_id)
    if plan.user_id != current_user.id:
        abort(403)
    data = request.get_json(silent=True) or {}
    if data.get('exercise_id') is None:
        return jsonify({'error': 'exercise_id required'}), 400
    try:
        group = services.set_superset_group(plan, data.get('exercise_id'), data.get('superset_group'))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    db.session.commit()
    return jsonify({'message': 'superset updated', 'superset_group': group})


@api_bp.route('/training_plans/<int:plan_id>/reorder', methods=['POST'])
@login_required
def api_reorder_exercises(plan_id):
    plan = TrainingPlan.query.get_or_404(plan_id)
    if plan.user_id != current_user.id:
        abort(403)
    data = request.get_json(silent=True) or {}
    if data.get('exercise_id') is None or data.get('direction') not in ('up', 'down'):
        return jsonify({'error': 'exercise_id and direction (up/down) required'}), 400
    try:
        found = services.move_exercise(plan, data.get('exercise_id'), data.get('direction'))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    if not found:
        return jsonify({'error': 'exercise not found in plan'}), 404
    db.session.commit()
    return jsonify({'message': 'exercises reordered'})


# ----------------------------------------------------
# API: Body Weight
# ----------------------------------------------------

@api_bp.route('/body_weight', methods=['GET'])
@login_required
def api_get_body_weight():
    entries = BodyWeight.query.filter_by(user_id=current_user.id).order_by(BodyWeight.timestamp.desc()).all()
    stats = None
    if entries:
        weights = [e.weight for e in entries]
        chart_entries = sorted(entries, key=lambda e: e.timestamp)
        stats = {
            'current': entries[0].weight,
            'min': min(weights),
            'max': max(weights),
            'avg': round(sum(weights) / len(weights), 1),
            'total_entries': len(entries),
        }
        if len(entries) > 1:
            stats['change'] = round(chart_entries[-1].weight - chart_entries[0].weight, 1)
    return jsonify({
        'entries': [{
            'id': e.id,
            'weight': e.weight,
            'timestamp': e.timestamp.isoformat() if e.timestamp else None,
            'notes': e.notes,
        } for e in entries],
        'stats': stats,
    })


@api_bp.route('/body_weight', methods=['POST'])
@login_required
def api_add_body_weight():
    data = request.get_json(silent=True) or {}
    if data.get('weight') is None:
        return jsonify({'error': 'weight required'}), 400
    try:
        entry = services.add_body_weight(current_user.id, data.get('weight'), data.get('notes'))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    db.session.commit()
    return jsonify({'id': entry.id, 'weight': entry.weight, 'timestamp': entry.timestamp.isoformat()}), 201


@api_bp.route('/body_weight/<int:entry_id>', methods=['DELETE'])
@login_required
def api_delete_body_weight(entry_id):
    entry = BodyWeight.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    db.session.delete(entry)
    db.session.commit()
    return jsonify({'message': 'entry deleted'})


# ----------------------------------------------------
# API: Progress Photos
# ----------------------------------------------------

@api_bp.route('/progress_photos', methods=['GET'])
@login_required
def api_get_progress_photos():
    photos = ProgressPhoto.query.filter_by(user_id=current_user.id).order_by(ProgressPhoto.timestamp.desc()).all()
    return jsonify([{
        'id': p.id,
        'filename': p.filename,
        'url': url_for('progress_photo_file', photo_id=p.id),
        'timestamp': p.timestamp.isoformat() if p.timestamp else None,
        'notes': p.notes,
        'body_weight': p.body_weight,
    } for p in photos])


@api_bp.route('/progress_photos', methods=['POST'])
@login_required
def api_upload_progress_photo():
    if 'photo' not in request.files:
        return jsonify({'error': 'photo file required'}), 400
    try:
        photo = services.create_progress_photo(
            current_user.id,
            request.files['photo'],
            notes=request.form.get('notes', ''),
            body_weight=request.form.get('body_weight', ''),
        )
    except ValueError as exc:
        db.session.rollback()
        return jsonify({'error': str(exc)}), 400
    db.session.commit()
    return jsonify({
        'id': photo.id,
        'filename': photo.filename,
        'url': url_for('progress_photo_file', photo_id=photo.id),
        'timestamp': photo.timestamp.isoformat(),
    }), 201


@api_bp.route('/progress_photos/<int:photo_id>', methods=['DELETE'])
@login_required
def api_delete_progress_photo(photo_id):
    photo = ProgressPhoto.query.get_or_404(photo_id)
    if photo.user_id != current_user.id:
        abort(403)
    services.delete_progress_photo(photo)
    db.session.commit()
    return jsonify({'message': 'photo deleted'})


# ----------------------------------------------------
# API: Training Calendar
# ----------------------------------------------------

@api_bp.route('/calendar', methods=['GET'])
@login_required
def api_get_calendar():
    try:
        year, month = _parse_calendar_month_args()
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    first_day = datetime.date(year, month, 1)
    if month == 12:
        last_day = datetime.date(year + 1, 1, 1)
    else:
        last_day = datetime.date(year, month + 1, 1)
    sessions = (
        ExerciseSession.query
        .filter_by(user_id=current_user.id)
        .filter(ExerciseSession.timestamp >= datetime.datetime.combine(first_day, datetime.time.min))
        .filter(ExerciseSession.timestamp < datetime.datetime.combine(last_day, datetime.time.min))
        .all()
    )
    day_counts = {}
    for s in sessions:
        day = s.timestamp.date().isoformat()
        day_counts[day] = day_counts.get(day, 0) + 1
    planned = PlannedTraining.query.filter(
        PlannedTraining.user_id == current_user.id,
        PlannedTraining.date >= first_day,
        PlannedTraining.date < last_day,
    ).all()
    planned_list = [{'date': p.date.isoformat(), 'label': p.label} for p in planned]
    total_sessions = len(sessions)
    training_days = len(set(s.timestamp.date() for s in sessions))
    total_volume = sum(_session_volume(s) for s in sessions)
    return jsonify({
        'year': year,
        'month': month,
        'day_counts': day_counts,
        'planned': planned_list,
        'total_sessions': total_sessions,
        'training_days': training_days,
        'total_volume': total_volume,
    })


@api_bp.route('/calendar/plan', methods=['POST'])
@login_required
def api_plan_training_day():
    data = request.get_json(silent=True) or {}
    try:
        day = services.parse_plan_date(data.get('date'))
        entry = services.plan_training_day(current_user.id, day, data.get('label'))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    db.session.commit()
    return jsonify({'message': 'training day planned', 'date': day.isoformat(), 'label': entry.label}), 201


@api_bp.route('/calendar/unplan', methods=['POST'])
@login_required
def api_unplan_training_day():
    data = request.get_json(silent=True) or {}
    try:
        day = services.parse_plan_date(data.get('date'))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    deleted = services.unplan_training_day(current_user.id, day)
    db.session.commit()
    if deleted:
        return jsonify({'message': 'training day unplanned'})
    return jsonify({'message': 'no planned training found for this date'}), 404


# ----------------------------------------------------
# API: Dashboard
# ----------------------------------------------------

@api_bp.route('/dashboard', methods=['GET'])
@login_required
def api_dashboard():
    today = datetime.date.today()
    this_monday = today - datetime.timedelta(days=today.weekday())
    week_sessions = (
        ExerciseSession.query
        .filter(
            ExerciseSession.user_id == current_user.id,
            ExerciseSession.timestamp >= datetime.datetime.combine(this_monday, datetime.time.min),
        )
        .all()
    )
    week_sets = len(week_sessions)
    week_volume = sum(_session_volume(s) for s in week_sessions)
    week_days = len(set(s.timestamp.date() for s in week_sessions))
    streak = 0
    for i in range(52):
        w_start = this_monday - datetime.timedelta(weeks=i)
        w_end = w_start + datetime.timedelta(days=7)
        cnt = ExerciseSession.query.filter(
            ExerciseSession.user_id == current_user.id,
            ExerciseSession.timestamp >= datetime.datetime.combine(w_start, datetime.time.min),
            ExerciseSession.timestamp < datetime.datetime.combine(w_end, datetime.time.min),
        ).count()
        if cnt > 0:
            streak += 1
        else:
            break
    deload_needed, weeks_trained = check_deload_reminder(current_user.id)
    upcoming_planned = (
        PlannedTraining.query
        .filter(
            PlannedTraining.user_id == current_user.id,
            PlannedTraining.date >= today,
            PlannedTraining.date <= today + datetime.timedelta(days=7),
        )
        .order_by(PlannedTraining.date)
        .all()
    )
    plans = TrainingPlan.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'training_plans': [serialize_training_plan(p) for p in plans],
        'week_stats': {
            'sets': week_sets,
            'volume': week_volume,
            'training_days': week_days,
        },
        'streak': streak,
        'deload_needed': deload_needed,
        'weeks_trained': weeks_trained,
        'upcoming_planned': [{'date': p.date.isoformat(), 'label': p.label} for p in upcoming_planned],
    })


# ----------------------------------------------------
# API: Statistics
# ----------------------------------------------------

@api_bp.route('/statistics', methods=['GET'])
@login_required
def api_statistics():
    now = _utcnow()
    today = now.date()
    this_monday = today - datetime.timedelta(days=today.weekday())
    last_monday = this_monday - datetime.timedelta(days=7)

    all_sessions = (
        ExerciseSession.query
        .filter_by(user_id=current_user.id)
        .order_by(ExerciseSession.timestamp.desc())
        .all()
    )
    kraft_sessions = [s for s in all_sessions if s.weight is not None and s.repetitions is not None]
    cardio_sessions = [s for s in all_sessions if s.exercise.exercise_type == 'ausdauer']

    # Muskelgruppen-Volumen
    muscle_volume = {}
    for s in kraft_sessions:
        mg = s.exercise.muscle_group or 'Nicht zugeordnet'
        muscle_volume[mg] = muscle_volume.get(mg, 0) + _session_volume(s)

    # Wochenvergleich
    this_week = [s for s in kraft_sessions if s.timestamp.date() >= this_monday]
    last_week = [s for s in kraft_sessions if last_monday <= s.timestamp.date() < this_monday]
    this_week_volume = sum(_session_volume(s) for s in this_week)
    last_week_volume = sum(_session_volume(s) for s in last_week)

    # Übungs-Vergleich
    tw_by_ex = {}
    lw_by_ex = {}
    for s in this_week:
        name = s.exercise.name
        if name not in tw_by_ex:
            tw_by_ex[name] = {'sets': 0, 'volume': 0, 'max_weight': 0}
        tw_by_ex[name]['sets'] += 1
        tw_by_ex[name]['volume'] += _session_volume(s)
        tw_by_ex[name]['max_weight'] = max(tw_by_ex[name]['max_weight'], _session_weight(s))
    for s in last_week:
        name = s.exercise.name
        if name not in lw_by_ex:
            lw_by_ex[name] = {'sets': 0, 'volume': 0, 'max_weight': 0}
        lw_by_ex[name]['sets'] += 1
        lw_by_ex[name]['volume'] += _session_volume(s)
        lw_by_ex[name]['max_weight'] = max(lw_by_ex[name]['max_weight'], _session_weight(s))
    exercise_comparison = []
    for name in sorted(set(list(tw_by_ex.keys()) + list(lw_by_ex.keys()))):
        tw = tw_by_ex.get(name, {'sets': 0, 'volume': 0, 'max_weight': 0})
        lw = lw_by_ex.get(name, {'sets': 0, 'volume': 0, 'max_weight': 0})
        exercise_comparison.append({
            'name': name,
            'this_week': tw,
            'last_week': lw,
            'volume_diff': tw['volume'] - lw['volume'],
            'weight_diff': tw['max_weight'] - lw['max_weight'],
        })

    # Trainingsfrequenz (12 Wochen)
    frequency_data = []
    for i in range(11, -1, -1):
        week_start = this_monday - datetime.timedelta(weeks=i)
        week_end = week_start + datetime.timedelta(days=7)
        week_sess = [s for s in kraft_sessions if week_start <= s.timestamp.date() < week_end]
        frequency_data.append({
            'label': week_start.strftime('%d.%m'),
            'days': len(set(s.timestamp.date() for s in week_sess)),
            'sets': len(week_sess),
            'volume': sum(_session_volume(s) for s in week_sess),
        })

    # Cardio-Statistiken
    cardio_this_week = [s for s in cardio_sessions if s.timestamp.date() >= this_monday]
    cardio_last_week = [s for s in cardio_sessions if last_monday <= s.timestamp.date() < this_monday]
    cardio_by_activity = {}
    for s in cardio_sessions:
        name = s.exercise.name
        if name not in cardio_by_activity:
            cardio_by_activity[name] = {'sessions': 0, 'duration': 0, 'distance': 0}
        cardio_by_activity[name]['sessions'] += 1
        cardio_by_activity[name]['duration'] += s.duration_minutes or 0
        cardio_by_activity[name]['distance'] += s.distance_km or 0
    cardio_frequency = []
    for i in range(11, -1, -1):
        week_start = this_monday - datetime.timedelta(weeks=i)
        week_end = week_start + datetime.timedelta(days=7)
        week_cardio = [s for s in cardio_sessions if week_start <= s.timestamp.date() < week_end]
        cardio_frequency.append({
            'label': week_start.strftime('%d.%m'),
            'sessions': len(week_cardio),
            'duration': sum(s.duration_minutes or 0 for s in week_cardio),
            'distance': round(sum(s.distance_km or 0 for s in week_cardio), 1),
        })

    return jsonify({
        'strength': {
            'muscle_volume': muscle_volume,
            'this_week_volume': this_week_volume,
            'last_week_volume': last_week_volume,
            'volume_diff': this_week_volume - last_week_volume,
            'this_week_sets': len(this_week),
            'last_week_sets': len(last_week),
            'sets_diff': len(this_week) - len(last_week),
            'exercise_comparison': exercise_comparison,
            'frequency': frequency_data,
        },
        'cardio': {
            'total_sessions': len(cardio_sessions),
            'total_duration': sum(s.duration_minutes or 0 for s in cardio_sessions),
            'total_distance': round(sum(s.distance_km or 0 for s in cardio_sessions), 1),
            'avg_duration': round(sum(s.duration_minutes or 0 for s in cardio_sessions) / len(cardio_sessions)) if cardio_sessions else 0,
            'this_week_duration': sum(s.duration_minutes or 0 for s in cardio_this_week),
            'last_week_duration': sum(s.duration_minutes or 0 for s in cardio_last_week),
            'this_week_distance': round(sum(s.distance_km or 0 for s in cardio_this_week), 1),
            'last_week_distance': round(sum(s.distance_km or 0 for s in cardio_last_week), 1),
            'this_week_sessions': len(cardio_this_week),
            'last_week_sessions': len(cardio_last_week),
            'by_activity': cardio_by_activity,
            'frequency': cardio_frequency,
        },
    })


# ----------------------------------------------------
# API: Achievements
# ----------------------------------------------------

@api_bp.route('/achievements', methods=['GET'])
@login_required
def api_achievements():
    total_sessions = ExerciseSession.query.filter_by(user_id=current_user.id).count()
    training_days = db.session.query(
        db.func.date(ExerciseSession.timestamp)
    ).filter_by(user_id=current_user.id).distinct().count()
    reg_days = (_utcnow() - (current_user.registration_date or _utcnow())).days
    earned = []
    locked = []
    for aid, name, desc, check_fn in ACHIEVEMENTS:
        entry = {'id': aid, 'name': name, 'description': desc}
        if check_fn(total_sessions, training_days, reg_days):
            earned.append(entry)
        else:
            locked.append(entry)
    return jsonify({
        'earned': earned,
        'locked': locked,
        'stats': {
            'total_sessions': total_sessions,
            'training_days': training_days,
            'member_days': reg_days,
        },
    })


# ----------------------------------------------------
# API: Training Plan Sharing
# ----------------------------------------------------

@api_bp.route('/training_plans/<int:plan_id>/share', methods=['POST'])
@login_required
def api_share_plan(plan_id):
    plan = TrainingPlan.query.get_or_404(plan_id)
    if plan.user_id != current_user.id:
        abort(403)
    if not plan.share_token:
        plan.share_token = str(uuid.uuid4())
        db.session.commit()
    share_url = request.url_root.rstrip('/') + url_for('copy_shared_plan', token=plan.share_token)
    return jsonify({'share_token': plan.share_token, 'share_url': share_url})


@api_bp.route('/training_plans/<int:plan_id>/unshare', methods=['POST'])
@login_required
def api_unshare_plan(plan_id):
    plan = TrainingPlan.query.get_or_404(plan_id)
    if plan.user_id != current_user.id:
        abort(403)
    plan.share_token = None
    db.session.commit()
    return jsonify({'message': 'sharing disabled'})


@api_bp.route('/shared/<token>/copy', methods=['POST'])
@login_required
def api_copy_shared_plan(token):
    source_plan = TrainingPlan.query.filter_by(share_token=token).first_or_404()
    if source_plan.user_id == current_user.id:
        return jsonify({'error': 'cannot copy your own plan'}), 400
    new_plan = services.copy_shared_plan_for(source_plan, current_user.id)
    db.session.commit()
    return jsonify({'id': new_plan.id, 'title': new_plan.title}), 201


# ----------------------------------------------------
# API: Data Export
# ----------------------------------------------------

@api_bp.route('/export', methods=['GET'])
@login_required
def api_export():
    plans = TrainingPlan.query.filter_by(user_id=current_user.id).all()
    plan_exports = []
    for plan in plans:
        plan_dict = serialize_training_plan(plan)
        exercises_out = []
        for exercise in plan.exercises:
            sessions = (
                ExerciseSession.query
                .filter_by(exercise_id=exercise.id, user_id=current_user.id)
                .order_by(ExerciseSession.timestamp.asc())
                .all()
            )
            exercises_out.append({
                **serialize_exercise(exercise),
                'exercise_type': exercise.exercise_type,
                'muscle_group': exercise.muscle_group,
                'sessions': [serialize_session(s) for s in sessions],
            })
        plan_exports.append({**plan_dict, 'exercises': exercises_out})

    body_weights = BodyWeight.query.filter_by(user_id=current_user.id).order_by(BodyWeight.timestamp.asc()).all()
    return jsonify({
        'exported_at': _utcnow().isoformat(),
        'training_plans': plan_exports,
        'body_weights': [{
            'id': e.id,
            'weight': e.weight,
            'timestamp': e.timestamp.isoformat() if e.timestamp else None,
            'notes': e.notes,
        } for e in body_weights],
    })


# ----------------------------------------------------
# API: Template Plans
# ----------------------------------------------------

@api_bp.route('/template_plans', methods=['GET'])
@login_required
def api_get_template_plans():
    if current_user.is_admin or current_user.is_trainer:
        templates = TemplateTrainingPlan.query.all()
    else:
        templates = TemplateTrainingPlan.query.filter_by(is_visible=True).all()
    return jsonify([{
        'id': t.id,
        'title': t.title,
        'description': t.description,
        'is_visible': t.is_visible,
        'exercises': [{
            'id': e.id,
            'name': e.name,
            'description': e.description,
            'is_separator': e.is_separator,
        } for e in t.exercises],
    } for t in templates])


@api_bp.route('/template_plans/<int:template_id>', methods=['GET'])
@login_required
def api_get_template_plan(template_id):
    template = TemplateTrainingPlan.query.get_or_404(template_id)
    if not template.is_visible and not (current_user.is_admin or current_user.is_trainer):
        abort(403)
    return jsonify({
        'id': template.id,
        'title': template.title,
        'description': template.description,
        'is_visible': template.is_visible,
        'exercises': [{
            'id': e.id,
            'name': e.name,
            'description': e.description,
            'is_separator': e.is_separator,
        } for e in template.exercises],
    })


@api_bp.route('/template_plans/<int:template_id>/add_to_account', methods=['POST'])
@login_required
def api_add_template_to_account(template_id):
    template = TemplateTrainingPlan.query.get_or_404(template_id)
    if not services.template_visible_to(template, current_user):
        abort(403)
    new_plan = services.copy_template_for(template, current_user.id)
    db.session.commit()
    return jsonify({'id': new_plan.id, 'title': new_plan.title}), 201


csrf.exempt(api_bp)
app.register_blueprint(api_bp)
