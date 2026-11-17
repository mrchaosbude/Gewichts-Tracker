"""Offline-Synchronisation (Service Worker)."""

import datetime

from flask import jsonify
from flask_login import current_user, login_required

from gewichts_tracker.core import _utcnow, app, csrf, db
from gewichts_tracker.models import BodyWeight, Exercise, ExerciseSession
from gewichts_tracker.parsing import _get_json_payload
from gewichts_tracker.data_io import _imp_num, _imp_str, _imp_timestamp


# ----------------------------------------------------
# Synchronisations-API (für Offline-Daten)
# ----------------------------------------------------
@app.route('/sync', methods=['POST'])
@csrf.exempt
@login_required
def sync():
    data, error_response, status_code = _get_json_payload()
    if error_response is not None:
        return error_response, status_code
    sessions_data = data.get('sessions', [])
    if not isinstance(sessions_data, list):
        return jsonify({'status': 'error', 'message': 'sessions must be a list'}), 400
    synced_uuids = []
    rejected_uuids = []
    for session_info in sessions_data:
        if not isinstance(session_info, dict):
            return jsonify({'status': 'error', 'message': 'each session must be an object'}), 400
        client_uuid = session_info.get('uuid')
        if client_uuid is not None and (not isinstance(client_uuid, str) or not 0 < len(client_uuid) <= 36):
            return jsonify({'status': 'error', 'message': 'uuid must be a string of at most 36 characters'}), 400
        # Deduplication
        if client_uuid and ExerciseSession.query.filter_by(client_uuid=client_uuid).first():
            synced_uuids.append(client_uuid)
            continue
        exercise_id = session_info.get('exercise_id')
        if isinstance(exercise_id, bool) or not isinstance(exercise_id, int):
            return jsonify({'status': 'error', 'message': 'exercise_id must be an integer'}), 400
        exercise = db.session.get(Exercise, exercise_id)
        if not exercise:
            return jsonify({'status': 'error', 'message': f'Übung {exercise_id} existiert nicht'}), 400
        if not any(p.user_id == current_user.id for p in exercise.training_plans):
            return jsonify({'status': 'error', 'message': 'Unautorisierte Übungs-ID'}), 403
        try:
            timestamp = _imp_timestamp(session_info.get('timestamp'), 'timestamp')
        except ValueError:
            timestamp = _utcnow()
        try:
            perceived_exertion = _imp_num(session_info.get('perceived_exertion'), 'RPE', integer=True, minimum=1, maximum=10)
        except ValueError:
            perceived_exertion = None
        try:
            weight = _imp_num(session_info.get('weight'), 'weight', integer=False, minimum=0, maximum=5000)
            repetitions = _imp_num(session_info.get('repetitions'), 'repetitions', integer=True, minimum=1, maximum=100000)
            duration = _imp_num(session_info.get('duration_minutes'), 'duration_minutes', integer=True, minimum=1, maximum=100000)
            distance = _imp_num(session_info.get('distance_km'), 'distance_km', integer=False, minimum=0, maximum=100000)
            warmup_duration = _imp_num(session_info.get('warmup_duration'), 'warmup_duration', integer=True, minimum=1, maximum=100000)
            warmup_activity = _imp_str(session_info.get('warmup_activity'), 100, 'warmup_activity')
            notes = _imp_str(session_info.get('notes'), 5000, 'notes')
            if not ((weight is not None and repetitions is not None) or duration is not None):
                raise ValueError('weight/repetitions or duration_minutes required')
        except ValueError as exc:
            # Unbrauchbarer Eintrag: nicht speichern, aber als erledigt melden,
            # damit er die Offline-Warteschlange des Geräts nicht dauerhaft blockiert.
            app.logger.warning('Rejected offline session from user %s: %s', current_user.id, exc)
            if client_uuid:
                synced_uuids.append(client_uuid)
                rejected_uuids.append(client_uuid)
            continue
        new_session = ExerciseSession(
            exercise_id=exercise_id,
            repetitions=repetitions,
            weight=weight,
            duration_minutes=duration,
            distance_km=distance,
            warmup_activity=warmup_activity,
            warmup_duration=warmup_duration,
            timestamp=timestamp,
            notes=notes,
            perceived_exertion=perceived_exertion,
            user_id=current_user.id,
            client_uuid=client_uuid,
        )
        db.session.add(new_session)
        if client_uuid:
            synced_uuids.append(client_uuid)
    db.session.commit()
    return jsonify({'status': 'success', 'synced_uuids': synced_uuids, 'rejected_uuids': rejected_uuids}), 200


@app.route('/sync_weights', methods=['POST'])
@csrf.exempt
@login_required
def sync_weights():
    data, error_response, status_code = _get_json_payload()
    if error_response is not None:
        return error_response, status_code
    weights_data = data.get('weights', [])
    if not isinstance(weights_data, list):
        return jsonify({'status': 'error', 'message': 'weights must be a list'}), 400
    synced_uuids = []
    for w in weights_data:
        if not isinstance(w, dict):
            return jsonify({'status': 'error', 'message': 'each weight entry must be an object'}), 400
        client_uuid = w.get('uuid')
        # Deduplication
        if client_uuid and BodyWeight.query.filter_by(client_uuid=client_uuid).first():
            synced_uuids.append(client_uuid)
            continue
        weight_val = w.get('weight')
        if weight_val is None:
            continue
        try:
            weight_val = float(weight_val)
        except (TypeError, ValueError):
            continue
        if weight_val < 20 or weight_val > 500:
            continue
        try:
            timestamp = datetime.datetime.fromisoformat(w.get('timestamp'))
        except Exception:
            timestamp = _utcnow()
        new_entry = BodyWeight(
            user_id=current_user.id,
            weight=weight_val,
            timestamp=timestamp,
            notes=w.get('notes') or None,
            client_uuid=client_uuid,
        )
        db.session.add(new_entry)
        if client_uuid:
            synced_uuids.append(client_uuid)
    db.session.commit()
    return jsonify({'status': 'success', 'synced_uuids': synced_uuids}), 200
