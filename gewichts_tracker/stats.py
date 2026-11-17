"""Statistik-, Fortschritts- und Achievement-Berechnungen."""

import datetime

from gewichts_tracker.core import _utcnow, db
from gewichts_tracker.models import ExerciseSession


# ----------------------------------------------------
# Analyse- und Statistik-Helfer
# ----------------------------------------------------

def _moving_average(values, window):
    if not values or window <= 0:
        return []
    averaged = []
    for index in range(len(values)):
        start = max(0, index - window + 1)
        window_slice = values[start:index + 1]
        averaged.append(sum(window_slice) / len(window_slice))
    return averaged


def _get_trained_weeks(user_id, num_weeks=52):
    """Return a set of week offsets (0=current, 1=last week, ...) that had training.
    Uses a single DB query instead of one per week."""
    today = _utcnow().date()
    monday = today - datetime.timedelta(days=today.weekday())
    earliest = datetime.datetime.combine(monday - datetime.timedelta(weeks=num_weeks - 1), datetime.time.min)
    timestamps = (
        db.session.query(ExerciseSession.timestamp)
        .filter(
            ExerciseSession.user_id == user_id,
            ExerciseSession.timestamp >= earliest,
        )
        .all()
    )
    trained_weeks = set()
    for (ts,) in timestamps:
        week_offset = (monday - ts.date()).days // 7
        if 0 <= week_offset < num_weeks:
            trained_weeks.add(week_offset)
    return trained_weeks


def check_deload_reminder(user_id, threshold_weeks=6):
    """Return (should_deload, consecutive_weeks) if the user has trained
    for *threshold_weeks* consecutive weeks without a break."""
    trained_weeks = _get_trained_weeks(user_id, num_weeks=12)
    consecutive = 0
    for i in range(12):
        if i in trained_weeks:
            consecutive += 1
        else:
            break
    return consecutive >= threshold_weeks, consecutive


def _session_volume(s):
    """Safely compute volume for a session, returns 0 for cardio sessions."""
    if s.weight is not None and s.repetitions is not None:
        return s.weight * s.repetitions
    return 0


def _session_weight(s):
    """Safely get weight for a session, returns 0 for cardio sessions."""
    return s.weight if s.weight is not None else 0


def calculate_exercise_statistics(sessions, moving_window=5):
    sorted_sessions = sorted(sessions, key=lambda s: s.timestamp)
    chart_data = {
        'labels': [],
        'iso_timestamps': [],
        'weights': [],
        'repetitions': [],
        'volume': [],
        'one_rm': [],
        'moving_avg_weight': [],
        'moving_avg_volume': [],
        'moving_avg_one_rm': [],
        'notes': [],
        'perceived_exertion': [],
    }
    personal_bests = {
        'max_weight': None,
        'max_volume': None,
        'max_one_rm': None,
    }
    summary = {
        'total_sessions': 0,
        'total_volume': 0,
        'average_volume': 0,
        'average_weight': 0,
        'latest_session': None,
        'recent_volume_average': 0,
        'recent_one_rm_average': 0,
    }
    if not sorted_sessions:
        return {
            'chart_data': chart_data,
            'personal_bests': personal_bests,
            'summary': summary,
            'moving_window': moving_window,
        }

    for session in sorted_sessions:
        chart_data['labels'].append(session.timestamp.strftime('%d.%m.%Y %H:%M'))
        chart_data['iso_timestamps'].append(session.timestamp.isoformat())
        chart_data['weights'].append(session.weight or 0)
        chart_data['repetitions'].append(session.repetitions or 0)
        chart_data['notes'].append(session.notes or '')
        chart_data['perceived_exertion'].append(session.perceived_exertion)
        chart_data['volume'].append(_session_volume(session))
        w = session.weight or 0
        r = session.repetitions or 0
        chart_data['one_rm'].append(round(w * (1 + r / 30.0), 2))

    moving_avg_weight = _moving_average(chart_data['weights'], moving_window)
    moving_avg_volume = _moving_average(chart_data['volume'], moving_window)
    moving_avg_one_rm = _moving_average(chart_data['one_rm'], moving_window)
    chart_data['moving_avg_weight'] = [round(value, 2) for value in moving_avg_weight]
    chart_data['moving_avg_volume'] = [round(value, 2) for value in moving_avg_volume]
    chart_data['moving_avg_one_rm'] = [round(value, 2) for value in moving_avg_one_rm]

    summary['total_sessions'] = len(sorted_sessions)
    summary['total_volume'] = sum(chart_data['volume'])
    summary['average_volume'] = summary['total_volume'] / summary['total_sessions'] if summary['total_sessions'] else 0
    summary['average_weight'] = sum(chart_data['weights']) / summary['total_sessions'] if summary['total_sessions'] else 0
    summary['latest_session'] = {
        'timestamp': sorted_sessions[-1].timestamp,
        'weight': sorted_sessions[-1].weight,
        'repetitions': sorted_sessions[-1].repetitions,
        'volume': chart_data['volume'][-1],
        'one_rm': chart_data['one_rm'][-1],
    }
    summary['recent_volume_average'] = round(moving_avg_volume[-1], 2) if moving_avg_volume else 0
    summary['recent_one_rm_average'] = round(moving_avg_one_rm[-1], 2) if moving_avg_one_rm else 0

    max_weight_index = max(range(len(chart_data['weights'])), key=chart_data['weights'].__getitem__)
    max_volume_index = max(range(len(chart_data['volume'])), key=chart_data['volume'].__getitem__)
    max_one_rm_index = max(range(len(chart_data['one_rm'])), key=chart_data['one_rm'].__getitem__)

    personal_bests['max_weight'] = {
        'value': chart_data['weights'][max_weight_index],
        'repetitions': chart_data['repetitions'][max_weight_index],
        'timestamp': sorted_sessions[max_weight_index].timestamp,
    }
    personal_bests['max_volume'] = {
        'value': chart_data['volume'][max_volume_index],
        'repetitions': chart_data['repetitions'][max_volume_index],
        'weight': chart_data['weights'][max_volume_index],
        'timestamp': sorted_sessions[max_volume_index].timestamp,
    }
    personal_bests['max_one_rm'] = {
        'value': chart_data['one_rm'][max_one_rm_index],
        'repetitions': chart_data['repetitions'][max_one_rm_index],
        'weight': chart_data['weights'][max_one_rm_index],
        'timestamp': sorted_sessions[max_one_rm_index].timestamp,
    }

    return {
        'chart_data': chart_data,
        'personal_bests': personal_bests,
        'summary': summary,
        'moving_window': moving_window,
    }


def calculate_progression_suggestion(sessions):
    """Berechnet einen Progressions-Vorschlag basierend auf den letzten Sessions."""
    if len(sessions) < 3:
        return None
    sorted_sessions = sorted(sessions, key=lambda s: s.timestamp, reverse=True)
    last_3 = sorted_sessions[:3]
    weight = last_3[0].weight
    # Prüfen ob die letzten 3 Sätze alle das gleiche Gewicht hatten
    same_weight = all(s.weight == weight for s in last_3)
    if not same_weight:
        return None
    reps = [s.repetitions for s in last_3]
    avg_reps = sum(reps) / len(reps)
    min_reps = min(reps)
    # Wenn alle Sätze mindestens 10 Wiederholungen hatten → Gewicht erhöhen
    if min_reps >= 10:
        new_weight = weight + 2.5
        return {
            'type': 'increase_weight',
            'current_weight': weight,
            'suggested_weight': new_weight,
            'avg_reps': round(avg_reps, 1),
            'message': f'Du schaffst konstant {min_reps}+ Wdh bei {weight} kg. Steigere auf {new_weight} kg!',
        }
    # Wenn unter 6 Wiederholungen → Gewicht reduzieren
    if avg_reps < 6 and weight > 5:
        new_weight = weight - 2.5
        return {
            'type': 'decrease_weight',
            'current_weight': weight,
            'suggested_weight': new_weight,
            'avg_reps': round(avg_reps, 1),
            'message': f'Durchschnittlich nur {round(avg_reps, 1)} Wdh bei {weight} kg. Versuche {new_weight} kg für mehr Wiederholungen.',
        }
    # Sonst: Wiederholungen steigern
    target_reps = int(avg_reps) + 1
    return {
        'type': 'increase_reps',
        'current_weight': weight,
        'suggested_weight': weight,
        'avg_reps': round(avg_reps, 1),
        'message': f'Versuche {target_reps} Wdh bei {weight} kg zu erreichen.',
    }


def check_new_personal_records(exercise_id, user_id, new_weight, new_reps):
    """Prüft ob ein neuer Satz einen persönlichen Rekord darstellt."""
    previous_sessions = (
        ExerciseSession.query
        .filter_by(exercise_id=exercise_id, user_id=user_id)
        .all()
    )
    # Nur Sessions mit Gewicht/Reps berücksichtigen
    previous_sessions = [s for s in previous_sessions if s.weight is not None and s.repetitions is not None]
    if not previous_sessions:
        return []
    records = []
    new_weight = float(new_weight)
    new_reps = float(new_reps)
    max_weight = max(s.weight for s in previous_sessions)
    if new_weight > max_weight:
        records.append(f'Neuer Gewichtsrekord: {new_weight} kg! (vorher: {max_weight} kg)')
    max_volume = max(s.weight * s.repetitions for s in previous_sessions)
    new_volume = new_weight * new_reps
    if new_volume > max_volume:
        records.append(f'Neues Volumenrekord: {new_volume} kg! (vorher: {max_volume} kg)')
    new_one_rm = round(new_weight * (1 + new_reps / 30.0), 1)
    max_one_rm = max(round(s.weight * (1 + s.repetitions / 30.0), 1) for s in previous_sessions)
    if new_one_rm > max_one_rm:
        records.append(f'Neue geschätzte 1RM: {new_one_rm} kg! (vorher: {max_one_rm} kg)')
    return records


def serialize_personal_bests(personal_bests):
    serialized = {}
    for key, entry in personal_bests.items():
        if entry is None:
            serialized[key] = None
        else:
            serialized_entry = {}
            for entry_key, entry_value in entry.items():
                if entry_key == 'timestamp' and entry_value is not None:
                    serialized_entry[entry_key] = entry_value.isoformat()
                else:
                    serialized_entry[entry_key] = entry_value
            serialized[key] = serialized_entry
    return serialized


def serialize_summary(summary):
    data = {
        key: value
        for key, value in summary.items()
        if key != 'latest_session'
    }
    latest_session = summary.get('latest_session')
    if latest_session:
        data['latest_session'] = {
            'timestamp': latest_session['timestamp'].isoformat() if latest_session.get('timestamp') else None,
            'weight': latest_session.get('weight'),
            'repetitions': latest_session.get('repetitions'),
            'volume': latest_session.get('volume'),
            'one_rm': latest_session.get('one_rm'),
        }
    else:
        data['latest_session'] = None
    return data


# ----------------------------------------------------
# Achievements / Badges
# ----------------------------------------------------
ACHIEVEMENTS = [
    # (id, name, beschreibung, bedingung_fn)
    ('first_session', 'Erster Satz', 'Deinen allerersten Satz geloggt', lambda s, d, r: s >= 1),
    ('sets_10', '10 Sätze', '10 Sätze absolviert', lambda s, d, r: s >= 10),
    ('sets_50', '50 Sätze', '50 Sätze absolviert', lambda s, d, r: s >= 50),
    ('sets_100', 'Century Club', '100 Sätze absolviert', lambda s, d, r: s >= 100),
    ('sets_500', 'Eisenkrieger', '500 Sätze absolviert', lambda s, d, r: s >= 500),
    ('sets_1000', 'Legende', '1000 Sätze absolviert', lambda s, d, r: s >= 1000),
    ('days_7', 'Erste Woche', 'An 7 verschiedenen Tagen trainiert', lambda s, d, r: d >= 7),
    ('days_30', 'Monatskämpfer', 'An 30 verschiedenen Tagen trainiert', lambda s, d, r: d >= 30),
    ('days_100', 'Dauerläufer', 'An 100 verschiedenen Tagen trainiert', lambda s, d, r: d >= 100),
    ('days_365', 'Jahresmeister', 'An 365 verschiedenen Tagen trainiert', lambda s, d, r: d >= 365),
    ('reg_30', '30 Tage dabei', 'Seit 30 Tagen registriert', lambda s, d, r: r >= 30),
    ('reg_180', 'Halbzeit', 'Seit 6 Monaten registriert', lambda s, d, r: r >= 180),
    ('reg_365', 'Ein Jahr dabei', 'Seit einem Jahr registriert', lambda s, d, r: r >= 365),
]
