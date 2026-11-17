"""JSON-Darstellung von Plänen, Übungen und Sessions."""




def serialize_training_plan(plan):
    return {
        'id': plan.id,
        'title': plan.title,
        'description': plan.description,
    }


def serialize_exercise(exercise):
    data = {
        'id': exercise.id,
        'name': exercise.name,
        'description': exercise.description,
    }
    if exercise.is_separator:
        data['is_separator'] = True
    return data


def serialize_session(session):
    data = {
        'id': session.id,
        'timestamp': session.timestamp.isoformat() if session.timestamp else None,
        'weight': session.weight,
        'repetitions': session.repetitions,
        'notes': session.notes,
        'perceived_exertion': session.perceived_exertion,
        'duration_minutes': session.duration_minutes,
        'distance_km': session.distance_km,
        'warmup_activity': session.warmup_activity,
        'warmup_duration': session.warmup_duration,
    }
    return data
