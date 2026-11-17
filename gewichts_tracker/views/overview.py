"""Seiten: Dashboard, Statistik, Achievements, Hilfe."""

import datetime

from flask import render_template
from flask_login import current_user, login_required
from sqlalchemy.orm import joinedload

from gewichts_tracker.core import _utcnow, app, db
from gewichts_tracker.models import ExerciseSession, PlannedTraining, TrainingPlan
from gewichts_tracker.stats import (
    _get_trained_weeks,
    _session_volume,
    _session_weight,
    ACHIEVEMENTS,
    check_deload_reminder,
)


@app.route('/dashboard')
@login_required
def dashboard():
    training_plans = TrainingPlan.query.filter_by(user_id=current_user.id).all()
    deload_needed, weeks_trained = check_deload_reminder(current_user.id)

    # Quick-Stats für diese Woche
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

    # Trainings-Streak (aufeinanderfolgende Wochen mit Training, 1 Query statt 52)
    trained_weeks = _get_trained_weeks(current_user.id, num_weeks=52)
    streak = 0
    for i in range(52):
        if i in trained_weeks:
            streak += 1
        else:
            break

    # Nächste geplante Trainings (die nächsten 7 Tage)
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

    return render_template(
        'dashboard.html',
        training_plans=training_plans,
        deload_needed=deload_needed,
        weeks_trained=weeks_trained,
        week_sets=week_sets,
        week_volume=week_volume,
        week_days=week_days,
        streak=streak,
        upcoming_planned=upcoming_planned,
        today=today,
    )


@app.route('/statistics')
@login_required
def statistics():
    now = _utcnow()
    # Alle Sessions des Users (mit Exercise eager-loaded, vermeidet N+1)
    all_sessions = (
        ExerciseSession.query
        .options(joinedload(ExerciseSession.exercise))
        .filter_by(user_id=current_user.id)
        .order_by(ExerciseSession.timestamp.desc())
        .all()
    )
    # Kraft- und Ausdauer-Sessions trennen
    kraft_sessions = [s for s in all_sessions if s.weight is not None and s.repetitions is not None]
    cardio_sessions = [s for s in all_sessions if s.exercise.exercise_type == 'ausdauer']

    # --- Muskelgruppen-Volumen (nur Kraft) ---
    muscle_volume = {}
    for s in kraft_sessions:
        mg = s.exercise.muscle_group or 'Nicht zugeordnet'
        volume = _session_volume(s)
        muscle_volume[mg] = muscle_volume.get(mg, 0) + volume
    muscle_labels = list(muscle_volume.keys())
    muscle_values = list(muscle_volume.values())

    # --- Vergleich diese Woche vs. letzte Woche ---
    today = now.date()
    # Montag dieser Woche
    this_monday = today - datetime.timedelta(days=today.weekday())
    last_monday = this_monday - datetime.timedelta(days=7)
    this_week_sessions = [
        s for s in kraft_sessions
        if s.timestamp.date() >= this_monday
    ]
    last_week_sessions = [
        s for s in kraft_sessions
        if last_monday <= s.timestamp.date() < this_monday
    ]
    this_week_volume = sum(_session_volume(s) for s in this_week_sessions)
    last_week_volume = sum(_session_volume(s) for s in last_week_sessions)
    this_week_sets = len(this_week_sessions)
    last_week_sets = len(last_week_sessions)
    volume_diff = this_week_volume - last_week_volume
    sets_diff = this_week_sets - last_week_sets

    # Vergleich pro Übung (nur Kraft)
    exercise_comparison = []
    this_week_by_exercise = {}
    last_week_by_exercise = {}
    for s in this_week_sessions:
        name = s.exercise.name
        if name not in this_week_by_exercise:
            this_week_by_exercise[name] = {'sets': 0, 'volume': 0, 'max_weight': 0}
        this_week_by_exercise[name]['sets'] += 1
        this_week_by_exercise[name]['volume'] += _session_volume(s)
        this_week_by_exercise[name]['max_weight'] = max(this_week_by_exercise[name]['max_weight'], _session_weight(s))
    for s in last_week_sessions:
        name = s.exercise.name
        if name not in last_week_by_exercise:
            last_week_by_exercise[name] = {'sets': 0, 'volume': 0, 'max_weight': 0}
        last_week_by_exercise[name]['sets'] += 1
        last_week_by_exercise[name]['volume'] += _session_volume(s)
        last_week_by_exercise[name]['max_weight'] = max(last_week_by_exercise[name]['max_weight'], _session_weight(s))
    all_exercise_names = sorted(set(list(this_week_by_exercise.keys()) + list(last_week_by_exercise.keys())))
    for name in all_exercise_names:
        tw = this_week_by_exercise.get(name, {'sets': 0, 'volume': 0, 'max_weight': 0})
        lw = last_week_by_exercise.get(name, {'sets': 0, 'volume': 0, 'max_weight': 0})
        exercise_comparison.append({
            'name': name,
            'this_week': tw,
            'last_week': lw,
            'volume_diff': tw['volume'] - lw['volume'],
            'weight_diff': tw['max_weight'] - lw['max_weight'],
        })

    # --- Trainingsfrequenz (letzte 12 Wochen) ---
    frequency_data = []
    for i in range(11, -1, -1):
        week_start = this_monday - datetime.timedelta(weeks=i)
        week_end = week_start + datetime.timedelta(days=7)
        week_sess = [
            s for s in kraft_sessions
            if week_start <= s.timestamp.date() < week_end
        ]
        training_days = len(set(s.timestamp.date() for s in week_sess))
        week_label = week_start.strftime('%d.%m')
        frequency_data.append({
            'label': week_label,
            'days': training_days,
            'sets': len(week_sess),
            'volume': sum(_session_volume(s) for s in week_sess),
        })

    # --- Ausdauer-Statistiken ---
    cardio_total_sessions = len(cardio_sessions)
    cardio_total_duration = sum(s.duration_minutes or 0 for s in cardio_sessions)
    cardio_total_distance = sum(s.distance_km or 0 for s in cardio_sessions)
    cardio_avg_duration = round(cardio_total_duration / cardio_total_sessions) if cardio_total_sessions else 0

    # Ausdauer diese Woche vs. letzte Woche
    cardio_this_week = [s for s in cardio_sessions if s.timestamp.date() >= this_monday]
    cardio_last_week = [s for s in cardio_sessions if last_monday <= s.timestamp.date() < this_monday]
    cardio_tw_duration = sum(s.duration_minutes or 0 for s in cardio_this_week)
    cardio_lw_duration = sum(s.duration_minutes or 0 for s in cardio_last_week)
    cardio_tw_distance = sum(s.distance_km or 0 for s in cardio_this_week)
    cardio_lw_distance = sum(s.distance_km or 0 for s in cardio_last_week)

    # Ausdauer pro Aktivität
    cardio_by_activity = {}
    for s in cardio_sessions:
        name = s.exercise.name
        if name not in cardio_by_activity:
            cardio_by_activity[name] = {'sessions': 0, 'duration': 0, 'distance': 0}
        cardio_by_activity[name]['sessions'] += 1
        cardio_by_activity[name]['duration'] += s.duration_minutes or 0
        cardio_by_activity[name]['distance'] += s.distance_km or 0
    cardio_activities = sorted(cardio_by_activity.items(), key=lambda x: x[1]['duration'], reverse=True)

    # Ausdauer-Frequenz (letzte 12 Wochen)
    cardio_frequency_data = []
    for i in range(11, -1, -1):
        week_start = this_monday - datetime.timedelta(weeks=i)
        week_end = week_start + datetime.timedelta(days=7)
        week_cardio = [
            s for s in cardio_sessions
            if week_start <= s.timestamp.date() < week_end
        ]
        week_label = week_start.strftime('%d.%m')
        cardio_frequency_data.append({
            'label': week_label,
            'sessions': len(week_cardio),
            'duration': sum(s.duration_minutes or 0 for s in week_cardio),
            'distance': round(sum(s.distance_km or 0 for s in week_cardio), 1),
        })

    return render_template(
        'statistics.html',
        muscle_labels=muscle_labels,
        muscle_values=muscle_values,
        this_week_volume=this_week_volume,
        last_week_volume=last_week_volume,
        volume_diff=volume_diff,
        this_week_sets=this_week_sets,
        last_week_sets=last_week_sets,
        sets_diff=sets_diff,
        exercise_comparison=exercise_comparison,
        frequency_data=frequency_data,
        # Cardio
        cardio_total_sessions=cardio_total_sessions,
        cardio_total_duration=cardio_total_duration,
        cardio_total_distance=round(cardio_total_distance, 1),
        cardio_avg_duration=cardio_avg_duration,
        cardio_tw_duration=cardio_tw_duration,
        cardio_lw_duration=cardio_lw_duration,
        cardio_tw_distance=round(cardio_tw_distance, 1),
        cardio_lw_distance=round(cardio_lw_distance, 1),
        cardio_tw_sessions=len(cardio_this_week),
        cardio_lw_sessions=len(cardio_last_week),
        cardio_activities=cardio_activities,
        cardio_frequency_data=cardio_frequency_data,
    )


@app.route('/achievements')
@login_required
def achievements():
    total_sessions = ExerciseSession.query.filter_by(user_id=current_user.id).count()
    training_days = db.session.query(
        db.func.date(ExerciseSession.timestamp)
    ).filter_by(user_id=current_user.id).distinct().count()
    reg_days = (_utcnow() - (current_user.registration_date or _utcnow())).days

    earned = []
    locked = []
    for aid, name, desc, check_fn in ACHIEVEMENTS:
        if check_fn(total_sessions, training_days, reg_days):
            earned.append({'id': aid, 'name': name, 'description': desc})
        else:
            locked.append({'id': aid, 'name': name, 'description': desc})

    return render_template(
        'achievements.html',
        earned=earned,
        locked=locked,
        total_sessions=total_sessions,
        training_days=training_days,
        reg_days=reg_days,
    )


# ----------------------------------------------------
# Hilfe / FAQ
# ----------------------------------------------------
@app.route('/hilfe')
@login_required
def hilfe():
    return render_template('hilfe.html')
