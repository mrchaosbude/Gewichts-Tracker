"""Seiten: Trainingspläne, Übungen, Sessions."""

import datetime
import uuid

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from gewichts_tracker import services
from gewichts_tracker.core import _utcnow, app, db
from gewichts_tracker.models import (
    CARDIO_EXERCISES,
    Exercise,
    ExerciseSession,
    get_app_settings,
    TrainingPlan,
)
from gewichts_tracker.security import sanitize_external_url
from gewichts_tracker.serializers import serialize_session
from gewichts_tracker.permissions import exercise_owned_exclusively_by, trainer_or_admin_required
from gewichts_tracker.stats import (
    calculate_exercise_statistics,
    calculate_progression_suggestion,
    check_new_personal_records,
)
from gewichts_tracker.markdown_import import parse_training_plan_markdown
from gewichts_tracker.forms import (
    DeleteExerciseForm,
    DeleteSessionForm,
    DeleteTrainingPlanForm,
    EditSessionForm,
    ExerciseSessionForm,
    ExerciseTemplateForm,
    MarkdownImportForm,
    TrainingPlanForm,
)


@app.route('/create_training_plan', methods=['GET','POST'])
@login_required
def create_training_plan():
    form = TrainingPlanForm()
    if form.validate_on_submit():
        new_plan = TrainingPlan(
            title=form.title.data,
            description=form.description.data,
            user_id=current_user.id
        )
        db.session.add(new_plan)
        db.session.commit()
        flash('Trainingsplan erstellt!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_training_plan.html', form=form)


@app.route('/import_training_plan', methods=['GET', 'POST'])
@login_required
@trainer_or_admin_required
def import_training_plan():
    form = MarkdownImportForm()
    preview = None

    if form.validate_on_submit():
        parsed = parse_training_plan_markdown(form.markdown_content.data)

        # Check if this is a preview request
        if request.form.get('action') == 'preview':
            preview = parsed
            return render_template('import_training_plan.html', form=form, preview=preview)

        # Import action
        if not parsed['success']:
            for error in parsed['errors']:
                flash(error, 'danger')
            return render_template('import_training_plan.html', form=form, preview=parsed)

        # Create the training plan
        new_plan = TrainingPlan(
            title=parsed['plan_title'],
            description=parsed['plan_description'],
            user_id=current_user.id
        )
        db.session.add(new_plan)
        db.session.flush()

        # Create exercises - each user gets their own copy
        for ex_data in parsed['exercises']:
            exercise = Exercise(
                name=ex_data['name'],
                description=ex_data['description'] if not ex_data.get('is_separator') else None,
                is_separator=ex_data.get('is_separator', False),
                muscle_group=ex_data.get('muscle_group') or None,
                exercise_type=ex_data.get('exercise_type') or 'kraft',
                video_url=sanitize_external_url(ex_data.get('video_url')),
                user_id=current_user.id
            )
            db.session.add(exercise)
            db.session.flush()
            new_plan.exercises.append(exercise)

        db.session.commit()
        flash(f"Trainingsplan '{new_plan.title}' mit {len(parsed['exercises'])} Übungen importiert!", 'success')
        return redirect(url_for('training_plan_detail', training_plan_id=new_plan.id))

    return render_template('import_training_plan.html', form=form, preview=preview)


@app.route('/training_plan/<int:training_plan_id>')
@login_required
def training_plan_detail(training_plan_id):
    training_plan = TrainingPlan.query.get_or_404(training_plan_id)
    if training_plan.user_id != current_user.id:
        abort(403)
    delete_plan_form = DeleteTrainingPlanForm()
    editable_map = {
        ex.id: exercise_owned_exclusively_by(current_user.id, ex)
        for ex in training_plan.exercises
    }
    # Superset-Gruppen und Positionen laden
    superset_map = {}
    position_map = {}
    rows = db.session.execute(
        db.text('SELECT exercise_id, superset_group, position FROM plan_exercises WHERE training_plan_id = :pid'),
        {'pid': training_plan_id}
    ).fetchall()
    for row in rows:
        if row[1] is not None:
            superset_map[row[0]] = row[1]
        position_map[row[0]] = row[2] if row[2] is not None else 999999
    # Übungen nach Position sortieren
    sorted_exercises = sorted(training_plan.exercises, key=lambda ex: (position_map.get(ex.id, 999999), ex.id))
    # Alle Sessions des Users für alle Übungen dieses Plans in einer Query laden (vermeidet N+1)
    exercise_ids = [ex.id for ex in sorted_exercises if not ex.is_separator]
    all_plan_sessions = (
        ExerciseSession.query
        .filter(
            ExerciseSession.exercise_id.in_(exercise_ids),
            ExerciseSession.user_id == current_user.id,
        )
        .all()
    ) if exercise_ids else []
    sessions_by_exercise = {}
    for s in all_plan_sessions:
        sessions_by_exercise.setdefault(s.exercise_id, []).append(s)
    exercise_overview = []
    for exercise in sorted_exercises:
        if exercise.is_separator:
            exercise_overview.append({
                'exercise': exercise,
                'summary': None,
                'personal_bests': None,
                'recent_sessions': [],
                'moving_window': 5,
                'superset_group': None,
                'is_separator': True,
            })
            continue
        user_sessions = sessions_by_exercise.get(exercise.id, [])
        is_cardio = (exercise.exercise_type == 'ausdauer')
        if is_cardio:
            # Einfache Cardio-Stats (keine Gewicht/Reps-Berechnungen)
            recent_sessions_sorted = sorted(user_sessions, key=lambda s: s.timestamp, reverse=True)[:3]
            latest = recent_sessions_sorted[0] if recent_sessions_sorted else None
            cardio_summary = {
                'total_sessions': len(user_sessions),
                'total_volume': 0,
                'average_volume': 0,
                'average_weight': 0,
                'latest_session': {
                    'timestamp': latest.timestamp,
                    'weight': None,
                    'repetitions': None,
                    'duration_minutes': latest.duration_minutes,
                    'volume': 0,
                    'one_rm': 0,
                } if latest else None,
                'recent_volume_average': 0,
                'recent_one_rm_average': 0,
            }
            exercise_overview.append({
                'exercise': exercise,
                'summary': cardio_summary,
                'personal_bests': {'max_weight': None, 'max_volume': None, 'max_one_rm': None},
                'recent_sessions': recent_sessions_sorted,
                'moving_window': 5,
                'superset_group': superset_map.get(exercise.id),
                'is_separator': False,
            })
        else:
            # Nur Kraft-Sessions für die Statistikberechnung verwenden
            kraft_sessions = [s for s in user_sessions if s.weight is not None and s.repetitions is not None]
            stats = calculate_exercise_statistics(kraft_sessions)
            recent_sessions = sorted(user_sessions, key=lambda s: s.timestamp, reverse=True)[:3]
            exercise_overview.append({
                'exercise': exercise,
                'summary': stats['summary'],
                'personal_bests': stats['personal_bests'],
                'recent_sessions': recent_sessions,
                'moving_window': stats['moving_window'],
                'superset_group': superset_map.get(exercise.id),
                'is_separator': False,
            })
    return render_template(
        'training_plan_detail.html',
        training_plan=training_plan,
        delete_plan_form=delete_plan_form,
        editable_map=editable_map,
        exercise_overview=exercise_overview,
    )


@app.route('/training_plan/<int:training_plan_id>/set_superset', methods=['POST'])
@login_required
def set_superset(training_plan_id):
    training_plan = TrainingPlan.query.get_or_404(training_plan_id)
    if training_plan.user_id != current_user.id:
        abort(403)
    exercise_id = request.form.get('exercise_id', type=int)
    if exercise_id is None:
        abort(400)
    try:
        group = services.set_superset_group(training_plan, exercise_id, request.form.get('superset_group', type=int))
    except ValueError as exc:
        flash(str(exc), 'danger')
        return redirect(url_for('training_plan_detail', training_plan_id=training_plan_id))
    db.session.commit()
    if group:
        flash(f'Übung zu Superset {group} zugeordnet.', 'success')
    else:
        flash('Superset-Zuordnung entfernt.', 'info')
    return redirect(url_for('training_plan_detail', training_plan_id=training_plan_id))


@app.route('/training_plan/<int:training_plan_id>/reorder', methods=['POST'])
@login_required
def reorder_exercise(training_plan_id):
    training_plan = TrainingPlan.query.get_or_404(training_plan_id)
    if training_plan.user_id != current_user.id:
        abort(403)
    exercise_id = request.form.get('exercise_id', type=int)
    direction = request.form.get('direction')  # 'up' or 'down'
    if exercise_id is None or direction not in ('up', 'down'):
        abort(400)
    if not services.move_exercise(training_plan, exercise_id, direction):
        abort(400)
    db.session.commit()
    return redirect(url_for('training_plan_detail', training_plan_id=training_plan_id))


@app.route('/training_plan/<int:training_plan_id>/share', methods=['POST'])
@login_required
def share_training_plan(training_plan_id):
    training_plan = TrainingPlan.query.get_or_404(training_plan_id)
    if training_plan.user_id != current_user.id:
        abort(403)
    if not training_plan.share_token:
        training_plan.share_token = str(uuid.uuid4())
        db.session.commit()
    share_url = request.url_root.rstrip('/') + url_for('copy_shared_plan', token=training_plan.share_token)
    flash(f'Share-Link: {share_url}', 'success')
    return redirect(url_for('training_plan_detail', training_plan_id=training_plan_id))


@app.route('/training_plan/<int:training_plan_id>/unshare', methods=['POST'])
@login_required
def unshare_training_plan(training_plan_id):
    training_plan = TrainingPlan.query.get_or_404(training_plan_id)
    if training_plan.user_id != current_user.id:
        abort(403)
    training_plan.share_token = None
    db.session.commit()
    flash('Teilen deaktiviert.', 'info')
    return redirect(url_for('training_plan_detail', training_plan_id=training_plan_id))


@app.route('/shared/<token>', methods=['GET', 'POST'])
@login_required
def copy_shared_plan(token):
    source_plan = TrainingPlan.query.filter_by(share_token=token).first_or_404()
    if source_plan.user_id == current_user.id:
        flash('Das ist dein eigener Plan.', 'info')
        return redirect(url_for('training_plan_detail', training_plan_id=source_plan.id))
    if request.method != 'POST':
        # Nur anzeigen; kopiert wird erst nach Bestätigung (kein ungewolltes Anlegen per Link)
        return render_template('shared_plan.html', plan=source_plan, token=token, form=DeleteTrainingPlanForm())
    new_plan = services.copy_shared_plan_for(source_plan, current_user.id)
    db.session.commit()
    flash(f'Trainingsplan "{source_plan.title}" wurde kopiert!', 'success')
    return redirect(url_for('training_plan_detail', training_plan_id=new_plan.id))


@app.route('/training_plan/<int:training_plan_id>/print')
@login_required
def print_training_plan(training_plan_id):
    training_plan = TrainingPlan.query.get_or_404(training_plan_id)
    if training_plan.user_id != current_user.id:
        abort(403)
    include_sessions = request.args.get('include_sessions', '0') == '1'
    # Alle Sessions des Users für diesen Plan in einer Query laden (vermeidet N+1)
    print_exercise_ids = [ex.id for ex in training_plan.exercises if not ex.is_separator]
    all_print_sessions = (
        ExerciseSession.query
        .filter(
            ExerciseSession.exercise_id.in_(print_exercise_ids),
            ExerciseSession.user_id == current_user.id,
        )
        .all()
    ) if print_exercise_ids else []
    print_sessions_map = {}
    for s in all_print_sessions:
        print_sessions_map.setdefault(s.exercise_id, []).append(s)
    exercise_overview = []
    for exercise in training_plan.exercises:
        if exercise.is_separator:
            exercise_overview.append({
                'exercise': exercise,
                'summary': None,
                'personal_bests': None,
                'recent_sessions': [],
                'is_separator': True,
            })
            continue
        user_sessions = print_sessions_map.get(exercise.id, [])
        user_sessions_sorted = sorted(user_sessions, key=lambda s: s.timestamp, reverse=True)
        stats = calculate_exercise_statistics(user_sessions)
        exercise_overview.append({
            'exercise': exercise,
            'summary': stats['summary'],
            'personal_bests': stats['personal_bests'],
            'recent_sessions': user_sessions_sorted[:10] if include_sessions else [],
            'is_separator': False,
        })
    return render_template(
        'print_training_plan.html',
        training_plan=training_plan,
        exercise_overview=exercise_overview,
        include_sessions=include_sessions,
        print_date=_utcnow()
    )


@app.route('/training_plan/<int:training_plan_id>/add_exercise', methods=['GET','POST'])
@login_required
def add_exercise_to_plan(training_plan_id):
    training_plan = TrainingPlan.query.get_or_404(training_plan_id)
    if training_plan.user_id != current_user.id:
        abort(403)
    form = ExerciseTemplateForm()
    existing_exercises = (
        Exercise.query
        .join(Exercise.training_plans)
        .filter(TrainingPlan.user_id == current_user.id)
        .filter(Exercise.is_separator != True)
        .order_by(Exercise.name)
        .distinct()
        .all()
    )
    if form.validate_on_submit():
        if form.is_separator.data:
            exercise = Exercise(
                name=form.name.data,
                is_separator=True,
                user_id=current_user.id,
            )
            db.session.add(exercise)
            db.session.flush()
        else:
            selected_id = request.form.get('existing_exercise_id')
            if selected_id:
                exercise = Exercise.query.get_or_404(int(selected_id))
                if not any(p.user_id == current_user.id for p in exercise.training_plans):
                    abort(403)
            else:
                exercise_type = form.exercise_type.data or 'kraft'
                if exercise_type == 'ausdauer':
                    cardio_name = (request.form.get('cardio_custom') or form.cardio_type.data or '').strip()
                    exercise_name = cardio_name if cardio_name else 'Ausdauer'
                    exercise = Exercise(
                        name=exercise_name,
                        exercise_type='ausdauer',
                        user_id=current_user.id,
                    )
                else:
                    if not form.name.data:
                        flash('Bitte einen Übungsnamen eingeben.', 'danger')
                        return render_template('add_exercise_to_plan.html', form=form, training_plan=training_plan,
                                               existing_exercises=existing_exercises, cardio_exercises=CARDIO_EXERCISES)
                    video_url = (form.video_url.data or '').strip()
                    if video_url and sanitize_external_url(video_url) is None:
                        flash('Ungültige Video-URL. Erlaubt sind nur Links mit http:// oder https://.', 'danger')
                        return render_template('add_exercise_to_plan.html', form=form, training_plan=training_plan,
                                               existing_exercises=existing_exercises, cardio_exercises=CARDIO_EXERCISES)
                    exercise = Exercise(
                        name=form.name.data,
                        description=form.description.data,
                        video_url=video_url or None,
                        muscle_group=form.muscle_group.data or None,
                        exercise_type='kraft',
                        user_id=current_user.id,
                    )
                db.session.add(exercise)
                db.session.flush()
        if exercise not in training_plan.exercises:
            training_plan.exercises.append(exercise)
        db.session.commit()
        flash('Trenner hinzugefügt!' if form.is_separator.data else 'Übung hinzugefügt!', 'success')
        return redirect(url_for('training_plan_detail', training_plan_id=training_plan_id))
    return render_template('add_exercise_to_plan.html', form=form, training_plan=training_plan,
                           existing_exercises=existing_exercises, cardio_exercises=CARDIO_EXERCISES)


@app.route('/exercise/<int:exercise_id>/add_session', methods=['GET','POST'])
@login_required
def add_session(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    if exercise.is_separator:
        abort(400)
    if not any(p.user_id == current_user.id for p in exercise.training_plans):
        abort(403)
    is_cardio = (exercise.exercise_type == 'ausdauer')
    form = ExerciseSessionForm()
    # Eigene Ausdauerübungen des Nutzers für das Aufwärm-Dropdown
    user_cardio_exercises = (
        Exercise.query
        .join(Exercise.training_plans)
        .filter(TrainingPlan.user_id == current_user.id)
        .filter(Exercise.exercise_type == 'ausdauer')
        .filter(Exercise.is_separator != True)
        .order_by(Exercise.name)
        .distinct()
        .all()
    )
    if request.method == 'GET':
        last_session = (
            ExerciseSession.query
            .filter_by(exercise_id=exercise_id, user_id=current_user.id)
            .order_by(ExerciseSession.timestamp.desc())
            .first()
        )
        if last_session:
            if is_cardio:
                form.duration_minutes.data = last_session.duration_minutes
                form.distance_km.data = last_session.distance_km
                form.warmup_activity.data = last_session.warmup_activity
            else:
                form.repetitions.data = last_session.repetitions
                form.weight.data = int(last_session.weight) if last_session.weight is not None else None
            form.perceived_exertion.data = last_session.perceived_exertion
            form.notes.data = last_session.notes
    if form.validate_on_submit():
        # Konditionelle Pflichtfeld-Prüfung
        if is_cardio:
            if not form.duration_minutes.data:
                form.duration_minutes.errors.append('Dauer ist erforderlich.')
                return render_template('add_session.html', form=form, exercise=exercise,
                                       is_cardio=is_cardio, cardio_exercises=CARDIO_EXERCISES,
                                       user_cardio_exercises=user_cardio_exercises)
        else:
            if form.weight.data is None:
                form.weight.errors.append('Gewicht ist erforderlich.')
                return render_template('add_session.html', form=form, exercise=exercise,
                                       is_cardio=is_cardio, cardio_exercises=CARDIO_EXERCISES,
                                       user_cardio_exercises=user_cardio_exercises)
            if not form.repetitions.data:
                form.repetitions.errors.append('Wiederholungen sind erforderlich.')
                return render_template('add_session.html', form=form, exercise=exercise,
                                       is_cardio=is_cardio, cardio_exercises=CARDIO_EXERCISES,
                                       user_cardio_exercises=user_cardio_exercises)
        # PR-Check nur für Kraftübungen
        pr_records = []
        if not is_cardio:
            pr_records = check_new_personal_records(
                exercise_id, current_user.id,
                form.weight.data, form.repetitions.data
            )
        distance_val = float(form.distance_km.data) if form.distance_km.data else None
        new_session = ExerciseSession(
            exercise_id=exercise_id,
            repetitions=form.repetitions.data if not is_cardio else None,
            weight=form.weight.data if not is_cardio else None,
            duration_minutes=form.duration_minutes.data if is_cardio else None,
            distance_km=distance_val if is_cardio else None,
            warmup_activity=form.warmup_activity.data or None,
            warmup_duration=form.warmup_duration.data if not is_cardio else None,
            timestamp=_utcnow(),
            perceived_exertion=form.perceived_exertion.data,
            notes=form.notes.data,
            user_id=current_user.id,
        )
        db.session.add(new_session)
        db.session.commit()
        flash('Eintrag hinzugefügt!', 'success')
        for pr in pr_records:
            flash(pr, 'warning')
        return redirect(url_for('exercise_detail', exercise_id=exercise_id))
    return render_template('add_session.html', form=form, exercise=exercise,
                           is_cardio=is_cardio, cardio_exercises=CARDIO_EXERCISES,
                           user_cardio_exercises=user_cardio_exercises)


@app.route('/exercise/<int:exercise_id>/detail')
@login_required
def exercise_detail(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    if exercise.is_separator:
        abort(404)
    if not any(p.user_id == current_user.id for p in exercise.training_plans):
        abort(403)
    user_plan = next((p for p in exercise.training_plans if p.user_id == current_user.id), None)
    editable = exercise_owned_exclusively_by(current_user.id, exercise)
    session_query = ExerciseSession.query.filter_by(
        exercise_id=exercise_id,
        user_id=current_user.id,
    )
    all_sessions = session_query.order_by(ExerciseSession.timestamp.asc()).all()
    sessions = session_query.order_by(ExerciseSession.timestamp.desc()).limit(15).all()

    is_cardio = (exercise.exercise_type == 'ausdauer')

    if is_cardio:
        stats = {'chart_data': {}, 'summary': {}, 'personal_bests': {}, 'moving_window': 5}
        progression = None
        total_dur = sum(s.duration_minutes or 0 for s in all_sessions)
        total_dist = sum(s.distance_km or 0 for s in all_sessions)
        avg_dur = round(total_dur / len(all_sessions)) if all_sessions else 0
        cardio_stats = {
            'total_sessions': len(all_sessions),
            'total_duration': total_dur,
            'avg_duration': avg_dur,
            'total_distance': round(total_dist, 1) if total_dist else None,
        }
    else:
        stats = calculate_exercise_statistics(all_sessions)
        progression = calculate_progression_suggestion(all_sessions)
        cardio_stats = None

    def _serialize_session_display(s):
        d = serialize_session(s)
        d['timestamp'] = s.timestamp.strftime('%d.%m.%Y %H:%M')
        return d
    all_sessions_serialized = [_serialize_session_display(s) for s in all_sessions]
    delete_exercise_form = DeleteExerciseForm()
    delete_session_form = DeleteSessionForm()
    app_settings = get_app_settings()
    chart_settings = {
        'weight': app_settings.chart_weight,
        'reps': app_settings.chart_reps,
        'volume': app_settings.chart_volume,
        'volume_avg': app_settings.chart_volume_avg,
        'one_rm': app_settings.chart_1rm,
        'one_rm_avg': app_settings.chart_1rm_avg,
    }
    return render_template(
        'exercise_detail.html',
        exercise=exercise,
        all_sessions=all_sessions_serialized,
        sessions=sessions,
        user_plan=user_plan,
        delete_exercise_form=delete_exercise_form,
        delete_session_form=delete_session_form,
        editable=editable,
        chart_data=stats['chart_data'],
        summary_metrics=stats['summary'],
        personal_bests=stats['personal_bests'],
        moving_window=stats['moving_window'],
        progression=progression,
        chart_settings=chart_settings,
        is_cardio=is_cardio,
        cardio_stats=cardio_stats,
    )


@app.route('/exercise/<int:exercise_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_exercise(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    if not any(p.user_id == current_user.id for p in exercise.training_plans):
        abort(403)
    user_plan = next((p for p in exercise.training_plans if p.user_id == current_user.id), None)
    if not exercise_owned_exclusively_by(current_user.id, exercise):
        flash('Diese Übung wird von anderen Benutzern verwendet und kann nicht bearbeitet werden.', 'warning')
        return redirect(url_for('training_plan_detail', training_plan_id=user_plan.id if user_plan else 0))
    form = ExerciseTemplateForm(obj=exercise)
    if form.validate_on_submit():
        exercise.name = form.name.data
        exercise.description = form.description.data
        exercise.muscle_group = form.muscle_group.data or None
        db.session.commit()
        flash('Übung aktualisiert!', 'success')
        return redirect(url_for('training_plan_detail', training_plan_id=user_plan.id if user_plan else 0))
    return render_template('edit_exercise.html', form=form, exercise=exercise, user_plan=user_plan)


@app.route('/training_plan/<int:training_plan_id>/delete', methods=['POST'])
@login_required
def delete_training_plan(training_plan_id):
    training_plan = TrainingPlan.query.get_or_404(training_plan_id)
    if training_plan.user_id != current_user.id:
        abort(403)
    form = DeleteTrainingPlanForm()
    if form.validate_on_submit():
        db.session.delete(training_plan)
        db.session.commit()
        flash('Trainingsplan gelöscht!', 'info')
        return redirect(url_for('dashboard'))
    abort(400)


@app.route('/exercise/<int:exercise_id>/delete', methods=['POST'])
@login_required
def delete_exercise(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    user_plan = services.user_plan_for_exercise(exercise, current_user.id)
    if not user_plan:
        abort(403)
    form = DeleteExerciseForm()
    if form.validate_on_submit():
        services.remove_exercise_from_plan(user_plan, exercise)
        db.session.commit()
        flash('Übung gelöscht!', 'info')
        return redirect(url_for('training_plan_detail', training_plan_id=user_plan.id))
    abort(400)


@app.route('/session/<int:session_id>/delete', methods=['POST'])
@login_required
def delete_session(session_id):
    session = ExerciseSession.query.get_or_404(session_id)
    if session.user_id != current_user.id:
        abort(403)
    if not any(p.user_id == current_user.id for p in session.exercise.training_plans):
        abort(403)
    exercise_id = session.exercise_id
    form = DeleteSessionForm()
    if form.validate_on_submit():
        db.session.delete(session)
        db.session.commit()
        flash('Satz gelöscht!', 'info')
        return redirect(url_for('exercise_detail', exercise_id=exercise_id))
    abort(400)


@app.route('/session/<int:session_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_session(session_id):
    session = ExerciseSession.query.get_or_404(session_id)
    if session.user_id != current_user.id:
        abort(403)
    exercise = session.exercise
    is_cardio = (exercise.exercise_type == 'ausdauer')
    form = EditSessionForm(obj=session if request.method == 'GET' else None)
    if request.method == 'GET':
        form.timestamp.data = session.timestamp.strftime('%Y-%m-%dT%H:%M') if session.timestamp else ''
    if form.validate_on_submit():
        try:
            timestamp = datetime.datetime.strptime(form.timestamp.data.strip()[:16], '%Y-%m-%dT%H:%M')
        except ValueError:
            timestamp = None
            form.timestamp.errors.append('Ungültiges Datum.')
        if is_cardio and not form.duration_minutes.data:
            form.duration_minutes.errors.append('Dauer ist erforderlich.')
        if not is_cardio and form.weight.data is None:
            form.weight.errors.append('Gewicht ist erforderlich.')
        if not is_cardio and not form.repetitions.data:
            form.repetitions.errors.append('Wiederholungen sind erforderlich.')
        if not any(field.errors for field in form):
            session.timestamp = timestamp
            if is_cardio:
                session.duration_minutes = form.duration_minutes.data
                session.distance_km = float(form.distance_km.data) if form.distance_km.data else None
            else:
                session.weight = float(form.weight.data)
                session.repetitions = form.repetitions.data
                session.warmup_duration = form.warmup_duration.data
            session.warmup_activity = form.warmup_activity.data or None
            session.perceived_exertion = form.perceived_exertion.data
            session.notes = form.notes.data or None
            db.session.commit()
            flash('Eintrag aktualisiert!', 'success')
            return redirect(url_for('exercise_detail', exercise_id=exercise.id))
    return render_template('edit_session.html', form=form, session=session, exercise=exercise, is_cardio=is_cardio)
