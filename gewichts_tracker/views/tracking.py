"""Seiten: Körpergewicht, Fortschrittsfotos, Kalender."""

import calendar as cal_module
import datetime
import os

from flask import abort, flash, make_response, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from gewichts_tracker import services
from gewichts_tracker.core import app, db, PHOTO_MIMETYPES
from gewichts_tracker.models import BodyWeight, ExerciseSession, PlannedTraining, ProgressPhoto
from gewichts_tracker.parsing import _parse_calendar_month_args
from gewichts_tracker.photos import progress_photo_path


from gewichts_tracker.stats import _session_volume
from gewichts_tracker.forms import BodyWeightForm, DeleteBodyWeightForm


# ----------------------------------------------------
# Fortschrittsfotos
# ----------------------------------------------------
@app.route('/progress_photos', methods=['GET', 'POST'])
@login_required
def progress_photos():
    if request.method == 'POST':
        try:
            services.create_progress_photo(
                current_user.id,
                request.files.get('photo'),
                notes=request.form.get('notes', ''),
                body_weight=request.form.get('body_weight', ''),
            )
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), 'danger')
            return redirect(url_for('progress_photos'))
        db.session.commit()
        flash('Foto hochgeladen!', 'success')
        return redirect(url_for('progress_photos'))

    photos = (
        ProgressPhoto.query
        .filter_by(user_id=current_user.id)
        .order_by(ProgressPhoto.timestamp.desc())
        .all()
    )
    delete_form = DeleteBodyWeightForm()
    return render_template('progress_photos.html', photos=photos, delete_form=delete_form)


@app.route('/progress_photos/<int:photo_id>/delete', methods=['POST'])
@login_required
def delete_progress_photo(photo_id):
    photo = ProgressPhoto.query.get_or_404(photo_id)
    if photo.user_id != current_user.id:
        abort(403)
    services.delete_progress_photo(photo)
    db.session.commit()
    flash('Foto gelöscht.', 'info')
    return redirect(url_for('progress_photos'))


@app.route('/progress_photos/<int:photo_id>/file')
@login_required
def progress_photo_file(photo_id):
    """Serve a progress photo to its owner only."""
    photo = db.session.get(ProgressPhoto, photo_id)
    # 404 statt 403, damit fremde Foto-IDs nicht erkennbar sind
    if photo is None or photo.user_id != current_user.id:
        abort(404)
    path = progress_photo_path(photo)
    if not os.path.isfile(path):
        abort(404)
    ext = path.rsplit('.', 1)[-1].lower()
    response = make_response(send_file(path, mimetype=PHOTO_MIMETYPES.get(ext, 'application/octet-stream')))
    response.headers['Cache-Control'] = 'private, no-store'
    return response


# ----------------------------------------------------
# Trainings-Kalender
# ----------------------------------------------------
@app.route('/calendar')
@login_required
def training_calendar():
    try:
        year, month = _parse_calendar_month_args()
    except ValueError:
        abort(400)
    # Grenzen für den Monat berechnen
    first_day = datetime.date(year, month, 1)
    if month == 12:
        last_day = datetime.date(year + 1, 1, 1)
    else:
        last_day = datetime.date(year, month + 1, 1)
    # Alle Sessions des Users in diesem Monat
    sessions = (
        ExerciseSession.query
        .filter_by(user_id=current_user.id)
        .filter(ExerciseSession.timestamp >= datetime.datetime.combine(first_day, datetime.time.min))
        .filter(ExerciseSession.timestamp < datetime.datetime.combine(last_day, datetime.time.min))
        .all()
    )
    # Sätze pro Tag zählen
    day_counts = {}
    for s in sessions:
        day = s.timestamp.date()
        day_counts[day] = day_counts.get(day, 0) + 1
    # Geplante Trainingstage laden
    planned = PlannedTraining.query.filter(
        PlannedTraining.user_id == current_user.id,
        PlannedTraining.date >= first_day,
        PlannedTraining.date < last_day,
    ).all()
    planned_map = {p.date: p.label for p in planned}
    # Kalender-Daten aufbauen
    today = datetime.date.today()
    cal = cal_module.Calendar(firstweekday=0)  # Montag = 0
    weeks = cal.monthdayscalendar(year, month)
    calendar_weeks = []
    for week in weeks:
        week_data = []
        for day_num in week:
            if day_num == 0:
                week_data.append({'day': 0, 'count': 0, 'planned': False, 'label': None, 'is_today': False})
            else:
                d = datetime.date(year, month, day_num)
                count = day_counts.get(d, 0)
                week_data.append({
                    'day': day_num,
                    'count': count,
                    'planned': d in planned_map,
                    'label': planned_map.get(d),
                    'is_today': d == today,
                    'date_str': d.isoformat(),
                })
        calendar_weeks.append(week_data)
    # Max-Count für Farbintensität
    max_count = max(day_counts.values()) if day_counts else 1
    # Navigation: vorheriger/nächster Monat
    if month == 1:
        prev_year, prev_month = year - 1, 12
    else:
        prev_year, prev_month = year, month - 1
    if month == 12:
        next_year, next_month = year + 1, 1
    else:
        next_year, next_month = year, month + 1
    month_name = [
        '', 'Januar', 'Februar', 'März', 'April', 'Mai', 'Juni',
        'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember'
    ][month]
    # Gesamtstatistik für den Monat
    total_sessions = len(sessions)
    training_days = len(day_counts)
    total_volume = sum(_session_volume(s) for s in sessions)
    return render_template(
        'training_calendar.html',
        calendar_weeks=calendar_weeks,
        year=year,
        month=month,
        month_name=month_name,
        max_count=max_count,
        prev_year=prev_year,
        prev_month=prev_month,
        next_year=next_year,
        next_month=next_month,
        total_sessions=total_sessions,
        training_days=training_days,
        total_volume=total_volume,
    )


@app.route('/calendar/plan', methods=['POST'])
@login_required
def plan_training_day():
    try:
        day = services.parse_plan_date(request.form.get('date'))
        services.plan_training_day(current_user.id, day, request.form.get('label', ''))
    except ValueError:
        abort(400)
    db.session.commit()
    return redirect(url_for('training_calendar', year=day.year, month=day.month))


@app.route('/calendar/unplan', methods=['POST'])
@login_required
def unplan_training_day():
    try:
        day = services.parse_plan_date(request.form.get('date'))
    except ValueError:
        abort(400)
    services.unplan_training_day(current_user.id, day)
    db.session.commit()
    return redirect(url_for('training_calendar', year=day.year, month=day.month))


# ----------------------------------------------------
# Körpergewicht-Tracking
# ----------------------------------------------------
@app.route('/body_weight', methods=['GET', 'POST'])
@login_required
def body_weight():
    form = BodyWeightForm()
    delete_form = DeleteBodyWeightForm()

    if form.validate_on_submit():
        new_entry = BodyWeight(
            user_id=current_user.id,
            weight=form.weight.data,
            notes=form.notes.data or None
        )
        db.session.add(new_entry)
        db.session.commit()
        flash('Gewicht gespeichert!', 'success')
        return redirect(url_for('body_weight'))

    # Alle Einträge des Benutzers, sortiert nach Datum
    entries = BodyWeight.query.filter_by(user_id=current_user.id).order_by(BodyWeight.timestamp.desc()).all()

    # Daten für das Chart vorbereiten (chronologisch)
    chart_entries = sorted(entries, key=lambda e: e.timestamp)
    chart_data = {
        'labels': [e.timestamp.strftime('%d.%m.%Y') for e in chart_entries],
        'weights': [e.weight for e in chart_entries]
    }

    # Statistiken berechnen
    stats = None
    if entries:
        weights = [e.weight for e in entries]
        stats = {
            'current': entries[0].weight if entries else None,
            'min': min(weights),
            'max': max(weights),
            'avg': round(sum(weights) / len(weights), 1),
            'total_entries': len(entries)
        }
        # Änderung zum ersten Eintrag
        if len(entries) > 1:
            first_entry = chart_entries[0]
            latest_entry = chart_entries[-1]
            stats['change'] = round(latest_entry.weight - first_entry.weight, 1)

    return render_template('body_weight.html', form=form, delete_form=delete_form,
                           entries=entries, chart_data=chart_data, stats=stats)


@app.route('/body_weight/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_body_weight(entry_id):
    entry = BodyWeight.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    db.session.delete(entry)
    db.session.commit()
    flash('Eintrag gelöscht!', 'info')
    return redirect(url_for('body_weight'))
