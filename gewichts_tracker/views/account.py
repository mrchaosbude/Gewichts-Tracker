"""Seiten: Konto, Zwei-Faktor-Anmeldung, Export/Import, Konto löschen."""

import csv
import io
import json
import tempfile
import zipfile

from flask import (
    abort,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    Response,
    send_file,
    session as flask_session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from gewichts_tracker.core import _utcnow, app, db, limiter, MAX_IMPORT_BYTES
from gewichts_tracker.crypto import encrypt_value
from gewichts_tracker.models import ExerciseSession, get_app_settings, TrainingPlan, User
from gewichts_tracker.security import (
    disable_two_factor,
    generate_backup_codes,
    generate_totp_secret,
    match_totp,
    totp_qr_svg,
    verify_second_factor,
)
from gewichts_tracker.serializers import serialize_exercise, serialize_session, serialize_training_plan
from gewichts_tracker.accounts import _is_last_admin, delete_user_with_data
from gewichts_tracker.forms import (
    ChangeEmailForm,
    ChangePasswordForm,
    DeleteAccountForm,
    TwoFactorCodeForm,
    TwoFactorPasswordForm,
)
from gewichts_tracker.data_io import (
    _cleanup_import_files,
    build_user_export,
    import_user_data,
    load_import_upload,
)


# ----------------------------------------------------
# Konto: Passwort, E-Mail, Passwort vergessen
# ----------------------------------------------------
def _render_account(password_form=None, email_form=None, delete_form=None):
    if email_form is None:
        email_form = ChangeEmailForm(prefix='mail')
        email_form.email.data = current_user.email or ''
    settings = get_app_settings()
    return render_template(
        'account.html',
        password_form=password_form or ChangePasswordForm(prefix='pw'),
        email_form=email_form,
        delete_form=delete_form or DeleteAccountForm(prefix='del'),
        reset_available=bool(settings.smtp_server and settings.smtp_sender_email),
        max_import_mb=MAX_IMPORT_BYTES // (1024 * 1024),
    )


@app.route('/account')
@login_required
def account():
    return _render_account()


@app.route('/account/password', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def account_change_password():
    form = ChangePasswordForm(prefix='pw')
    if form.validate_on_submit():
        user = db.session.get(User, current_user.id)
        if not check_password_hash(user.password, form.current_password.data):
            form.current_password.errors.append('Aktuelles Passwort ist falsch.')
        else:
            user.password = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
            db.session.commit()
            login_user(user)  # diese Sitzung behalten, alle anderen sind jetzt ungültig
            flash('Passwort geändert. Alle anderen Geräte wurden abgemeldet.', 'success')
            return redirect(url_for('account'))
    return _render_account(password_form=form), 400


@app.route('/account/email', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def account_change_email():
    form = ChangeEmailForm(prefix='mail')
    if form.validate_on_submit():
        user = db.session.get(User, current_user.id)
        new_email = (form.email.data or '').strip() or None
        if not check_password_hash(user.password, form.current_password.data):
            form.current_password.errors.append('Aktuelles Passwort ist falsch.')
        elif new_email and User.query.filter(
                db.func.lower(User.email) == new_email.lower(), User.id != user.id).first():
            form.email.errors.append('Diese E-Mail-Adresse wird bereits verwendet.')
        elif new_email is None and get_app_settings().require_email_verification:
            form.email.errors.append('Eine E-Mail-Adresse ist erforderlich.')
        else:
            user.email = new_email
            db.session.commit()
            flash('E-Mail-Adresse gespeichert.' if new_email else 'E-Mail-Adresse entfernt.', 'success')
            return redirect(url_for('account'))
    return _render_account(email_form=form), 400


def _render_two_factor(**context):
    # formdata=None: eingegebene Codes/Passwörter nie in die Seite zurückschreiben
    context.setdefault('password_form', TwoFactorPasswordForm(prefix='tfp', formdata=None))
    context.setdefault('code_form', TwoFactorCodeForm(prefix='tfc', formdata=None))
    context.setdefault('setup', None)
    context.setdefault('backup_codes', None)
    try:
        remaining = len(json.loads(current_user.totp_backup_codes or '[]'))
    except ValueError:
        remaining = 0
    response = make_response(render_template('two_factor.html', backup_codes_left=remaining, **context))
    response.headers['Cache-Control'] = 'no-store'
    return response


def _two_factor_setup_context(secret):
    settings = get_app_settings()
    issuer = settings.app_name or 'Gewichts-Tracker'
    from urllib.parse import quote
    uri = (f'otpauth://totp/{quote(issuer)}:{quote(current_user.username)}'
           f'?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30')
    return {'secret': ' '.join(secret[i:i + 4] for i in range(0, len(secret), 4)), 'uri': uri, 'qr': totp_qr_svg(uri)}


@app.route('/account/2fa')
@login_required
def account_two_factor():
    secret = flask_session.get('2fa_setup')
    setup = _two_factor_setup_context(secret) if secret and not current_user.totp_enabled else None
    return _render_two_factor(setup=setup)


@app.route('/account/2fa/setup', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def account_two_factor_setup():
    form = TwoFactorPasswordForm(prefix='tfp')
    user = db.session.get(User, current_user.id)
    if user.totp_enabled:
        return redirect(url_for('account_two_factor'))
    if form.validate_on_submit() and check_password_hash(user.password, form.current_password.data):
        flask_session['2fa_setup'] = generate_totp_secret()
        return redirect(url_for('account_two_factor'))
    form.current_password.errors.append('Aktuelles Passwort ist falsch.')
    return _render_two_factor(password_form=form), 400


@app.route('/account/2fa/enable', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def account_two_factor_enable():
    secret = flask_session.get('2fa_setup')
    user = db.session.get(User, current_user.id)
    if not secret or user.totp_enabled:
        return redirect(url_for('account_two_factor'))
    form = TwoFactorCodeForm(prefix='tfc')
    counter = match_totp(secret, form.code.data) if form.validate_on_submit() else None
    if counter is None:
        form.code.errors.append('Der Code stimmt nicht. Prüfe die Uhrzeit deines Geräts und versuche es erneut.')
        return _render_two_factor(code_form=form, setup=_two_factor_setup_context(secret)), 400
    user.totp_secret = encrypt_value(secret)
    user.totp_enabled = True
    user.totp_last_counter = counter
    codes = generate_backup_codes(user)
    db.session.commit()
    flask_session.pop('2fa_setup', None)
    flash('Zwei-Faktor-Anmeldung ist aktiv.', 'success')
    return _render_two_factor(backup_codes=codes)


def _confirm_password_and_code(form, user):
    if not form.validate_on_submit():
        return False
    if not check_password_hash(user.password, form.current_password.data):
        form.current_password.errors.append('Aktuelles Passwort ist falsch.')
        return False
    if not verify_second_factor(user, form.code.data or ''):
        db.session.rollback()
        form.code.errors.append('Der Code ist falsch oder abgelaufen.')
        return False
    return True


@app.route('/account/2fa/disable', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def account_two_factor_disable():
    user = db.session.get(User, current_user.id)
    if not user.totp_enabled:
        return redirect(url_for('account_two_factor'))
    form = TwoFactorPasswordForm(prefix='tfp')
    if not _confirm_password_and_code(form, user):
        return _render_two_factor(password_form=form), 400
    disable_two_factor(user)
    db.session.commit()
    flash('Zwei-Faktor-Anmeldung wurde abgeschaltet.', 'info')
    return redirect(url_for('account_two_factor'))


@app.route('/account/2fa/backup-codes', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def account_two_factor_backup_codes():
    user = db.session.get(User, current_user.id)
    if not user.totp_enabled:
        return redirect(url_for('account_two_factor'))
    form = TwoFactorPasswordForm(prefix='tfp')
    if not _confirm_password_and_code(form, user):
        return _render_two_factor(password_form=form), 400
    codes = generate_backup_codes(user)
    db.session.commit()
    flash('Neue Backup-Codes erzeugt. Die alten sind ungültig.', 'success')
    return _render_two_factor(backup_codes=codes)


@app.route('/account/delete', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def account_delete():
    form = DeleteAccountForm(prefix='del')
    if form.validate_on_submit():
        user = db.session.get(User, current_user.id)
        if not check_password_hash(user.password, form.current_password.data):
            form.current_password.errors.append('Aktuelles Passwort ist falsch.')
        elif form.confirm_username.data.strip() != user.username:
            form.confirm_username.errors.append('Der Benutzername stimmt nicht.')
        elif _is_last_admin(user):
            form.confirm_username.errors.append(
                'Du bist der einzige Administrator. Ernenne zuerst einen anderen Benutzer zum Admin.')
        else:
            logout_user()
            delete_user_with_data(user)
            db.session.commit()
            flash('Dein Konto und alle zugehörigen Daten wurden gelöscht.', 'info')
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie('sw_clear_cache', '1', max_age=10)
            return resp
    return _render_account(delete_form=form), 400


@app.route('/export/full')
@login_required
@limiter.limit("10 per minute")
def export_full():
    """Everything the user owns as one ZIP: data.json plus photos/."""
    data, photo_files = build_user_export(current_user)
    spool = tempfile.SpooledTemporaryFile(max_size=20 * 1024 * 1024)
    with zipfile.ZipFile(spool, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('data.json', json.dumps(data, ensure_ascii=False, indent=2))
        for archive_name, path in photo_files:
            archive.write(path, archive_name, compress_type=zipfile.ZIP_STORED)
    spool.seek(0)
    stamp = _utcnow().strftime('%Y%m%d')
    response = send_file(spool, mimetype='application/zip', as_attachment=True,
                         download_name=f'gewichts-tracker-export-{stamp}.zip')
    response.headers['Cache-Control'] = 'private, no-store'
    return response


@app.route('/account/import', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def account_import():
    upload = request.files.get('export_file')
    if upload is None or not upload.filename:
        flash('Keine Datei ausgewählt.', 'warning')
        return redirect(url_for('account'))
    closer = lambda: None
    try:
        data, read_photo, closer = load_import_upload(upload)
        counts = import_user_data(db.session.get(User, current_user.id), data, read_photo)
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        _cleanup_import_files(getattr(exc, 'created_files', None))
        flash(f'Import fehlgeschlagen, es wurde nichts übernommen: {exc}', 'danger')
        return redirect(url_for('account'))
    except Exception as exc:
        db.session.rollback()
        _cleanup_import_files(getattr(exc, 'created_files', None))
        app.logger.exception('Import failed')
        flash('Import fehlgeschlagen, es wurde nichts übernommen.', 'danger')
        return redirect(url_for('account'))
    finally:
        closer()
    flash(
        f"Import abgeschlossen: {counts['plans']} Pläne, {counts['exercises']} Übungen, {counts['sessions']} Sessions, "
        f"{counts['body_weights']} Körpergewichte, {counts['planned_trainings']} geplante Trainings, {counts['photos']} Fotos.",
        'success')
    return redirect(url_for('account'))


@app.route('/export/training-data')
@login_required
def export_training_data():
    export_format = request.args.get('format', 'json').lower()
    compress = request.args.get('zip', '').lower() in ('1', 'true', 'yes', 'y')

    plans = TrainingPlan.query.filter_by(user_id=current_user.id).all()

    plan_exports = []
    exercise_cache = {}
    session_rows = []

    for plan in plans:
        plan_dict = serialize_training_plan(plan)
        serialized_exercises = []
        if not plan.exercises:
            plan_exports.append({**plan_dict, 'exercises': []})
            session_rows.append({'plan': plan_dict, 'exercise': None, 'session': None})
            continue
        for exercise in plan.exercises:
            if exercise.id not in exercise_cache:
                exercise_cache[exercise.id] = serialize_exercise(exercise)
            sessions = (
                ExerciseSession.query
                .filter_by(exercise_id=exercise.id, user_id=current_user.id)
                .order_by(ExerciseSession.timestamp.asc())
                .all()
            )
            serialized_sessions = [serialize_session(s) for s in sessions]
            if serialized_sessions:
                for session in serialized_sessions:
                    session_rows.append({
                        'plan': plan_dict,
                        'exercise': exercise_cache[exercise.id],
                        'session': session,
                    })
            else:
                session_rows.append({
                    'plan': plan_dict,
                    'exercise': exercise_cache[exercise.id],
                    'session': None,
                })
            serialized_exercises.append({
                **exercise_cache[exercise.id],
                'sessions': serialized_sessions,
            })
        plan_exports.append({**plan_dict, 'exercises': serialized_exercises})

    if export_format not in ('json', 'csv'):
        abort(400, description='Unsupported format. Use "json" or "csv".')

    timestamp = _utcnow()

    if export_format == 'json':
        payload = {
            'exported_at': timestamp.isoformat(),
            'format': 'json',
            'training_plans': plan_exports,
        }
        json_bytes = json.dumps(payload, ensure_ascii=False, indent=2).encode('utf-8')
        if compress:
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('training-data.json', json_bytes)
            memory_file.seek(0)
            return send_file(
                memory_file,
                mimetype='application/zip',
                as_attachment=True,
                download_name='training-data.zip',
            )
        return Response(json_bytes, mimetype='application/json')

    # CSV export
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow([
        'plan_id',
        'plan_title',
        'plan_description',
        'exercise_id',
        'exercise_name',
        'exercise_description',
        'session_id',
        'timestamp',
        'weight',
        'repetitions',
        'notes',
        'perceived_exertion',
        'duration_minutes',
        'distance_km',
        'warmup_activity',
        'warmup_duration',
    ])

    for row in session_rows:
        plan = row['plan']
        exercise = row['exercise']
        session = row['session']
        writer.writerow([
            plan['id'],
            plan['title'],
            plan['description'],
            exercise['id'] if exercise else '',
            exercise['name'] if exercise else '',
            exercise['description'] if exercise else '',
            session['id'] if session else '',
            session['timestamp'] if session else '',
            session['weight'] if session else '',
            session['repetitions'] if session else '',
            session['notes'] if session else '',
            session['perceived_exertion'] if session else '',
            session['duration_minutes'] if session else '',
            session['distance_km'] if session else '',
            session['warmup_activity'] if session else '',
            session['warmup_duration'] if session else '',
        ])

    csv_bytes = csv_buffer.getvalue().encode('utf-8')
    if compress:
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('training-data.csv', csv_bytes)
        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name='training-data.zip',
        )

    response = Response(csv_bytes, mimetype='text/csv; charset=utf-8')
    response.headers['Content-Disposition'] = 'attachment; filename=training-data.csv'
    return response
