"""Seiten: Start, Registrierung, Login, Logout, Passwort vergessen."""

import hmac
import secrets
import time

from flask import (
    flash,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session as flask_session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash
from wtforms.validators import DataRequired, Length

from gewichts_tracker.core import _utcnow, app, db, limiter
from gewichts_tracker.crypto import password_fingerprint
from gewichts_tracker.models import FooterPage, get_app_settings, User
from gewichts_tracker.security import (
    TWO_FACTOR_MAX_TRIES,
    TWO_FACTOR_PENDING_SECONDS,
    verify_password_reset_token,
    verify_second_factor,
)
from gewichts_tracker.mail import mail_links_available, send_password_reset_email, send_verification_email
from gewichts_tracker.accounts import (
    authenticate,
    cleanup_unverified_accounts,
    login_account_limit,
    registration_open,
    two_factor_account_limit,
)
from gewichts_tracker.forms import (
    ForgotPasswordForm,
    LoginForm,
    RegistrationForm,
    ResetPasswordForm,
    TwoFactorCodeForm,
)


# ----------------------------------------------------
# Routen
# ----------------------------------------------------
@app.route('/sw.js')
def service_worker():
    response = make_response(send_file('static/sw.js', mimetype='application/javascript'))
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET','POST'])
@limiter.limit("5 per minute")
def register():
    cleanup_unverified_accounts()
    settings = get_app_settings()
    if not registration_open(settings):
        flash('Die Registrierung ist auf diesem Server deaktiviert.', 'warning')
        return redirect(url_for('login'))
    email_required = settings.require_email_verification
    form = RegistrationForm()
    if email_required:
        form.email.validators = [DataRequired(), Length(max=150)]
    if form.validate_on_submit():
        is_first_user = User.query.first() is None
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            is_admin=is_first_user
        )
        if email_required and not is_first_user:
            new_user.email = form.email.data
            new_user.email_confirmed = False
            new_user.email_token = secrets.token_urlsafe(32)
            new_user.email_token_created = _utcnow()
            db.session.add(new_user)
            db.session.commit()
            if send_verification_email(new_user):
                flash('Konto erstellt! Bitte bestätige deine E-Mail-Adresse über den Link in der E-Mail.', 'info')
            else:
                flash('Konto erstellt, aber die Bestätigungs-E-Mail konnte nicht gesendet werden. Bitte kontaktiere den Administrator.', 'warning')
            return redirect(url_for('login'))
        else:
            new_user.email_confirmed = True
            if email_required and form.email.data:
                new_user.email = form.email.data
            db.session.add(new_user)
            db.session.commit()
            flash('Konto erstellt, bitte einloggen.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form, email_required=email_required)


@app.route('/login', methods=['GET','POST'])
@limiter.limit("10 per minute")
@login_account_limit
def login():
    cleanup_unverified_accounts()
    form = LoginForm()
    show_resend = False
    if form.validate_on_submit():
        user = authenticate(form.username.data, form.password.data)
        if user:
            settings = get_app_settings()
            if settings.require_email_verification and not user.email_confirmed:
                flash('Bitte bestätige zuerst deine E-Mail-Adresse.', 'warning')
                show_resend = True
            elif user.totp_enabled:
                # Passwort stimmt, zweiter Faktor fehlt noch: noch NICHT einloggen
                flask_session['2fa_pending'] = {
                    'uid': user.id, 'fp': password_fingerprint(user.password),
                    'ts': time.time(), 'remember': bool(form.remember.data), 'tries': 0,
                }
                return redirect(url_for('login_two_factor'))
            else:
                login_user(user, remember=form.remember.data)
                user.last_login = _utcnow()
                db.session.commit()
                flash('Erfolgreich eingeloggt!', 'success')
                return redirect(url_for('dashboard'))
        else:
            flash('Ungültiger Benutzername oder Passwort.', 'danger')
    pages = FooterPage.query.all()
    return render_template('login.html', form=form, footer_pages=pages, show_resend=show_resend)


@app.route('/login/2fa', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
@two_factor_account_limit
def login_two_factor():
    pending = flask_session.get('2fa_pending')
    user = db.session.get(User, pending['uid']) if isinstance(pending, dict) and isinstance(pending.get('uid'), int) else None
    if (user is None or not user.totp_enabled
            or time.time() - float(pending.get('ts', 0)) > TWO_FACTOR_PENDING_SECONDS
            or pending.get('tries', 0) >= TWO_FACTOR_MAX_TRIES
            or not hmac.compare_digest(str(pending.get('fp', '')), password_fingerprint(user.password))):
        flask_session.pop('2fa_pending', None)
        flash('Bitte melde dich erneut an.', 'warning')
        return redirect(url_for('login'))
    form = TwoFactorCodeForm()
    if form.validate_on_submit():
        if verify_second_factor(user, form.code.data):
            flask_session.pop('2fa_pending', None)
            login_user(user, remember=bool(pending.get('remember')))
            user.last_login = _utcnow()
            db.session.commit()
            flash('Erfolgreich eingeloggt!', 'success')
            return redirect(url_for('dashboard'))
        pending['tries'] = pending.get('tries', 0) + 1
        flask_session['2fa_pending'] = pending
        form.code.errors.append('Der Code ist falsch oder abgelaufen.')
    return render_template('login_2fa.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    if request.method != 'POST':
        # Kein Logout per Link/Bild von fremden Seiten (CSRF)
        flash('Zum Abmelden bitte den Logout-Knopf benutzen.', 'info')
        return redirect(url_for('dashboard'))
    logout_user()
    flash('Ausgeloggt.', 'info')
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('sw_clear_cache', '1', max_age=10)
    return resp


@app.route('/confirm/<token>')
def confirm_email(token):
    user = User.query.filter_by(email_token=token).first()
    if not user:
        flash('Ungültiger oder abgelaufener Bestätigungslink.', 'danger')
        return redirect(url_for('login'))
    # Token läuft nach 24 Stunden ab
    if user.email_token_created:
        age = (_utcnow() - user.email_token_created).total_seconds()
        if age > 86400:  # 24 Stunden
            flash('Der Bestätigungslink ist abgelaufen. Bitte fordere einen neuen an.', 'danger')
            return redirect(url_for('login'))
    if user.pending_email:
        # Bestätigung einer geänderten Adresse
        taken = User.query.filter(db.func.lower(User.email) == user.pending_email.lower(), User.id != user.id).first()
        if taken:
            user.pending_email = None
            user.email_token = None
            user.email_token_created = None
            db.session.commit()
            flash('Diese E-Mail-Adresse wird inzwischen von einem anderen Konto verwendet.', 'danger')
            return redirect(url_for('account' if current_user.is_authenticated else 'login'))
        user.email = user.pending_email
        user.pending_email = None
        user.email_confirmed = True
        user.email_token = None
        user.email_token_created = None
        db.session.commit()
        flash('Neue E-Mail-Adresse bestätigt.', 'success')
        return redirect(url_for('account' if current_user.is_authenticated else 'login'))
    user.email_confirmed = True
    user.email_token = None
    user.email_token_created = None
    db.session.commit()
    flash('E-Mail bestätigt! Du kannst dich jetzt einloggen.', 'success')
    return redirect(url_for('login'))


@app.route('/resend-confirmation', methods=['POST'])
@limiter.limit("5 per minute")
def resend_confirmation():
    username = request.form.get('username', '').strip()
    user = User.query.filter_by(username=username).first()
    now = _utcnow()
    if (user is not None and not user.email_confirmed and user.email
            and not (user.email_token_created and (now - user.email_token_created).total_seconds() < 300)):
        user.email_token = secrets.token_urlsafe(32)
        user.email_token_created = now
        db.session.commit()
        send_verification_email(user)
    # Immer dieselbe Antwort, damit sich keine Konten erraten lassen
    flash('Falls ein noch unbestätigtes Konto existiert, wurde eine neue Bestätigungs-E-Mail gesendet. '
          'Kommt nichts an, warte 5 Minuten oder wende dich an den Administrator.', 'info')
    return redirect(url_for('login'))


_reset_mail_last_sent = {}  # user_id -> Zeitpunkt; begrenzt Mail-Flut an ein Opfer
RESET_MAIL_COOLDOWN = 300  # Sekunden


@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=['POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    reset_available = mail_links_available()
    form = ForgotPasswordForm()
    if form.validate_on_submit() and reset_available:
        identifier = form.identifier.data.strip()
        user = User.query.filter_by(username=identifier).first()
        if user is None:
            matches = User.query.filter(db.func.lower(User.email) == identifier.lower()).all()
            user = matches[0] if len(matches) == 1 else None
        if user is not None and user.email:
            now = _utcnow()
            last = _reset_mail_last_sent.get(user.id)
            if last is None or (now - last).total_seconds() >= RESET_MAIL_COOLDOWN:
                _reset_mail_last_sent[user.id] = now
                send_password_reset_email(user)
        # Immer dieselbe Antwort, damit sich keine Konten erraten lassen
        flash('Falls ein Konto mit hinterlegter E-Mail-Adresse existiert, wurde ein Link zum Zurücksetzen gesendet.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html', form=form, reset_available=reset_available)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def reset_password(token):
    user = verify_password_reset_token(token)
    if user is None:
        flash('Der Link ist ungültig, abgelaufen oder wurde bereits verwendet.', 'danger')
        return redirect(url_for('forgot_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
        db.session.commit()
        _reset_mail_last_sent.pop(user.id, None)
        logout_user()
        flash('Passwort gespeichert. Du kannst dich jetzt einloggen.', 'success')
        return redirect(url_for('login'))
    response = make_response(render_template('reset_password.html', form=form, token=token))
    response.headers['Referrer-Policy'] = 'no-referrer'  # Token nicht an Dritte weitergeben
    response.headers['Cache-Control'] = 'no-store'
    return response
