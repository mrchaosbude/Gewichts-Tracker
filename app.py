from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    abort,
    jsonify,
    Blueprint,
    Response,
    send_file,
    make_response,
)
import markdown
import bleach
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, IntegerField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, InputRequired, Length, EqualTo, ValidationError, Optional, NumberRange
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import io
import json
import csv
import zipfile
import os
import uuid
import calendar as cal_module

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dein_geheimer_schluessel'  # Bitte anpassen!
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('GEWICHTS_TRACKER_DATABASE_URI', 'sqlite:///fitness.db')

# reCAPTCHA-Konfiguration (ersetze die Schlüssel durch deine echten Werte)
app.config['RECAPTCHA_PUBLIC_KEY'] = 'dein_recaptcha_public_key'
app.config['RECAPTCHA_PRIVATE_KEY'] = 'dein_recaptcha_private_key'
# Zum Testen (ohne reCAPTCHA) kannst du es hier auf False setzen:
app.config['RECAPTCHA_ENABLED'] = False

db = SQLAlchemy(app)


def _ensure_database_setup_once() -> None:
    """Ensure database tables exist once per application lifecycle."""

    if getattr(app, '_database_setup_ran', False):
        return

    try:
        with app.app_context():
            db.create_all()
    except Exception as exc:  # pragma: no cover - defensive logging
        app.logger.warning('Failed to ensure database tables: %s', exc)

    app._database_setup_ran = True


# Flask-Login konfigurieren
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
api_bp = Blueprint("api", __name__, url_prefix="/api")
# ----------------------------------------------------
# Datenbankmodelle
# ----------------------------------------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.datetime.now)
    last_login = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)
    is_trainer = db.Column(db.Boolean, default=False)
    training_plans = db.relationship('TrainingPlan', backref='owner', lazy=True, cascade="all, delete-orphan")
    exercises = db.relationship('Exercise', backref='owner', lazy=True)

plan_exercises = db.Table(
    'plan_exercises',
    db.Column('training_plan_id', db.Integer, db.ForeignKey('training_plan.id'), primary_key=True),
    db.Column('exercise_id', db.Integer, db.ForeignKey('exercise.id'), primary_key=True),
    db.Column('superset_group', db.Integer, nullable=True),
    db.Column('position', db.Integer, nullable=True),
)


class TrainingPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    share_token = db.Column(db.String(36), nullable=True, unique=True)
    exercises = db.relationship('Exercise', secondary=plan_exercises, back_populates='training_plans')

MUSCLE_GROUPS = [
    'Brust', 'Rücken', 'Schultern', 'Bizeps', 'Trizeps',
    'Beine', 'Waden', 'Bauch', 'Unterarme', 'Ganzkörper', 'Sonstiges',
]

class Exercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(300), nullable=True)
    video_url = db.Column(db.String(500), nullable=True)
    muscle_group = db.Column(db.String(50), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sessions = db.relationship('ExerciseSession', backref='exercise', lazy=True, cascade="all, delete-orphan")
    training_plans = db.relationship('TrainingPlan', secondary=plan_exercises, back_populates='exercises')

class ExerciseSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exercise_id = db.Column(db.Integer, db.ForeignKey('exercise.id'), nullable=False)
    repetitions = db.Column(db.Integer, nullable=False)
    weight = db.Column(db.Integer, nullable=False)  # Gewicht als Integer
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    notes = db.Column(db.Text)
    perceived_exertion = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Modelle für Template Trainingspläne
class TemplateTrainingPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(300))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Admin/Trainer, der die Vorlage erstellt
    is_visible = db.Column(db.Boolean, default=True)  # Sichtbarkeit
    exercises = db.relationship('TemplateExercise', backref='template_plan', lazy=True, cascade="all, delete-orphan")

class TemplateExercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(300), nullable=True)  # Beschreibung bei Template-Übung
    template_plan_id = db.Column(db.Integer, db.ForeignKey('template_training_plan.id'), nullable=False)


# Seiten, die im Login-Footer verlinkt werden
class FooterPage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)


class FooterLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    url = db.Column(db.String(500), nullable=False)


# Körpergewicht-Tracking
class BodyWeight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    weight = db.Column(db.Float, nullable=False)  # Gewicht in kg
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    notes = db.Column(db.Text)  # Optionale Notizen


# Geplante Trainingstage
class PlannedTraining(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    label = db.Column(db.String(100), nullable=True)  # z.B. "Push", "Pull", "Beine"

    __table_args__ = (db.UniqueConstraint('user_id', 'date', name='uq_user_planned_date'),)


# Fortschrittsfotos
class ProgressPhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    notes = db.Column(db.Text)
    body_weight = db.Column(db.Float, nullable=True)


# Upload-Konfiguration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'photos')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB max


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.context_processor
def inject_footer_pages():
    """Provide footer pages to all templates."""

    _ensure_database_setup_once()
    return {
        "footer_pages": FooterPage.query.all(),
        "footer_links": FooterLink.query.all(),
    }


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------------------------------------------
# Decorators
# ----------------------------------------------------
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def trainer_or_admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (current_user.is_admin or current_user.is_trainer):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Helper to check if an exercise belongs only to the current user
def exercise_owned_exclusively_by(user_id, exercise):
    """Return True if the exercise is only linked to plans of the given user."""
    return all(p.user_id == user_id for p in exercise.training_plans)

# ----------------------------------------------------
# Formulare
# ----------------------------------------------------
class RegistrationForm(FlaskForm):
    username = StringField('Benutzername', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Passwort', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Passwort wiederholen', validators=[DataRequired(), EqualTo('password', message='Passwörter müssen übereinstimmen')])
    if app.config.get('RECAPTCHA_ENABLED', True):
        recaptcha = RecaptchaField()
    submit = SubmitField('Registrieren')
    
    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Benutzername bereits vergeben.')

class LoginForm(FlaskForm):
    username = StringField('Benutzername', validators=[DataRequired()])
    password = PasswordField('Passwort', validators=[DataRequired()])
    remember = BooleanField('Angemeldet bleiben')
    submit = SubmitField('Login')

class TrainingPlanForm(FlaskForm):
    title = StringField('Titel', validators=[DataRequired()])
    description = StringField('Beschreibung')
    submit = SubmitField('Trainingsplan speichern')

class ExerciseTemplateForm(FlaskForm):
    name = StringField('Übungsname', validators=[DataRequired()])
    description = StringField('Beschreibung (optional)')
    video_url = StringField('Video/Anleitung URL (optional)')
    muscle_group = SelectField('Muskelgruppe (optional)', choices=[('', '-- Keine --')] + [(mg, mg) for mg in MUSCLE_GROUPS], default='')
    submit = SubmitField('Übung hinzufügen')

class ExerciseSessionForm(FlaskForm):
    repetitions = IntegerField('Wiederholungen', validators=[DataRequired()], render_kw={"onfocus": "this.select()"})
    weight = IntegerField('Gewicht (kg)', validators=[InputRequired()], render_kw={"step": "1", "onfocus": "this.select()"})
    perceived_exertion = IntegerField(
        'Wahrgenommene Anstrengung (RPE 1-10, optional)',
        validators=[Optional(), NumberRange(min=1, max=10)],
        render_kw={"min": "1", "max": "10", "onfocus": "this.select()"}
    )
    notes = TextAreaField('Notizen', render_kw={"rows": 3})
    submit = SubmitField('Session hinzufügen')

class AdminChangePasswordForm(FlaskForm):
    new_password = PasswordField('Neues Passwort', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Passwort wiederholen', validators=[DataRequired(), EqualTo('new_password', message='Passwörter müssen übereinstimmen')])
    submit = SubmitField('Passwort ändern')

# Formular für Template Trainingspläne
class TemplateTrainingPlanForm(FlaskForm):
    title = StringField('Titel', validators=[DataRequired()])
    description = StringField('Beschreibung')
    submit = SubmitField('Vorlage speichern')

# Formular für Template-Übungen (Übungsname + Beschreibung)
class TemplateExerciseForm(FlaskForm):
    name = StringField('Übungsname', validators=[DataRequired()])
    description = StringField('Beschreibung (optional)')
    submit = SubmitField('Übung hinzufügen')

# Leichtgewichtige Formulare für einfache Aktionen
class DeleteTrainingPlanForm(FlaskForm):
    submit = SubmitField('Löschen')

class DeleteExerciseForm(FlaskForm):
    submit = SubmitField('Löschen')

class DeleteSessionForm(FlaskForm):
    submit = SubmitField('Löschen')

class DeleteUserForm(FlaskForm):
    submit = SubmitField('Löschen')

class SetTrainerForm(FlaskForm):
    submit = SubmitField('Bestätigen')

class RemoveTrainerForm(FlaskForm):
    submit = SubmitField('Bestätigen')

class ToggleTemplateVisibilityForm(FlaskForm):
    submit = SubmitField('Umschalten')

class DeleteTemplatePlanForm(FlaskForm):
    submit = SubmitField('Löschen')


class FooterPageForm(FlaskForm):
    title = StringField('Seitentitel', validators=[DataRequired()])
    content = TextAreaField('Inhalt (Markdown)', validators=[DataRequired()])
    submit = SubmitField('Speichern')

class DeleteFooterPageForm(FlaskForm):

    submit = SubmitField('Löschen')


class FooterLinkForm(FlaskForm):
    title = StringField('Link-Text', validators=[DataRequired()])
    url = StringField('URL', validators=[DataRequired()])
    submit = SubmitField('Speichern')

    @staticmethod
    def _is_valid_absolute_url(url: str) -> bool:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)

    def validate_url(self, field):  # noqa: D401 - Flask-WTF convention
        """Allow absolute URLs or relative paths starting with '/'."""

        value = (field.data or "").strip()
        if value.startswith('/'):
            return
        if not self._is_valid_absolute_url(value):
            raise ValidationError(
                "Bitte gib eine gültige URL (z. B. https://...) oder einen relativen Pfad beginnend mit '/' an."
            )


class DeleteFooterLinkForm(FlaskForm):

    submit = SubmitField('Löschen')


class BodyWeightForm(FlaskForm):
    weight = IntegerField('Gewicht (kg)', validators=[InputRequired(), NumberRange(min=20, max=500)], render_kw={"step": "0.1", "onfocus": "this.select()"})
    notes = TextAreaField('Notizen (optional)', render_kw={"rows": 2})
    submit = SubmitField('Speichern')


class DeleteBodyWeightForm(FlaskForm):
    submit = SubmitField('Löschen')


class MarkdownImportForm(FlaskForm):
    markdown_content = TextAreaField('Markdown Inhalt', validators=[DataRequired()])
    submit = SubmitField('Importieren')


# ----------------------------------------------------
# Markdown Parser für Trainingspläne
# ----------------------------------------------------

def parse_training_plan_markdown(content: str) -> dict:
    """
    Parse Markdown content into a training plan structure.

    Format:
    # Plan Title
    Plan description (optional)

    ## Exercise 1 Name
    Exercise 1 description (all content until next ## or end)

    ## Exercise 2 Name
    Exercise 2 description

    Returns:
        {
            'success': bool,
            'plan_title': str,
            'plan_description': str,
            'exercises': [{'name': str, 'description': str}, ...],
            'errors': [str, ...]
        }
    """
    errors = []
    lines = content.strip().split('\n')

    plan_title = None
    plan_description_lines = []
    exercises = []
    current_exercise = None
    current_exercise_desc_lines = []
    in_plan_description = False

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Check for H1 (plan title) - must not start with ##
        if stripped.startswith('# ') and not stripped.startswith('## '):
            if plan_title is not None:
                errors.append(f"Zeile {i}: Mehrere H1-Überschriften gefunden. Nur ein Plantitel erlaubt.")
                continue
            plan_title = stripped[2:].strip()
            if len(plan_title) > 150:
                errors.append(f"Zeile {i}: Plantitel zu lang ({len(plan_title)}/150 Zeichen).")
            in_plan_description = True
            continue

        # Check for H2 (exercise)
        if stripped.startswith('## '):
            # Save previous exercise if exists
            if current_exercise:
                desc = '\n'.join(current_exercise_desc_lines).strip()
                if len(desc) > 300:
                    errors.append(f"Übung '{current_exercise}': Beschreibung zu lang ({len(desc)}/300 Zeichen). Wird abgeschnitten.")
                exercises.append({'name': current_exercise, 'description': desc[:300]})

            current_exercise = stripped[3:].strip()
            if len(current_exercise) > 150:
                errors.append(f"Zeile {i}: Übungsname zu lang ({len(current_exercise)}/150 Zeichen).")
            current_exercise_desc_lines = []
            in_plan_description = False
            continue

        # Accumulate description lines
        if plan_title and current_exercise is None and in_plan_description:
            plan_description_lines.append(line)
        elif current_exercise:
            current_exercise_desc_lines.append(line)

    # Don't forget the last exercise
    if current_exercise:
        desc = '\n'.join(current_exercise_desc_lines).strip()
        if len(desc) > 300:
            errors.append(f"Übung '{current_exercise}': Beschreibung zu lang ({len(desc)}/300 Zeichen). Wird abgeschnitten.")
        exercises.append({'name': current_exercise, 'description': desc[:300]})

    # Validate required fields
    if not plan_title:
        errors.append("Kein Plantitel gefunden. Beginne mit '# Titel'.")

    if not exercises:
        errors.append("Keine Übungen gefunden. Füge Übungen mit '## Übungsname' hinzu.")

    plan_description = '\n'.join(plan_description_lines).strip()
    if len(plan_description) > 300:
        errors.append(f"Planbeschreibung zu lang ({len(plan_description)}/300 Zeichen). Wird abgeschnitten.")
        plan_description = plan_description[:300]

    return {
        'success': len(errors) == 0,
        'plan_title': plan_title or '',
        'plan_description': plan_description,
        'exercises': exercises,
        'errors': errors
    }


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


def check_deload_reminder(user_id, threshold_weeks=6):
    """Return (should_deload, consecutive_weeks) if the user has trained
    for *threshold_weeks* consecutive weeks without a break."""
    today = datetime.datetime.now().date()
    monday = today - datetime.timedelta(days=today.weekday())

    # Check the last 12 weeks for consecutive training
    consecutive = 0
    for i in range(12):
        week_start = monday - datetime.timedelta(weeks=i)
        week_end = week_start + datetime.timedelta(days=7)
        count = (
            ExerciseSession.query
            .filter(
                ExerciseSession.user_id == user_id,
                ExerciseSession.timestamp >= datetime.datetime.combine(week_start, datetime.time.min),
                ExerciseSession.timestamp < datetime.datetime.combine(week_end, datetime.time.min),
            )
            .count()
        )
        if count > 0:
            consecutive += 1
        else:
            break
    return consecutive >= threshold_weeks, consecutive


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
        chart_data['weights'].append(session.weight)
        chart_data['repetitions'].append(session.repetitions)
        chart_data['notes'].append(session.notes or '')
        chart_data['perceived_exertion'].append(session.perceived_exertion)
        chart_data['volume'].append(session.weight * session.repetitions)
        chart_data['one_rm'].append(round(session.weight * (1 + session.repetitions / 30.0), 2))

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
    if not previous_sessions:
        return []
    records = []
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
# Routen
# ----------------------------------------------------
@app.route('/sw.js')
def service_worker():
    response = make_response(send_file('static/sw.js', mimetype='application/javascript'))
    response.headers['Service-Worker-Allowed'] = '/'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/fit')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        is_first_user = User.query.first() is None
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            is_admin=is_first_user
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Konto erstellt, bitte einloggen.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            user.last_login = datetime.datetime.now()
            db.session.commit()
            flash('Erfolgreich eingeloggt!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Ungültiger Benutzername oder Passwort.', 'danger')
    pages = FooterPage.query.all()
    return render_template('login.html', form=form, footer_pages=pages)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ausgeloggt.', 'info')
    return redirect(url_for('login'))

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
    week_volume = sum(s.weight * s.repetitions for s in week_sessions)
    week_days = len(set(s.timestamp.date() for s in week_sessions))

    # Trainings-Streak (aufeinanderfolgende Wochen mit Training)
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
    now = datetime.datetime.now()
    # Alle Sessions des Users
    all_sessions = (
        ExerciseSession.query
        .filter_by(user_id=current_user.id)
        .order_by(ExerciseSession.timestamp.desc())
        .all()
    )
    # --- Muskelgruppen-Volumen ---
    muscle_volume = {}
    for s in all_sessions:
        mg = s.exercise.muscle_group or 'Nicht zugeordnet'
        volume = s.weight * s.repetitions
        muscle_volume[mg] = muscle_volume.get(mg, 0) + volume
    muscle_labels = list(muscle_volume.keys())
    muscle_values = list(muscle_volume.values())

    # --- Vergleich diese Woche vs. letzte Woche ---
    today = now.date()
    # Montag dieser Woche
    this_monday = today - datetime.timedelta(days=today.weekday())
    last_monday = this_monday - datetime.timedelta(days=7)
    this_week_sessions = [
        s for s in all_sessions
        if s.timestamp.date() >= this_monday
    ]
    last_week_sessions = [
        s for s in all_sessions
        if last_monday <= s.timestamp.date() < this_monday
    ]
    this_week_volume = sum(s.weight * s.repetitions for s in this_week_sessions)
    last_week_volume = sum(s.weight * s.repetitions for s in last_week_sessions)
    this_week_sets = len(this_week_sessions)
    last_week_sets = len(last_week_sessions)
    volume_diff = this_week_volume - last_week_volume
    sets_diff = this_week_sets - last_week_sets

    # Vergleich pro Übung
    exercise_comparison = []
    this_week_by_exercise = {}
    last_week_by_exercise = {}
    for s in this_week_sessions:
        name = s.exercise.name
        if name not in this_week_by_exercise:
            this_week_by_exercise[name] = {'sets': 0, 'volume': 0, 'max_weight': 0}
        this_week_by_exercise[name]['sets'] += 1
        this_week_by_exercise[name]['volume'] += s.weight * s.repetitions
        this_week_by_exercise[name]['max_weight'] = max(this_week_by_exercise[name]['max_weight'], s.weight)
    for s in last_week_sessions:
        name = s.exercise.name
        if name not in last_week_by_exercise:
            last_week_by_exercise[name] = {'sets': 0, 'volume': 0, 'max_weight': 0}
        last_week_by_exercise[name]['sets'] += 1
        last_week_by_exercise[name]['volume'] += s.weight * s.repetitions
        last_week_by_exercise[name]['max_weight'] = max(last_week_by_exercise[name]['max_weight'], s.weight)
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
        week_sessions = [
            s for s in all_sessions
            if week_start <= s.timestamp.date() < week_end
        ]
        training_days = len(set(s.timestamp.date() for s in week_sessions))
        week_label = week_start.strftime('%d.%m')
        frequency_data.append({
            'label': week_label,
            'days': training_days,
            'sets': len(week_sessions),
            'volume': sum(s.weight * s.repetitions for s in week_sessions),
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
    )


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


@app.route('/achievements')
@login_required
def achievements():
    total_sessions = ExerciseSession.query.filter_by(user_id=current_user.id).count()
    training_days = db.session.query(
        db.func.date(ExerciseSession.timestamp)
    ).filter_by(user_id=current_user.id).distinct().count()
    reg_days = (datetime.datetime.now() - (current_user.registration_date or datetime.datetime.now())).days

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
# Fortschrittsfotos
# ----------------------------------------------------
@app.route('/progress_photos', methods=['GET', 'POST'])
@login_required
def progress_photos():
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('Keine Datei ausgewählt.', 'warning')
            return redirect(url_for('progress_photos'))
        file = request.files['photo']
        if file.filename == '':
            flash('Keine Datei ausgewählt.', 'warning')
            return redirect(url_for('progress_photos'))
        if file and allowed_file(file.filename):
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f'{current_user.id}_{uuid.uuid4().hex[:8]}.{ext}'
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            notes = request.form.get('notes', '').strip() or None
            bw = request.form.get('body_weight', '').strip()
            body_weight_val = float(bw) if bw else None
            photo = ProgressPhoto(
                user_id=current_user.id,
                filename=filename,
                notes=notes,
                body_weight=body_weight_val,
            )
            db.session.add(photo)
            db.session.commit()
            flash('Foto hochgeladen!', 'success')
            return redirect(url_for('progress_photos'))
        else:
            flash('Ungültiges Dateiformat. Erlaubt: PNG, JPG, JPEG, WebP', 'danger')
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
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], photo.filename)
    if os.path.exists(filepath):
        os.remove(filepath)
    db.session.delete(photo)
    db.session.commit()
    flash('Foto gelöscht.', 'info')
    return redirect(url_for('progress_photos'))


# ----------------------------------------------------
# Trainings-Kalender
# ----------------------------------------------------
@app.route('/calendar')
@login_required
def training_calendar():
    year = request.args.get('year', datetime.datetime.now().year, type=int)
    month = request.args.get('month', datetime.datetime.now().month, type=int)
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
    total_volume = sum(s.weight * s.repetitions for s in sessions)
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
    date_str = request.form.get('date')
    label = request.form.get('label', '').strip() or None
    if not date_str:
        abort(400)
    try:
        day = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        abort(400)
    existing = PlannedTraining.query.filter_by(user_id=current_user.id, date=day).first()
    if existing:
        existing.label = label
    else:
        db.session.add(PlannedTraining(user_id=current_user.id, date=day, label=label))
    db.session.commit()
    return redirect(url_for('training_calendar', year=day.year, month=day.month))


@app.route('/calendar/unplan', methods=['POST'])
@login_required
def unplan_training_day():
    date_str = request.form.get('date')
    if not date_str:
        abort(400)
    try:
        day = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        abort(400)
    PlannedTraining.query.filter_by(user_id=current_user.id, date=day).delete()
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
                description=ex_data['description'],
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
    exercise_overview = []
    for exercise in sorted_exercises:
        user_sessions = [s for s in exercise.sessions if s.user_id == current_user.id]
        stats = calculate_exercise_statistics(user_sessions)
        recent_sessions = sorted(user_sessions, key=lambda s: s.timestamp, reverse=True)[:3]
        exercise_overview.append({
            'exercise': exercise,
            'summary': stats['summary'],
            'personal_bests': stats['personal_bests'],
            'recent_sessions': recent_sessions,
            'moving_window': stats['moving_window'],
            'superset_group': superset_map.get(exercise.id),
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
    group = request.form.get('superset_group', type=int)
    if exercise_id is None:
        abort(400)
    # group=0 oder leer → Superset entfernen
    if not group:
        group = None
    db.session.execute(
        db.text('UPDATE plan_exercises SET superset_group = :grp WHERE training_plan_id = :pid AND exercise_id = :eid'),
        {'grp': group, 'pid': training_plan_id, 'eid': exercise_id}
    )
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

    # Load current positions
    rows = db.session.execute(
        db.text('SELECT exercise_id, position FROM plan_exercises WHERE training_plan_id = :pid ORDER BY COALESCE(position, 999999), exercise_id'),
        {'pid': training_plan_id}
    ).fetchall()

    ordered = [(row[0], row[1]) for row in rows]

    # Find the index of the exercise to move
    idx = None
    for i, (eid, _) in enumerate(ordered):
        if eid == exercise_id:
            idx = i
            break
    if idx is None:
        abort(400)

    # Swap with neighbor
    if direction == 'up' and idx > 0:
        ordered[idx], ordered[idx - 1] = ordered[idx - 1], ordered[idx]
    elif direction == 'down' and idx < len(ordered) - 1:
        ordered[idx], ordered[idx + 1] = ordered[idx + 1], ordered[idx]

    # Update all positions
    for pos, (eid, _) in enumerate(ordered):
        db.session.execute(
            db.text('UPDATE plan_exercises SET position = :pos WHERE training_plan_id = :pid AND exercise_id = :eid'),
            {'pos': pos, 'pid': training_plan_id, 'eid': eid}
        )
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


@app.route('/shared/<token>')
@login_required
def copy_shared_plan(token):
    source_plan = TrainingPlan.query.filter_by(share_token=token).first_or_404()
    if source_plan.user_id == current_user.id:
        flash('Das ist dein eigener Plan.', 'info')
        return redirect(url_for('training_plan_detail', training_plan_id=source_plan.id))
    # Plan kopieren
    new_plan = TrainingPlan(
        title=source_plan.title + ' (kopiert)',
        description=source_plan.description,
        user_id=current_user.id,
    )
    db.session.add(new_plan)
    db.session.flush()
    for exercise in source_plan.exercises:
        new_exercise = Exercise(
            name=exercise.name,
            description=exercise.description,
            video_url=exercise.video_url,
            muscle_group=exercise.muscle_group,
            user_id=current_user.id,
        )
        db.session.add(new_exercise)
        db.session.flush()
        new_plan.exercises.append(new_exercise)
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
    exercise_overview = []
    for exercise in training_plan.exercises:
        user_sessions = [s for s in exercise.sessions if s.user_id == current_user.id]
        user_sessions_sorted = sorted(user_sessions, key=lambda s: s.timestamp, reverse=True)
        stats = calculate_exercise_statistics(user_sessions)
        exercise_overview.append({
            'exercise': exercise,
            'summary': stats['summary'],
            'personal_bests': stats['personal_bests'],
            'recent_sessions': user_sessions_sorted[:10] if include_sessions else [],
        })
    return render_template(
        'print_training_plan.html',
        training_plan=training_plan,
        exercise_overview=exercise_overview,
        include_sessions=include_sessions,
        print_date=datetime.datetime.now()
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
        .order_by(Exercise.name)
        .distinct()
        .all()
    )
    if form.validate_on_submit():
        selected_id = request.form.get('existing_exercise_id')
        if selected_id:
            exercise = Exercise.query.get_or_404(int(selected_id))
            if not any(p.user_id == current_user.id for p in exercise.training_plans):
                abort(403)
        else:
            exercise = Exercise(
                name=form.name.data,
                description=form.description.data,
                video_url=form.video_url.data or None,
                muscle_group=form.muscle_group.data or None,
                user_id=current_user.id,
            )
            db.session.add(exercise)
            db.session.flush()
        if exercise not in training_plan.exercises:
            training_plan.exercises.append(exercise)
        db.session.commit()
        flash('Übung hinzugefügt!', 'success')
        return redirect(url_for('training_plan_detail', training_plan_id=training_plan_id))
    return render_template('add_exercise_to_plan.html', form=form, training_plan=training_plan, existing_exercises=existing_exercises)

@app.route('/exercise/<int:exercise_id>/add_session', methods=['GET','POST'])
@login_required
def add_session(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
    if not any(p.user_id == current_user.id for p in exercise.training_plans):
        abort(403)
    form = ExerciseSessionForm()
    if request.method == 'GET':
        last_session = (
            ExerciseSession.query
            .filter_by(exercise_id=exercise_id, user_id=current_user.id)
            .order_by(ExerciseSession.timestamp.desc())
            .first()
        )
        if last_session:
            form.repetitions.data = last_session.repetitions
            form.weight.data = int(last_session.weight)
            form.perceived_exertion.data = last_session.perceived_exertion
            form.notes.data = last_session.notes
    if form.validate_on_submit():
        # PR-Check vor dem Speichern
        pr_records = check_new_personal_records(
            exercise_id, current_user.id,
            form.weight.data, form.repetitions.data
        )
        new_session = ExerciseSession(
            exercise_id=exercise_id,
            repetitions=form.repetitions.data,
            weight=form.weight.data,
            timestamp=datetime.datetime.now(),
            perceived_exertion=form.perceived_exertion.data,
            notes=form.notes.data,
            user_id=current_user.id,
        )
        db.session.add(new_session)
        db.session.commit()
        flash('Satz hinzugefügt!', 'success')
        for pr in pr_records:
            flash(pr, 'warning')
        return redirect(url_for('exercise_detail', exercise_id=exercise_id))
    return render_template('add_session.html', form=form, exercise=exercise)

@app.route('/exercise/<int:exercise_id>/detail')
@login_required
def exercise_detail(exercise_id):
    exercise = Exercise.query.get_or_404(exercise_id)
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

    stats = calculate_exercise_statistics(all_sessions)
    progression = calculate_progression_suggestion(all_sessions)

    def serialize_session(s):
        return {
            'id': s.id,
            'timestamp': s.timestamp.strftime('%d.%m.%Y %H:%M'),
            'weight': s.weight,
            'repetitions': s.repetitions,
            'notes': s.notes,
            'perceived_exertion': s.perceived_exertion,
        }
    all_sessions_serialized = [serialize_session(s) for s in all_sessions]
    delete_exercise_form = DeleteExerciseForm()
    delete_session_form = DeleteSessionForm()
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
    user_plan = next((p for p in exercise.training_plans if p.user_id == current_user.id), None)
    if not user_plan:
        abort(403)
    form = DeleteExerciseForm()
    if form.validate_on_submit():
        user_plan.exercises.remove(exercise)
        if not exercise.training_plans:
            db.session.delete(exercise)
        db.session.commit()
        flash('Übung gelöscht!', 'info')
        return redirect(url_for('training_plan_detail', training_plan_id=user_plan.id if user_plan else 0))
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

# ----------------------------------------------------
# Synchronisations-API (für Offline-Daten)
# ----------------------------------------------------
@app.route('/sync', methods=['POST'])
@login_required
def sync():
    data = request.get_json()
    sessions_data = data.get('sessions', [])
    sessions_to_add = []
    for session_info in sessions_data:
        exercise_id = session_info.get('exercise_id')
        exercise = Exercise.query.get(exercise_id)
        if not exercise:
            return jsonify({'status': 'error', 'message': f'Übung {exercise_id} existiert nicht'}), 400
        if not any(p.user_id == current_user.id for p in exercise.training_plans):
            return jsonify({'status': 'error', 'message': 'Unautorisierte Übungs-ID'}), 403
        try:
            timestamp = datetime.datetime.fromisoformat(session_info.get('timestamp'))
        except Exception:
            timestamp = datetime.datetime.now()
        perceived_exertion = session_info.get('perceived_exertion')
        if perceived_exertion == '' or perceived_exertion is None:
            perceived_exertion = None
        else:
            try:
                perceived_exertion = int(perceived_exertion)
            except (TypeError, ValueError):
                perceived_exertion = None
        new_session = ExerciseSession(
            exercise_id=exercise_id,
            repetitions=session_info.get('repetitions'),
            weight=session_info.get('weight'),
            timestamp=timestamp,
            notes=session_info.get('notes'),
            perceived_exertion=perceived_exertion,
            user_id=current_user.id,
        )
        sessions_to_add.append(new_session)
    for sess in sessions_to_add:
        db.session.add(sess)
    db.session.commit()
    return jsonify({'status': 'success'}), 200

# ----------------------------------------------------
# Admin-Funktionalitäten
# ----------------------------------------------------
@app.route('/admin')
@login_required
@admin_required
def admin_overview():
    users = User.query.order_by(User.registration_date.desc()).all()
    delete_user_form = DeleteUserForm()
    set_trainer_form = SetTrainerForm()
    remove_trainer_form = RemoveTrainerForm()
    return render_template(
        'admin_overview.html',
        users=users,
        delete_user_form=delete_user_form,
        set_trainer_form=set_trainer_form,
        remove_trainer_form=remove_trainer_form,
    )

@app.route('/admin/user/<int:user_id>/change_password', methods=['GET','POST'])
@login_required
@admin_required
def admin_change_password(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminChangePasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
        db.session.commit()
        flash(f'Passwort für {user.username} geändert!', 'success')
        return redirect(url_for('admin_overview'))
    return render_template('admin_change_password.html', user=user, form=form)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Du kannst deinen eigenen Account nicht löschen!', 'danger')
        return redirect(url_for('admin_overview'))
    form = DeleteUserForm()
    if form.validate_on_submit():
        db.session.delete(user)
        db.session.commit()
        flash(f'Benutzer {user.username} gelöscht!', 'info')
        return redirect(url_for('admin_overview'))
    abort(400)

# Rolle: Trainer setzen/entfernen
@app.route('/admin/user/<int:user_id>/set_trainer', methods=['POST'])
@login_required
@admin_required
def admin_set_trainer(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Du kannst dir selbst nicht den Trainer-Rang geben.", "danger")
        return redirect(url_for('admin_overview'))
    form = SetTrainerForm()
    if form.validate_on_submit():
        user.is_trainer = True
        db.session.commit()
        flash(f"{user.username} wurde der Trainer-Rang zugewiesen.", "success")
        return redirect(url_for('admin_overview'))
    abort(400)

@app.route('/admin/user/<int:user_id>/remove_trainer', methods=['POST'])
@login_required
@admin_required
def admin_remove_trainer(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Du kannst dir selbst den Trainer-Rang nicht entziehen.", "danger")
        return redirect(url_for('admin_overview'))
    form = RemoveTrainerForm()
    if form.validate_on_submit():
        user.is_trainer = False
        db.session.commit()
        flash(f"Trainer-Rang wurde von {user.username} entfernt.", "success")
        return redirect(url_for('admin_overview'))
    abort(400)

# ----------------------------------------------------
# Footer-Links verwalten
# ----------------------------------------------------
@app.route('/admin/footer_links', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_footer_links():
    form = FooterLinkForm()
    delete_form = DeleteFooterLinkForm()
    if form.validate_on_submit():
        new_link = FooterLink(title=form.title.data.strip(), url=form.url.data.strip())
        db.session.add(new_link)
        db.session.commit()
        flash('Link hinzugefügt!', 'success')
        return redirect(url_for('admin_footer_links'))
    links = FooterLink.query.all()
    return render_template('admin_footer_links.html', links=links, form=form, delete_form=delete_form)


@app.route('/admin/footer_link/<int:link_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_footer_link(link_id):
    link = FooterLink.query.get_or_404(link_id)
    form = FooterLinkForm(obj=link)
    if form.validate_on_submit():
        link.title = form.title.data.strip()
        link.url = form.url.data.strip()
        db.session.commit()
        flash('Link aktualisiert!', 'success')
        return redirect(url_for('admin_footer_links'))
    return render_template('edit_footer_link.html', form=form, link=link)


@app.route('/admin/footer_link/<int:link_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_footer_link(link_id):
    link = FooterLink.query.get_or_404(link_id)
    form = DeleteFooterLinkForm()
    if form.validate_on_submit():
        db.session.delete(link)
        db.session.commit()
        flash('Link gelöscht!', 'info')
        return redirect(url_for('admin_footer_links'))
    abort(400)


# ----------------------------------------------------
# Footer-Seiten verwalten
# ----------------------------------------------------
@app.route('/admin/footer_pages', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_footer_pages():
    form = FooterPageForm()
    delete_form = DeleteFooterPageForm()
    if form.validate_on_submit():
        new_page = FooterPage(title=form.title.data, content=form.content.data)
        db.session.add(new_page)
        db.session.commit()
        flash('Seite hinzugefügt!', 'success')
        return redirect(url_for('admin_footer_pages'))
    pages = FooterPage.query.all()
    return render_template('admin_footer_pages.html', pages=pages, form=form, delete_form=delete_form)

@app.route('/admin/footer_page/<int:page_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_footer_page(page_id):
    page = FooterPage.query.get_or_404(page_id)
    form = FooterPageForm(obj=page)
    if form.validate_on_submit():
        page.title = form.title.data
        page.content = form.content.data
        db.session.commit()
        flash('Seite aktualisiert!', 'success')
        return redirect(url_for('admin_footer_pages'))
    return render_template('edit_footer_page.html', form=form, page=page)

@app.route('/admin/footer_page/<int:page_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_footer_page(page_id):
    page = FooterPage.query.get_or_404(page_id)
    form = DeleteFooterPageForm()
    if form.validate_on_submit():
        db.session.delete(page)
        db.session.commit()
        flash('Seite gelöscht!', 'info')
        return redirect(url_for('admin_footer_pages'))
    abort(400)

@app.route('/page/<int:page_id>')
def view_footer_page(page_id):
    page = FooterPage.query.get_or_404(page_id)
    # Convert markdown to HTML
    raw_html = markdown.markdown(page.content)
    # Sanitize HTML - only allow safe tags for formatted text
    allowed_tags = [
        'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'hr', 'a'
    ]
    allowed_attrs = {
        'a': ['href', 'title'],  # Allow links but not javascript:
    }
    html = bleach.clean(raw_html, tags=allowed_tags, attributes=allowed_attrs, strip=True)
    # Ensure links don't use javascript: protocol
    html = bleach.linkify(html)
    return render_template('footer_page.html', page=page, html_content=html)


# ----------------------------------------------------
# Admin-/Trainer-Funktionalitäten für Template-Pläne
# ----------------------------------------------------
@app.route('/admin/template_plans')
@login_required
@trainer_or_admin_required
def admin_template_plans():
    templates = TemplateTrainingPlan.query.all()
    toggle_form = ToggleTemplateVisibilityForm()
    delete_tpl_form = DeleteTemplatePlanForm()
    return render_template('admin_template_plans.html', templates=templates, toggle_form=toggle_form, delete_tpl_form=delete_tpl_form)

@app.route('/admin/template_plan/create', methods=['GET', 'POST'])
@login_required
@trainer_or_admin_required
def create_template_plan():
    form = TemplateTrainingPlanForm()
    if form.validate_on_submit():
        new_template = TemplateTrainingPlan(
            title=form.title.data,
            description=form.description.data,
            creator_id=current_user.id,
            is_visible=True
        )
        db.session.add(new_template)
        db.session.commit()
        flash('Template Trainingsplan erstellt!', 'success')
        return redirect(url_for('admin_template_plans'))
    return render_template('create_template_plan.html', form=form)


@app.route('/admin/template_plan/import', methods=['GET', 'POST'])
@login_required
@trainer_or_admin_required
def import_template_plan():
    form = MarkdownImportForm()
    preview = None

    if form.validate_on_submit():
        parsed = parse_training_plan_markdown(form.markdown_content.data)

        # Check if this is a preview request
        if request.form.get('action') == 'preview':
            preview = parsed
            return render_template('import_template_plan.html', form=form, preview=preview)

        # Import action
        if not parsed['success']:
            for error in parsed['errors']:
                flash(error, 'danger')
            return render_template('import_template_plan.html', form=form, preview=parsed)

        # Create the template training plan
        new_template = TemplateTrainingPlan(
            title=parsed['plan_title'],
            description=parsed['plan_description'],
            creator_id=current_user.id,
            is_visible=True
        )
        db.session.add(new_template)
        db.session.flush()

        # Create template exercises
        for ex_data in parsed['exercises']:
            template_exercise = TemplateExercise(
                name=ex_data['name'],
                description=ex_data['description'],
                template_plan_id=new_template.id
            )
            db.session.add(template_exercise)

        db.session.commit()
        flash(f"Template '{new_template.title}' mit {len(parsed['exercises'])} Übungen importiert!", 'success')
        return redirect(url_for('admin_template_plans'))

    return render_template('import_template_plan.html', form=form, preview=preview)


@app.route('/admin/template_plan/<int:template_plan_id>/edit', methods=['GET','POST'])
@login_required
@trainer_or_admin_required
def edit_template_plan(template_plan_id):
    template_plan = TemplateTrainingPlan.query.get_or_404(template_plan_id)
    form = TemplateTrainingPlanForm(obj=template_plan)
    if form.validate_on_submit():
        template_plan.title = form.title.data
        template_plan.description = form.description.data
        db.session.commit()
        flash('Template Trainingsplan aktualisiert!', 'success')
        return redirect(url_for('admin_template_plans'))
    return render_template('edit_template_plan.html', form=form, template_plan=template_plan)

@app.route('/admin/template_plan/<int:template_plan_id>/add_exercise', methods=['GET','POST'])
@login_required
@trainer_or_admin_required
def add_exercise_to_template(template_plan_id):
    template_plan = TemplateTrainingPlan.query.get_or_404(template_plan_id)
    form = TemplateExerciseForm()
    if form.validate_on_submit():
        new_exercise = TemplateExercise(
            name=form.name.data,
            description=form.description.data,  # Beschreibung der Template-Übung
            template_plan_id=template_plan_id
        )
        db.session.add(new_exercise)
        db.session.commit()
        flash('Übung zur Vorlage hinzugefügt!', 'success')
        return redirect(url_for('admin_template_plans'))
    return render_template('add_exercise_to_template.html', form=form, template_plan=template_plan)

@app.route('/admin/template_plan/<int:template_plan_id>/toggle_visibility', methods=['POST'])
@login_required
@trainer_or_admin_required
def toggle_template_visibility(template_plan_id):
    template_plan = TemplateTrainingPlan.query.get_or_404(template_plan_id)
    form = ToggleTemplateVisibilityForm()
    if form.validate_on_submit():
        template_plan.is_visible = not template_plan.is_visible
        db.session.commit()
        status = "sichtbar" if template_plan.is_visible else "unsichtbar"
        flash(f"Template Trainingsplan ist jetzt {status}.", "success")
        return redirect(url_for('admin_template_plans'))
    abort(400)

@app.route('/admin/template_plan/<int:template_plan_id>/delete', methods=['POST'])
@login_required
@trainer_or_admin_required
def delete_template_plan(template_plan_id):
    template_plan = TemplateTrainingPlan.query.get_or_404(template_plan_id)
    form = DeleteTemplatePlanForm()
    if form.validate_on_submit():
        db.session.delete(template_plan)
        db.session.commit()
        flash("Template Trainingsplan gelöscht!", "info")
        return redirect(url_for('admin_template_plans'))
    abort(400)

# ----------------------------------------------------
# Benutzeransicht für Vorlagen
# ----------------------------------------------------
@app.route('/template_plans')
@login_required
def template_plans():
    if current_user.is_admin or current_user.is_trainer:
        templates = TemplateTrainingPlan.query.all()
    else:
        templates = TemplateTrainingPlan.query.filter_by(is_visible=True).all()
    return render_template('template_plans.html', templates=templates)

@app.route('/template_plan/<int:template_plan_id>/view')
@login_required
def view_template_plan(template_plan_id):
    template_plan = TemplateTrainingPlan.query.get_or_404(template_plan_id)
    # Falls der Plan unsichtbar ist und der aktuelle User kein Admin/Trainer, 403
    if not template_plan.is_visible and not (current_user.is_admin or current_user.is_trainer):
        abort(403)
    return render_template('view_template_plan.html', template_plan=template_plan)

@app.route('/template_plan/<int:template_plan_id>/add_to_account', methods=['POST'])
@login_required
def add_template_to_account(template_plan_id):
    template_plan = TemplateTrainingPlan.query.get_or_404(template_plan_id)
    # Falls der Plan unsichtbar ist und der aktuelle User kein Admin/Trainer, 403
    if not template_plan.is_visible and not (current_user.is_admin or current_user.is_trainer):
        abort(403)

    new_plan = TrainingPlan(
        title=template_plan.title,
        description=template_plan.description,
        user_id=current_user.id
    )
    db.session.add(new_plan)
    db.session.flush()  # Neue ID generieren

    for temp_ex in template_plan.exercises:
        exercise = Exercise(
            name=temp_ex.name,
            description=temp_ex.description,
            user_id=current_user.id,
        )
        db.session.add(exercise)
        db.session.flush()
        new_plan.exercises.append(exercise)

    db.session.commit()
    flash('Template Trainingsplan wurde zu deinem Konto hinzugefügt!', 'success')
    return redirect(url_for('dashboard'))

# ----------------------------------------------------
# REST API Endpunkte
# ----------------------------------------------------

@api_bp.route('/register', methods=['POST'])
def api_register():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'username exists'}), 400
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password, is_admin=(User.query.first() is None))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'registered'}), 201


@api_bp.route('/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        user.last_login = datetime.datetime.now()
        db.session.commit()
        return jsonify({'message': 'logged in'})
    return jsonify({'error': 'invalid credentials'}), 401


@api_bp.route('/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({'message': 'logged out'})


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
    data = request.get_json() or {}
    repetitions = data.get('repetitions')
    weight = data.get('weight')
    notes = data.get('notes')
    perceived_exertion = data.get('perceived_exertion')
    if repetitions is None or weight is None:
        return jsonify({'error': 'repetitions and weight required'}), 400
    if perceived_exertion == '' or perceived_exertion is None:
        perceived_exertion = None
    else:
        try:
            perceived_exertion = int(perceived_exertion)
        except (TypeError, ValueError):
            return jsonify({'error': 'perceived_exertion must be an integer'}), 400
    pr_records = check_new_personal_records(
        exercise_id, current_user.id, int(weight), int(repetitions)
    )
    new_session = ExerciseSession(
        exercise_id=exercise_id,
        repetitions=repetitions,
        weight=weight,
        timestamp=datetime.datetime.now(),
        notes=notes,
        perceived_exertion=perceived_exertion,
        user_id=current_user.id,
    )
    db.session.add(new_session)
    db.session.commit()
    for pr in pr_records:
        flash(pr, 'warning')
    return jsonify({'id': new_session.id, 'personal_records': pr_records}), 201


app.register_blueprint(api_bp)


def serialize_training_plan(plan):
    return {
        'id': plan.id,
        'title': plan.title,
        'description': plan.description,
    }


def serialize_exercise(exercise):
    return {
        'id': exercise.id,
        'name': exercise.name,
        'description': exercise.description,
    }


def serialize_session(session):
    return {
        'id': session.id,
        'timestamp': session.timestamp.isoformat() if session.timestamp else None,
        'weight': session.weight,
        'repetitions': session.repetitions,
        'notes': session.notes,
        'perceived_exertion': session.perceived_exertion,
    }


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

    timestamp = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

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

_ensure_database_setup_once()


if hasattr(app, 'before_first_request'):

    @app.before_first_request
    def _ensure_tables_before_first_request() -> None:
        """Ensure database tables exist before handling the first request."""

        _ensure_database_setup_once()

else:

    @app.before_request
    def _ensure_tables_before_request() -> None:
        """Ensure database tables exist before handling the first request."""

        _ensure_database_setup_once()


# Anwendung starten
# ----------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Tabellen erstellen (nur beim ersten Start)
    app.run(debug=True)
