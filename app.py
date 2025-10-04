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
)
import markdown
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, IntegerField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, InputRequired, Length, EqualTo, ValidationError, Optional, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import io
import json
import csv
import zipfile
import os

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

plan_exercises = db.Table(
    'plan_exercises',
    db.Column('training_plan_id', db.Integer, db.ForeignKey('training_plan.id'), primary_key=True),
    db.Column('exercise_id', db.Integer, db.ForeignKey('exercise.id'), primary_key=True)
)


class TrainingPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exercises = db.relationship('Exercise', secondary=plan_exercises, back_populates='training_plans')

class Exercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(300), nullable=True)  # Beschreibung der Übung
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


@app.context_processor
def inject_footer_pages():
    """Provide footer pages to all templates."""

    _ensure_database_setup_once()
    return {"footer_pages": FooterPage.query.all()}


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
    description = StringField('Beschreibung (optional)')  # Beschreibung bei normaler Übung
    submit = SubmitField('Übung hinzufügen')

class ExerciseSessionForm(FlaskForm):
    repetitions = IntegerField('Wiederholungen', validators=[DataRequired()], render_kw={"onfocus": "this.select()"})
    weight = IntegerField('Gewicht (kg)', validators=[InputRequired()], render_kw={"step": "1", "onfocus": "this.select()"})
    perceived_exertion = IntegerField(
        'RPE (optional)',
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
    return render_template('dashboard.html', training_plans=training_plans)

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
    exercise_overview = []
    for exercise in training_plan.exercises:
        stats = calculate_exercise_statistics(exercise.sessions)
        recent_sessions = sorted(exercise.sessions, key=lambda s: s.timestamp, reverse=True)[:3]
        exercise_overview.append({
            'exercise': exercise,
            'summary': stats['summary'],
            'personal_bests': stats['personal_bests'],
            'recent_sessions': recent_sessions,
            'moving_window': stats['moving_window'],
        })
    return render_template(
        'training_plan_detail.html',
        training_plan=training_plan,
        delete_plan_form=delete_plan_form,
        editable_map=editable_map,
        exercise_overview=exercise_overview,
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
            exercise = Exercise.query.get(int(selected_id))
        else:
            exercise = Exercise(name=form.name.data, description=form.description.data)
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
        last_session = ExerciseSession.query.filter_by(exercise_id=exercise_id).order_by(ExerciseSession.timestamp.desc()).first()
        if last_session:
            form.repetitions.data = last_session.repetitions
            form.weight.data = int(last_session.weight)
            form.perceived_exertion.data = last_session.perceived_exertion
            form.notes.data = last_session.notes
    if form.validate_on_submit():
        new_session = ExerciseSession(
            exercise_id=exercise_id,
            repetitions=form.repetitions.data,
            weight=form.weight.data,
            timestamp=datetime.datetime.now(),
            perceived_exertion=form.perceived_exertion.data,
            notes=form.notes.data,
        )
        db.session.add(new_session)
        db.session.commit()
        flash('Satz hinzugefügt!', 'success')
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
    all_sessions = ExerciseSession.query.filter_by(exercise_id=exercise_id).order_by(ExerciseSession.timestamp.asc()).all()
    sessions = ExerciseSession.query.filter_by(exercise_id=exercise_id).order_by(ExerciseSession.timestamp.desc()).limit(15).all()

    stats = calculate_exercise_statistics(all_sessions)

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
    html = markdown.markdown(page.content)
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
        exercise = Exercise.query.filter_by(name=temp_ex.name, description=temp_ex.description).first()
        if not exercise:
            exercise = Exercise(name=temp_ex.name, description=temp_ex.description)
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
    exercise = Exercise.query.filter_by(name=name, description=desc).first()
    if not exercise:
        exercise = Exercise(name=name, description=desc)
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
    sessions = ExerciseSession.query.filter_by(exercise_id=exercise_id).order_by(ExerciseSession.timestamp.asc()).all()
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
    new_session = ExerciseSession(
        exercise_id=exercise_id,
        repetitions=repetitions,
        weight=weight,
        timestamp=datetime.datetime.now(),
        notes=notes,
        perceived_exertion=perceived_exertion,
    )
    db.session.add(new_session)
    db.session.commit()
    return jsonify({'id': new_session.id}), 201


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
                .filter_by(exercise_id=exercise.id)
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
