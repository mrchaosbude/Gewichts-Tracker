"""Datenbankmodelle."""

from flask_login import UserMixin

from gewichts_tracker.core import _utcnow, db
from gewichts_tracker.crypto import password_fingerprint


# ----------------------------------------------------
# Datenbankmodelle
# ----------------------------------------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=True)
    email_confirmed = db.Column(db.Boolean, default=False)
    email_token = db.Column(db.String(100), nullable=True)
    email_token_created = db.Column(db.DateTime, nullable=True)
    pending_email = db.Column(db.String(150), nullable=True)  # neue Adresse, bis der Link bestätigt ist
    registration_date = db.Column(db.DateTime, default=lambda: _utcnow())
    last_login = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)
    is_trainer = db.Column(db.Boolean, default=False)
    # Zwei-Faktor-Anmeldung (TOTP)
    totp_secret = db.Column(db.String(300), nullable=True)       # verschlüsselt
    totp_enabled = db.Column(db.Boolean, default=False)
    totp_last_counter = db.Column(db.Integer, nullable=True)     # verhindert Wiederverwendung eines Codes
    totp_backup_codes = db.Column(db.Text, nullable=True)        # JSON-Liste von Hashes
    training_plans = db.relationship('TrainingPlan', backref='owner', lazy=True, cascade="all, delete-orphan")
    exercises = db.relationship('Exercise', backref='owner', lazy=True)

    def get_id(self):
        # Sitzung ist an das aktuelle Passwort gebunden (siehe password_fingerprint)
        return f'{self.id}:{password_fingerprint(self.password)}'


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
CARDIO_EXERCISES = [
    'Laufen', 'Radfahren', 'Rudern', 'Seilspringen',
    'Ellipsentrainer', 'Schwimmen', 'Wandern', 'Skifahren',
]


class Exercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(300), nullable=True)
    video_url = db.Column(db.String(500), nullable=True)
    muscle_group = db.Column(db.String(50), nullable=True)
    is_separator = db.Column(db.Boolean, default=False)
    exercise_type = db.Column(db.String(20), nullable=True, default='kraft')  # 'kraft' oder 'ausdauer'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    sessions = db.relationship('ExerciseSession', backref='exercise', lazy=True, cascade="all, delete-orphan")
    training_plans = db.relationship('TrainingPlan', secondary=plan_exercises, back_populates='exercises')


class ExerciseSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exercise_id = db.Column(db.Integer, db.ForeignKey('exercise.id'), nullable=False)
    repetitions = db.Column(db.Integer, nullable=True)
    weight = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: _utcnow(), index=True)
    notes = db.Column(db.Text)
    perceived_exertion = db.Column(db.Integer)
    duration_minutes = db.Column(db.Integer, nullable=True)   # Ausdauer: Dauer in Minuten
    distance_km = db.Column(db.Float, nullable=True)           # Ausdauer: Distanz in km
    warmup_activity = db.Column(db.String(100), nullable=True) # Aufwärmung: Aktivität
    warmup_duration = db.Column(db.Integer, nullable=True)     # Aufwärmung: Dauer in Minuten
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    client_uuid = db.Column(db.String(36), nullable=True, unique=True)


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
    is_separator = db.Column(db.Boolean, default=False)
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    weight = db.Column(db.Float, nullable=False)  # Gewicht in kg
    timestamp = db.Column(db.DateTime, default=lambda: _utcnow())
    notes = db.Column(db.Text)  # Optionale Notizen
    client_uuid = db.Column(db.String(36), nullable=True, unique=True)


class AppSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(150), default='Gewichts-Tracker')
    chart_weight = db.Column(db.Boolean, default=True)
    chart_reps = db.Column(db.Boolean, default=True)
    chart_volume = db.Column(db.Boolean, default=True)
    chart_volume_avg = db.Column(db.Boolean, default=True)
    chart_1rm = db.Column(db.Boolean, default=True)
    chart_1rm_avg = db.Column(db.Boolean, default=True)
    require_email_verification = db.Column(db.Boolean, default=False)
    registration_enabled = db.Column(db.Boolean, default=True)
    require_admin_2fa = db.Column(db.Boolean, default=False)
    base_url = db.Column(db.String(300), nullable=True)  # Adresse der App für Links in E-Mails
    smtp_server = db.Column(db.String(150), nullable=True)
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(150), nullable=True)
    smtp_password = db.Column(db.String(500), nullable=True)
    smtp_use_tls = db.Column(db.Boolean, default=True)
    smtp_sender_email = db.Column(db.String(150), nullable=True)


def get_app_settings():
    settings = AppSettings.query.first()
    if not settings:
        settings = AppSettings(id=1)
        db.session.add(settings)
        db.session.commit()
    return settings


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
    timestamp = db.Column(db.DateTime, default=lambda: _utcnow())
    notes = db.Column(db.Text)
    body_weight = db.Column(db.Float, nullable=True)
