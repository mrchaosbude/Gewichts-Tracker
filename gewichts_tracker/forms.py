"""WTForms-Formulare."""

from flask_wtf import FlaskForm, RecaptchaField
from wtforms import (
    BooleanField,
    DecimalField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import (
    DataRequired,
    EqualTo,
    InputRequired,
    Length,
    NumberRange,
    Optional,
    ValidationError,
)

from gewichts_tracker.core import app
from gewichts_tracker.models import MUSCLE_GROUPS, User
from gewichts_tracker.security import EMAIL_RE, PASSWORD_MIN_LENGTH, sanitize_external_url


# ----------------------------------------------------
# Formulare
# ----------------------------------------------------
class RegistrationForm(FlaskForm):
    username = StringField('Benutzername', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('E-Mail', validators=[Optional(), Length(max=150)])
    password = PasswordField('Passwort', validators=[DataRequired(), Length(min=PASSWORD_MIN_LENGTH, max=200)])
    confirm = PasswordField('Passwort wiederholen', validators=[DataRequired(), EqualTo('password', message='Passwörter müssen übereinstimmen')])
    if app.config.get('RECAPTCHA_ENABLED', True):
        recaptcha = RecaptchaField()
    submit = SubmitField('Registrieren')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Benutzername bereits vergeben.')

    def validate_email(self, email):
        if email.data:
            if User.query.filter_by(email=email.data).first():
                raise ValidationError('Diese E-Mail-Adresse wird bereits verwendet.')


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
    is_separator = BooleanField('Als Trenner/Abschnitt hinzufügen')
    exercise_type = SelectField('Übungstyp', choices=[('kraft', 'Kraft'), ('ausdauer', 'Ausdauer')], default='kraft')
    name = StringField('Übungsname', validators=[Optional()])
    description = StringField('Beschreibung (optional)')
    video_url = StringField('Video/Anleitung URL (optional)')
    muscle_group = SelectField('Muskelgruppe (optional)', choices=[('', '-- Keine --')] + [(mg, mg) for mg in MUSCLE_GROUPS], default='')
    cardio_type = StringField('Ausdauer-Aktivität', validators=[Optional()])
    submit = SubmitField('Übung hinzufügen')


class ExerciseSessionForm(FlaskForm):
    repetitions = IntegerField('Wiederholungen', validators=[Optional()], render_kw={"onfocus": "this.select()"})
    weight = DecimalField('Gewicht (kg)', validators=[Optional()], places=1, render_kw={"step": "0.5", "onfocus": "this.select()"})
    duration_minutes = IntegerField('Dauer (Minuten)', validators=[Optional()], render_kw={"onfocus": "this.select()"})
    distance_km = DecimalField('Distanz (km, optional)', validators=[Optional()], places=2, render_kw={"onfocus": "this.select()", "step": "0.1"})
    warmup_activity = StringField('Aufwärm-Aktivität', validators=[Optional()])
    warmup_duration = IntegerField('Aufwärm-Dauer (Min)', validators=[Optional()], render_kw={"onfocus": "this.select()"})
    perceived_exertion = IntegerField(
        'Wahrgenommene Anstrengung (RPE 1-10, optional)',
        validators=[Optional(), NumberRange(min=1, max=10)],
        render_kw={"min": "1", "max": "10", "onfocus": "this.select()"}
    )
    notes = TextAreaField('Notizen', render_kw={"rows": 3})
    submit = SubmitField('Session hinzufügen')


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Aktuelles Passwort', validators=[DataRequired()])
    new_password = PasswordField('Neues Passwort', validators=[DataRequired(), Length(min=PASSWORD_MIN_LENGTH, max=200)])
    confirm = PasswordField('Neues Passwort wiederholen', validators=[DataRequired(), EqualTo('new_password', message='Passwörter müssen übereinstimmen')])
    submit = SubmitField('Passwort ändern')


class ChangeEmailForm(FlaskForm):
    email = StringField('E-Mail-Adresse', validators=[Optional(), Length(max=150)])
    current_password = PasswordField('Aktuelles Passwort', validators=[DataRequired()])
    submit = SubmitField('E-Mail speichern')

    def validate_email(self, field):
        value = (field.data or '').strip()
        if value and not EMAIL_RE.match(value):
            raise ValidationError('Bitte eine gültige E-Mail-Adresse eingeben.')


class TwoFactorCodeForm(FlaskForm):
    code = StringField('Code', validators=[DataRequired(), Length(max=20)])
    submit = SubmitField('Bestätigen')


class TwoFactorPasswordForm(FlaskForm):
    current_password = PasswordField('Aktuelles Passwort', validators=[DataRequired()])
    code = StringField('Code aus der App oder Backup-Code', validators=[Optional(), Length(max=20)])
    submit = SubmitField('Bestätigen')


class DeleteAccountForm(FlaskForm):
    current_password = PasswordField('Aktuelles Passwort', validators=[DataRequired()])
    confirm_username = StringField('Benutzername zur Bestätigung', validators=[DataRequired()])
    submit = SubmitField('Konto endgültig löschen')


class EditSessionForm(FlaskForm):
    timestamp = StringField('Datum und Uhrzeit', validators=[DataRequired()])
    repetitions = IntegerField('Wiederholungen', validators=[Optional(), NumberRange(min=1, max=100000)])
    weight = DecimalField('Gewicht (kg)', validators=[Optional(), NumberRange(min=0, max=5000)], places=1, render_kw={"step": "0.5"})
    duration_minutes = IntegerField('Dauer (Minuten)', validators=[Optional(), NumberRange(min=1, max=100000)])
    distance_km = DecimalField('Distanz (km, optional)', validators=[Optional(), NumberRange(min=0, max=100000)], places=2, render_kw={"step": "0.1"})
    warmup_activity = StringField('Aufwärm-Aktivität', validators=[Optional(), Length(max=100)])
    warmup_duration = IntegerField('Aufwärm-Dauer (Min)', validators=[Optional(), NumberRange(min=1, max=100000)])
    perceived_exertion = IntegerField('RPE (1-10, optional)', validators=[Optional(), NumberRange(min=1, max=10)],
                                      render_kw={"min": "1", "max": "10"})
    notes = TextAreaField('Notizen', validators=[Optional(), Length(max=5000)], render_kw={"rows": 3})
    submit = SubmitField('Speichern')


class ForgotPasswordForm(FlaskForm):
    identifier = StringField('Benutzername oder E-Mail', validators=[DataRequired(), Length(max=150)])
    submit = SubmitField('Link anfordern')


class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('Neues Passwort', validators=[DataRequired(), Length(min=PASSWORD_MIN_LENGTH, max=200)])
    confirm = PasswordField('Neues Passwort wiederholen', validators=[DataRequired(), EqualTo('new_password', message='Passwörter müssen übereinstimmen')])
    submit = SubmitField('Passwort speichern')


class AdminChangePasswordForm(FlaskForm):
    new_password = PasswordField('Neues Passwort', validators=[DataRequired(), Length(min=PASSWORD_MIN_LENGTH, max=200)])
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
        return sanitize_external_url(url) is not None

    def validate_url(self, field):  # noqa: D401 - Flask-WTF convention
        """Allow absolute URLs or relative paths starting with '/'."""

        value = (field.data or "").strip()
        if sanitize_external_url(value, allow_relative=True) is not None:
            return
        if not self._is_valid_absolute_url(value):
            raise ValidationError(
                "Bitte gib eine gültige URL (z. B. https://...) oder einen relativen Pfad beginnend mit '/' an."
            )


class DeleteFooterLinkForm(FlaskForm):

    submit = SubmitField('Löschen')


class AppSettingsForm(FlaskForm):
    app_name = StringField('App-Titel', validators=[DataRequired(), Length(max=150)])
    chart_weight = BooleanField('Gewichtsverlauf')
    chart_reps = BooleanField('Wiederholungen')
    chart_volume = BooleanField('Volumen')
    chart_volume_avg = BooleanField('Volumen Ø (Durchschnitt)')
    chart_1rm = BooleanField('1RM (Epley)')
    chart_1rm_avg = BooleanField('1RM Ø (Durchschnitt)')
    require_email_verification = BooleanField('E-Mail-Verifizierung aktivieren')
    registration_enabled = BooleanField('Registrierung neuer Benutzer erlauben')
    require_admin_2fa = BooleanField('Zwei-Faktor-Anmeldung für Administratoren verpflichtend')
    smtp_server = StringField('SMTP-Server', validators=[Optional(), Length(max=150)])
    smtp_port = IntegerField('SMTP-Port', validators=[Optional(), NumberRange(min=1, max=65535)], default=587)
    smtp_username = StringField('SMTP-Benutzername', validators=[Optional(), Length(max=150)])
    smtp_password = PasswordField('SMTP-Passwort', validators=[Optional(), Length(max=150)])
    smtp_use_tls = BooleanField('TLS verwenden')
    smtp_sender_email = StringField('Absender-E-Mail', validators=[Optional(), Length(max=150)])
    submit = SubmitField('Speichern')


class BodyWeightForm(FlaskForm):
    weight = DecimalField('Gewicht (kg)', validators=[InputRequired(), NumberRange(min=20, max=500)], places=1, render_kw={"step": "0.1", "onfocus": "this.select()"})
    notes = TextAreaField('Notizen (optional)', render_kw={"rows": 2})
    submit = SubmitField('Speichern')


class DeleteBodyWeightForm(FlaskForm):
    submit = SubmitField('Löschen')


class BroadcastEmailForm(FlaskForm):
    subject = StringField('Betreff', validators=[DataRequired(), Length(max=200)])
    message = TextAreaField('Nachricht (HTML erlaubt)', validators=[DataRequired()])
    submit = SubmitField('An alle senden')


class MarkdownImportForm(FlaskForm):
    markdown_content = TextAreaField('Markdown Inhalt', validators=[DataRequired()])
    submit = SubmitField('Importieren')
