"""E-Mail-Versand (Bestätigung, Passwort-Reset)."""

import html
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import url_for

from gewichts_tracker.core import app
from gewichts_tracker.crypto import decrypt_value
from gewichts_tracker.models import get_app_settings
from gewichts_tracker.security import make_password_reset_token


def _smtp_connect(settings):
    """Create and return an authenticated SMTP connection using app settings."""
    if settings.smtp_use_tls:
        server = smtplib.SMTP(settings.smtp_server, settings.smtp_port)
        server.starttls()
    else:
        server = smtplib.SMTP_SSL(settings.smtp_server, settings.smtp_port)
    if settings.smtp_username and settings.smtp_password:
        server.login(settings.smtp_username, decrypt_value(settings.smtp_password))
    return server


def send_app_email(to_address, subject, html_body):
    """Send one HTML mail via the configured SMTP server. Returns True on success."""
    settings = get_app_settings()
    if not settings.smtp_server or not settings.smtp_sender_email:
        return False
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = settings.smtp_sender_email
    msg['To'] = to_address
    msg.attach(MIMEText(html_body, 'html'))
    try:
        server = _smtp_connect(settings)
        server.sendmail(settings.smtp_sender_email, to_address, msg.as_string())
        server.quit()
        return True
    except Exception as exc:
        app.logger.error('Failed to send email: %s', exc)
        return False


def send_password_reset_email(user):
    settings = get_app_settings()
    app_name = settings.app_name or 'Gewichts-Tracker'
    reset_url = html.escape(
        url_for('reset_password', token=make_password_reset_token(user), _external=True), quote=True)
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #007bff;">{html.escape(app_name)}</h2>
        <p>Hallo <strong>{html.escape(user.username)}</strong>,</p>
        <p>für dein Konto wurde ein neues Passwort angefordert. Der folgende Link ist 1 Stunde gültig:</p>
        <p style="text-align: center; margin: 30px 0;">
            <a href="{reset_url}"
               style="background: #007bff; color: #fff; padding: 12px 28px; border-radius: 6px;
                      text-decoration: none; font-weight: bold;">
                Neues Passwort setzen
            </a>
        </p>
        <p style="font-size: 0.85rem; color: #666;">
            Oder kopiere diesen Link in deinen Browser:<br>
            <a href="{reset_url}">{reset_url}</a>
        </p>
        <p style="font-size: 0.85rem; color: #999; margin-top: 30px;">
            Falls du das nicht warst, kannst du diese E-Mail ignorieren. Dein Passwort bleibt unverändert.
        </p>
    </div>
    """
    return send_app_email(user.email, f'{app_name} – Passwort zurücksetzen', html_body)


def send_verification_email(user):
    """Send an email verification link to the user using SMTP settings from AppSettings."""
    settings = get_app_settings()
    if not settings.smtp_server or not settings.smtp_sender_email:
        return False

    confirm_url = html.escape(url_for('confirm_email', token=user.email_token, _external=True), quote=True)
    app_name = settings.app_name or 'Gewichts-Tracker'
    app_name_html = html.escape(app_name)

    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #007bff;">{app_name_html}</h2>
        <p>Hallo <strong>{html.escape(user.username)}</strong>,</p>
        <p>bitte bestätige deine E-Mail-Adresse, indem du auf den folgenden Link klickst:</p>
        <p style="text-align: center; margin: 30px 0;">
            <a href="{confirm_url}"
               style="background: #007bff; color: #fff; padding: 12px 28px; border-radius: 6px;
                      text-decoration: none; font-weight: bold;">
                E-Mail bestätigen
            </a>
        </p>
        <p style="font-size: 0.85rem; color: #666;">
            Oder kopiere diesen Link in deinen Browser:<br>
            <a href="{confirm_url}">{confirm_url}</a>
        </p>
        <p style="font-size: 0.85rem; color: #999; margin-top: 30px;">
            Falls du dich nicht registriert hast, kannst du diese E-Mail ignorieren.
            Der Account wird nach 7 Tagen automatisch gelöscht.
        </p>
    </div>
    """

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'{app_name} – E-Mail bestätigen'
    msg['From'] = settings.smtp_sender_email
    msg['To'] = user.email
    msg.attach(MIMEText(html_body, 'html'))

    try:
        server = _smtp_connect(settings)
        server.sendmail(settings.smtp_sender_email, user.email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        app.logger.error('Failed to send verification email: %s', e)
        return False
