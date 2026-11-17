"""E-Mail-Versand (Bestätigung, Passwort-Reset)."""

import html
import os
import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import url_for

from env_config import BASE_URL_ENV, normalize_base_url
from gewichts_tracker.core import app
from gewichts_tracker.crypto import decrypt_value
from gewichts_tracker.models import get_app_settings
from gewichts_tracker.security import make_password_reset_token


def public_base_url():
    """Address of the app for links in e-mails: environment variable, else admin setting.

    Bewusst NICHT aus dem Host-Header der Anfrage: den bestimmt der Absender, und ein
    Angreifer könnte so Reset-Links auf seine eigene Domain umleiten.
    """
    return normalize_base_url(os.environ.get(BASE_URL_ENV)) or normalize_base_url(get_app_settings().base_url)


def external_url(endpoint, **values):
    base = public_base_url()
    if base is None:
        return None
    return base + url_for(endpoint, **values)


def smtp_configured(settings=None):
    settings = settings or get_app_settings()
    return bool(settings.smtp_server and settings.smtp_sender_email)


def mail_links_available():
    """True if mails with links (reset, confirmation) can be sent."""
    return smtp_configured() and public_base_url() is not None


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
    link = external_url('reset_password', token=make_password_reset_token(user))
    if link is None:
        app.logger.warning('Password reset mail not sent: no app address configured (%s)', BASE_URL_ENV)
        return False
    reset_url = html.escape(link, quote=True)
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


def send_verification_email(user, to=None):
    """Send the confirmation link to *to* (default: the user's address).

    With ``to`` set this confirms a changed address (``user.pending_email``).
    """
    settings = get_app_settings()
    if not smtp_configured(settings):
        return False
    link = external_url('confirm_email', token=user.email_token)
    if link is None:
        app.logger.warning('Confirmation mail not sent: no app address configured (%s)', BASE_URL_ENV)
        return False
    recipient = to or user.email
    change = to is not None
    confirm_url = html.escape(link, quote=True)
    app_name = settings.app_name or 'Gewichts-Tracker'
    app_name_html = html.escape(app_name)
    intro = ('bitte bestätige deine neue E-Mail-Adresse. Bis dahin bleibt deine bisherige Adresse aktiv:'
             if change else 'bitte bestätige deine E-Mail-Adresse, indem du auf den folgenden Link klickst:')
    footer = ('Falls du das nicht warst, ignoriere diese E-Mail; es ändert sich nichts.'
              if change else 'Falls du dich nicht registriert hast, kannst du diese E-Mail ignorieren.\n'
                             '            Der Account wird nach 7 Tagen automatisch gelöscht.')

    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #007bff;">{app_name_html}</h2>
        <p>Hallo <strong>{html.escape(user.username)}</strong>,</p>
        <p>{intro}</p>
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
            {footer}
        </p>
    </div>
    """
    return send_app_email(recipient, f'{app_name} – E-Mail bestätigen', html_body)
