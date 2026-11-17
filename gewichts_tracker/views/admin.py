"""Admin-Bereich: Benutzer, Einstellungen, Footer."""

import html
import os

import markdown
import nh3

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user
from werkzeug.security import generate_password_hash

from gewichts_tracker.core import app, db
from gewichts_tracker.crypto import encrypt_value
from gewichts_tracker.models import FooterLink, FooterPage, get_app_settings, User
from gewichts_tracker.security import disable_two_factor
from gewichts_tracker.permissions import admin_required
from gewichts_tracker.mail import _smtp_connect, BASE_URL_ENV, normalize_base_url, public_base_url
from gewichts_tracker.accounts import delete_user_with_data
from gewichts_tracker.forms import (
    AdminChangePasswordForm,
    AppSettingsForm,
    BroadcastEmailForm,
    DeleteFooterLinkForm,
    DeleteFooterPageForm,
    DeleteUserForm,
    FooterLinkForm,
    FooterPageForm,
    RemoveTrainerForm,
    SetTrainerForm,
)


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


@app.route('/admin/settings', methods=['GET','POST'])
@login_required
@admin_required
def admin_settings():
    settings = get_app_settings()
    form = AppSettingsForm(obj=settings)
    base_url_from_env = normalize_base_url(os.environ.get(BASE_URL_ENV))
    if form.is_submitted() and form.base_url.data and normalize_base_url(form.base_url.data) is None:
        form.base_url.errors = list(form.base_url.errors) + [
            'Bitte nur Schema und Host angeben, z. B. https://fit.example.de']
    elif form.validate_on_submit():
        settings.app_name = form.app_name.data
        settings.base_url = normalize_base_url(form.base_url.data)
        settings.chart_weight = form.chart_weight.data
        settings.chart_reps = form.chart_reps.data
        settings.chart_volume = form.chart_volume.data
        settings.chart_volume_avg = form.chart_volume_avg.data
        settings.chart_1rm = form.chart_1rm.data
        settings.chart_1rm_avg = form.chart_1rm_avg.data
        settings.require_email_verification = form.require_email_verification.data
        settings.registration_enabled = form.registration_enabled.data
        settings.require_admin_2fa = form.require_admin_2fa.data
        settings.smtp_server = form.smtp_server.data
        settings.smtp_port = form.smtp_port.data or 587
        settings.smtp_username = form.smtp_username.data
        if form.smtp_password.data:
            settings.smtp_password = encrypt_value(form.smtp_password.data)
        settings.smtp_use_tls = form.smtp_use_tls.data
        settings.smtp_sender_email = form.smtp_sender_email.data
        db.session.commit()
        flash('Einstellungen gespeichert!', 'success')
        return redirect(url_for('admin_settings'))
    suggested_base_url = None
    if not settings.base_url and not base_url_from_env and request.method == 'GET':
        # Vorschlag aus der Adresse, mit der der Admin gerade arbeitet; gilt erst nach Speichern
        suggested_base_url = normalize_base_url(request.host_url)
        form.base_url.data = suggested_base_url
    return render_template('admin_settings.html', form=form, settings=settings,
                           base_url_from_env=base_url_from_env, suggested_base_url=suggested_base_url,
                           mail_links_missing=bool(settings.smtp_server) and public_base_url() is None)


@app.route('/admin/test-email', methods=['POST'])
@login_required
@admin_required
def admin_test_email():
    settings = get_app_settings()
    if not settings.smtp_server or not settings.smtp_sender_email:
        flash('Bitte zuerst SMTP-Einstellungen konfigurieren.', 'danger')
        return redirect(url_for('admin_settings'))
    app_name = settings.app_name or 'Gewichts-Tracker'
    test_to = settings.smtp_sender_email
    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'{app_name} – Test-E-Mail'
    msg['From'] = settings.smtp_sender_email
    msg['To'] = test_to
    test_html = f'<p>Dies ist eine Test-E-Mail von <strong>{html.escape(app_name)}</strong>. Die SMTP-Konfiguration funktioniert!</p>'
    msg.attach(MIMEText(test_html, 'html'))
    try:
        server = _smtp_connect(settings)
        server.sendmail(settings.smtp_sender_email, test_to, msg.as_string())
        server.quit()
        flash(f'Test-E-Mail an {test_to} gesendet!', 'success')
    except Exception as e:
        flash(f'Fehler beim Senden: {e}', 'danger')
    return redirect(url_for('admin_settings'))


@app.route('/admin/broadcast-email', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_broadcast_email():
    settings = get_app_settings()
    smtp_configured = bool(settings.smtp_server and settings.smtp_sender_email)
    form = BroadcastEmailForm()
    if form.validate_on_submit():
        if not smtp_configured:
            flash('Bitte zuerst SMTP-Einstellungen in den Einstellungen konfigurieren.', 'danger')
            return redirect(url_for('admin_settings'))
        recipients = User.query.filter(User.email.isnot(None), User.email != '', User.email_confirmed == True).all()
        if not recipients:
            flash('Keine Benutzer mit bestätigter E-Mail-Adresse gefunden.', 'warning')
            return redirect(url_for('admin_broadcast_email'))
        app_name = settings.app_name or 'Gewichts-Tracker'
        sent = 0
        errors = 0
        try:
            server = _smtp_connect(settings)
            for user in recipients:
                try:
                    msg = MIMEMultipart('alternative')
                    msg['Subject'] = form.subject.data
                    msg['From'] = settings.smtp_sender_email
                    msg['To'] = user.email
                    html_body = f"""
                    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #007bff;">{html.escape(app_name)}</h2>
                        <p>Hallo <strong>{html.escape(user.username)}</strong>,</p>
                        <div>{form.message.data}</div>
                        <hr style="margin-top: 30px; border: none; border-top: 1px solid #eee;">
                        <p style="font-size: 0.8rem; color: #999;">{html.escape(app_name)}</p>
                    </div>
                    """
                    msg.attach(MIMEText(html_body, 'html'))
                    server.sendmail(settings.smtp_sender_email, user.email, msg.as_string())
                    sent += 1
                except Exception:
                    errors += 1
            server.quit()
        except Exception as e:
            flash(f'SMTP-Verbindungsfehler: {e}', 'danger')
            return redirect(url_for('admin_broadcast_email'))
        if errors:
            flash(f'E-Mail an {sent} Benutzer gesendet, {errors} fehlgeschlagen.', 'warning')
        else:
            flash(f'E-Mail erfolgreich an {sent} Benutzer gesendet!', 'success')
        return redirect(url_for('admin_overview'))
    return render_template('admin_broadcast_email.html', form=form, smtp_configured=smtp_configured)


@app.route('/admin/user/<int:user_id>/change_password', methods=['GET','POST'])
@login_required
@admin_required
def admin_change_password(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminChangePasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
        db.session.commit()
        if user.id == current_user.id:
            login_user(user)  # eigene Sitzung behalten
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
        username = user.username
        delete_user_with_data(user)
        db.session.commit()
        flash(f'Benutzer {username} gelöscht!', 'info')
        return redirect(url_for('admin_overview'))
    abort(400)


@app.route('/admin/user/<int:user_id>/reset_2fa', methods=['POST'])
@login_required
@admin_required
def admin_reset_two_factor(user_id):
    user = User.query.get_or_404(user_id)
    form = SetTrainerForm()
    if form.validate_on_submit():
        disable_two_factor(user)
        db.session.commit()
        flash(f'Zwei-Faktor-Anmeldung für {user.username} zurückgesetzt.', 'info')
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
    allowed_tags = {
        'p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'hr', 'a'
    }
    allowed_attrs = {
        'a': {'href', 'title'},
    }
    html = nh3.clean(raw_html, tags=allowed_tags, attributes=allowed_attrs, url_schemes={'http', 'https', 'mailto'})
    return render_template('footer_page.html', page=page, html_content=html)
