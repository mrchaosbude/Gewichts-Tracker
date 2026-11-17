"""Vorlagen (Template-Trainingspläne) für Trainer, Admins und Benutzer."""

from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from gewichts_tracker import services
from gewichts_tracker.core import app, db
from gewichts_tracker.models import TemplateExercise, TemplateTrainingPlan
from gewichts_tracker.permissions import trainer_or_admin_required
from gewichts_tracker.markdown_import import parse_training_plan_markdown
from gewichts_tracker.forms import (
    DeleteTemplatePlanForm,
    MarkdownImportForm,
    TemplateExerciseForm,
    TemplateTrainingPlanForm,
    ToggleTemplateVisibilityForm,
)


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
                description=ex_data['description'] if not ex_data.get('is_separator') else None,
                is_separator=ex_data.get('is_separator', False),
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
    if not services.template_visible_to(template_plan, current_user):
        abort(403)
    services.copy_template_for(template_plan, current_user.id)
    db.session.commit()
    flash('Template Trainingsplan wurde zu deinem Konto hinzugefügt!', 'success')
    return redirect(url_for('dashboard'))
