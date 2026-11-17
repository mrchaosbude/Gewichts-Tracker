"""Markdown-Format für Trainingsplan-Importe."""

from gewichts_tracker.security import sanitize_external_url


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

    # Metadata keys recognized at the start of an exercise block
    METADATA_KEYS = {'muskelgruppe', 'typ', 'youtube'}
    current_exercise_meta = {}
    meta_phase = False  # True while we're still reading metadata lines after ##

    def _finish_exercise():
        """Helper to finalize the current exercise and append it."""
        nonlocal current_exercise, current_exercise_desc_lines, current_exercise_meta, meta_phase
        if current_exercise:
            desc = '\n'.join(current_exercise_desc_lines).strip()
            if len(desc) > 300:
                errors.append(f"Übung '{current_exercise}': Beschreibung zu lang ({len(desc)}/300 Zeichen). Wird abgeschnitten.")
            video_url = current_exercise_meta.get('youtube', '')
            if video_url and sanitize_external_url(video_url) is None:
                errors.append(f"Übung '{current_exercise}': Ungültige Video-URL (nur http/https erlaubt).")
                video_url = ''
            ex_entry = {
                'name': current_exercise,
                'description': desc[:300],
                'is_separator': False,
                'muscle_group': current_exercise_meta.get('muskelgruppe', ''),
                'exercise_type': current_exercise_meta.get('typ', ''),
                'video_url': video_url,
            }
            exercises.append(ex_entry)
            current_exercise = None
            current_exercise_desc_lines = []
            current_exercise_meta = {}
            meta_phase = False

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

        # Check for separator (---Label)
        if stripped.startswith('---') and len(stripped) > 3 and not stripped.startswith('----'):
            _finish_exercise()
            separator_label = stripped[3:].strip()
            if separator_label:
                exercises.append({'name': separator_label, 'description': '', 'is_separator': True})
            in_plan_description = False
            continue

        # Check for H2 (exercise)
        if stripped.startswith('## '):
            _finish_exercise()
            current_exercise = stripped[3:].strip()
            if len(current_exercise) > 150:
                errors.append(f"Zeile {i}: Übungsname zu lang ({len(current_exercise)}/150 Zeichen).")
            current_exercise_desc_lines = []
            current_exercise_meta = {}
            meta_phase = True
            in_plan_description = False
            continue

        # Check for metadata lines (only right after ## header, before description)
        if current_exercise and meta_phase and ':' in stripped and stripped:
            key_part = stripped.split(':', 1)[0].strip().lower()
            if key_part in METADATA_KEYS:
                value_part = stripped.split(':', 1)[1].strip()
                current_exercise_meta[key_part] = value_part
                continue
            elif stripped == '':
                # Empty lines during meta phase are skipped
                continue
            else:
                # Not a metadata line — switch to description phase
                meta_phase = False

        # Empty lines right after ## (during meta phase) are skipped
        if current_exercise and meta_phase and stripped == '':
            continue

        # First non-empty, non-metadata line ends meta phase
        if current_exercise and meta_phase and stripped:
            meta_phase = False

        # Accumulate description lines
        if plan_title and current_exercise is None and in_plan_description:
            plan_description_lines.append(line)
        elif current_exercise:
            current_exercise_desc_lines.append(line)

    # Don't forget the last exercise
    _finish_exercise()

    # Validate required fields
    if not plan_title:
        errors.append("Kein Plantitel gefunden. Beginne mit '# Titel'.")

    real_exercises = [e for e in exercises if not e.get('is_separator')]
    if not real_exercises:
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
