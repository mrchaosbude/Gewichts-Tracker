"""Tests for Markdown-based training plan import functionality."""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import (
    app, db, User, TrainingPlan, Exercise,
    TemplateTrainingPlan, TemplateExercise,
    parse_training_plan_markdown
)
from werkzeug.security import generate_password_hash


class TestMarkdownParser:
    """Unit tests for the parse_training_plan_markdown function."""

    def test_valid_plan_with_exercises(self):
        """Test parsing a valid markdown with title, description, and exercises."""
        content = """# My Training Plan

This is a description.

## Bench Press
Chest exercise with barbell.

## Squat
Leg exercise for strength.
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is True
        assert result['plan_title'] == 'My Training Plan'
        assert result['plan_description'] == 'This is a description.'
        assert len(result['exercises']) == 2
        assert result['exercises'][0]['name'] == 'Bench Press'
        assert result['exercises'][0]['description'] == 'Chest exercise with barbell.'
        assert result['exercises'][1]['name'] == 'Squat'
        assert result['exercises'][1]['description'] == 'Leg exercise for strength.'
        assert len(result['errors']) == 0

    def test_multiline_exercise_description(self):
        """Test that all content under H2 until next H2 is captured."""
        content = """# Plan

## Exercise
First line
Second line
- List item 1
- List item 2

Another paragraph

## Next Exercise
Simple description
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is True
        assert len(result['exercises']) == 2
        expected_desc = """First line
Second line
- List item 1
- List item 2

Another paragraph"""
        assert result['exercises'][0]['description'] == expected_desc
        assert result['exercises'][1]['description'] == 'Simple description'

    def test_missing_title_fails(self):
        """Test that missing H1 title causes failure."""
        content = """## Exercise Only
No plan title here.
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is False
        assert any('Kein Plantitel' in e for e in result['errors'])

    def test_no_exercises_fails(self):
        """Test that having no exercises causes failure."""
        content = """# Plan Title
Description only.
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is False
        assert any('Keine Übungen' in e for e in result['errors'])

    def test_title_too_long_warns(self):
        """Test that overly long title is flagged."""
        long_title = 'A' * 200
        content = f"""# {long_title}

## Exercise
Desc.
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is False
        assert any('Plantitel zu lang' in e for e in result['errors'])

    def test_description_too_long_truncated(self):
        """Test that overly long description is truncated."""
        long_desc = 'B' * 400
        content = f"""# Plan

{long_desc}

## Exercise
Short desc.
"""
        result = parse_training_plan_markdown(content)
        # Should still succeed but with warning
        assert any('Planbeschreibung zu lang' in e for e in result['errors'])
        assert len(result['plan_description']) == 300

    def test_exercise_description_too_long_truncated(self):
        """Test that overly long exercise description is truncated."""
        long_desc = 'C' * 400
        content = f"""# Plan

## Exercise
{long_desc}
"""
        result = parse_training_plan_markdown(content)
        assert any('Beschreibung zu lang' in e for e in result['errors'])
        assert len(result['exercises'][0]['description']) == 300

    def test_multiple_h1_titles_error(self):
        """Test that multiple H1 headers cause an error."""
        content = """# First Title

## Exercise 1
Desc

# Second Title

## Exercise 2
Desc
"""
        result = parse_training_plan_markdown(content)
        assert any('Mehrere H1-Überschriften' in e for e in result['errors'])

    def test_empty_content(self):
        """Test that empty content fails gracefully."""
        result = parse_training_plan_markdown('')
        assert result['success'] is False
        assert any('Kein Plantitel' in e for e in result['errors'])

    def test_plan_without_description(self):
        """Test plan with title and exercises but no description."""
        content = """# My Plan

## Exercise 1
Description 1
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is True
        assert result['plan_title'] == 'My Plan'
        assert result['plan_description'] == ''
        assert len(result['exercises']) == 1

    def test_exercise_without_description(self):
        """Test exercise with name but no description."""
        content = """# My Plan

## Exercise 1

## Exercise 2
Has description
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is True
        assert result['exercises'][0]['description'] == ''
        assert result['exercises'][1]['description'] == 'Has description'

    def test_muscle_group_metadata(self):
        """Test parsing Muskelgruppe metadata from exercise."""
        content = """# Plan

## Bench Press
Muskelgruppe: Brust
Chest exercise.
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is True
        assert result['exercises'][0]['muscle_group'] == 'Brust'
        assert result['exercises'][0]['description'] == 'Chest exercise.'

    def test_exercise_type_metadata(self):
        """Test parsing Typ (exercise_type) metadata."""
        content = """# Plan

## Laufen
Typ: ausdauer
30 Minuten joggen.
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is True
        assert result['exercises'][0]['exercise_type'] == 'ausdauer'
        assert result['exercises'][0]['description'] == '30 Minuten joggen.'

    def test_youtube_metadata(self):
        """Test parsing YouTube URL metadata."""
        content = """# Plan

## Squat
YouTube: https://youtube.com/watch?v=abc123
Heavy squats.
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is True
        assert result['exercises'][0]['video_url'] == 'https://youtube.com/watch?v=abc123'
        assert result['exercises'][0]['description'] == 'Heavy squats.'

    def test_all_metadata_combined(self):
        """Test parsing all metadata fields together."""
        content = """# Plan

## Bankdrücken
Muskelgruppe: Brust
Typ: kraft
YouTube: https://youtube.com/watch?v=xyz
Klassische Brustübung.
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is True
        ex = result['exercises'][0]
        assert ex['muscle_group'] == 'Brust'
        assert ex['exercise_type'] == 'kraft'
        assert ex['video_url'] == 'https://youtube.com/watch?v=xyz'
        assert ex['description'] == 'Klassische Brustübung.'

    def test_no_metadata_defaults_empty(self):
        """Test that exercises without metadata have empty metadata fields."""
        content = """# Plan

## Simple Exercise
Just a description.
"""
        result = parse_training_plan_markdown(content)
        assert result['success'] is True
        ex = result['exercises'][0]
        assert ex['muscle_group'] == ''
        assert ex['exercise_type'] == ''
        assert ex['video_url'] == ''
        assert ex['description'] == 'Just a description.'


@pytest.fixture
def client():
    """Set up test client with in-memory database."""
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
        WTF_CSRF_ENABLED=False,
    )
    with app.app_context():
        db.drop_all()
        db.create_all()
        user = User(username='tester', password=generate_password_hash('secret'))
        admin = User(username='admin', password=generate_password_hash('admin'), is_admin=True)
        db.session.add(user)
        db.session.add(admin)
        db.session.commit()

    with app.test_client() as test_client:
        yield test_client


def login(client, username, password):
    """Helper to log in a user."""
    return client.post('/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)


def test_import_creates_plan_and_exercises(client):
    """Test that import creates a training plan with exercises."""
    login(client, 'tester', 'secret')

    markdown = """# Imported Plan

Test description

## Exercise A
First exercise

## Exercise B
Second exercise
"""
    response = client.post('/import_training_plan', data={
        'markdown_content': markdown,
        'action': 'import'
    }, follow_redirects=True)
    assert response.status_code == 200

    with app.app_context():
        plan = TrainingPlan.query.filter_by(title='Imported Plan').first()
        assert plan is not None
        assert plan.description == 'Test description'
        assert len(plan.exercises) == 2

        # Check exercises belong to the user
        user = User.query.filter_by(username='tester').first()
        for ex in plan.exercises:
            assert ex.user_id == user.id


def test_import_preview_does_not_create(client):
    """Test that preview action does not create any records."""
    login(client, 'tester', 'secret')

    markdown = """# Preview Plan

## Exercise
Desc
"""
    response = client.post('/import_training_plan', data={
        'markdown_content': markdown,
        'action': 'preview'
    })
    assert response.status_code == 200
    assert b'Preview Plan' in response.data

    with app.app_context():
        plan = TrainingPlan.query.filter_by(title='Preview Plan').first()
        assert plan is None


def test_import_validation_errors_shown(client):
    """Test that validation errors are shown to user."""
    login(client, 'tester', 'secret')

    # Missing title and exercises
    markdown = """Just some text without headers"""
    response = client.post('/import_training_plan', data={
        'markdown_content': markdown,
        'action': 'import'
    })
    assert response.status_code == 200
    assert b'Kein Plantitel' in response.data or b'Keine' in response.data


def test_template_import_requires_admin_or_trainer(client):
    """Test that template import is protected."""
    login(client, 'tester', 'secret')

    response = client.get('/admin/template_plan/import')
    assert response.status_code == 403


def test_admin_can_import_template(client):
    """Test that admin can import templates."""
    login(client, 'admin', 'admin')

    markdown = """# Template Plan

Template description

## Template Exercise
Exercise in template
"""
    response = client.post('/admin/template_plan/import', data={
        'markdown_content': markdown,
        'action': 'import'
    }, follow_redirects=True)
    assert response.status_code == 200

    with app.app_context():
        template = TemplateTrainingPlan.query.filter_by(title='Template Plan').first()
        assert template is not None
        assert len(template.exercises) == 1
        assert template.exercises[0].name == 'Template Exercise'


def test_each_user_gets_own_exercises(client):
    """Test that each user importing gets their own exercise copies."""
    # First user imports
    login(client, 'tester', 'secret')

    markdown = """# Shared Style Plan

## Common Exercise
Everyone gets their own copy
"""
    client.post('/import_training_plan', data={
        'markdown_content': markdown,
        'action': 'import'
    }, follow_redirects=True)

    # Check first user's data
    with app.app_context():
        user1 = User.query.filter_by(username='tester').first()
        plan1 = TrainingPlan.query.filter_by(user_id=user1.id, title='Shared Style Plan').first()
        assert plan1 is not None
        assert plan1.exercises[0].user_id == user1.id

    # Admin imports same plan
    login(client, 'admin', 'admin')
    client.post('/import_training_plan', data={
        'markdown_content': markdown,
        'action': 'import'
    }, follow_redirects=True)

    with app.app_context():
        user2 = User.query.filter_by(username='admin').first()
        plan2 = TrainingPlan.query.filter_by(user_id=user2.id, title='Shared Style Plan').first()
        assert plan2 is not None
        assert plan2.exercises[0].user_id == user2.id

        # Verify exercises are separate
        assert plan1.exercises[0].id != plan2.exercises[0].id
