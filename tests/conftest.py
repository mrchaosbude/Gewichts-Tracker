"""Shared test fixtures for all test modules."""
import pytest
from werkzeug.security import generate_password_hash
from app import app as flask_app, db, limiter, User, TrainingPlan, Exercise, ExerciseSession, BodyWeight


@pytest.fixture()
def app():
    """Create application for testing."""
    flask_app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI='sqlite://',
        WTF_CSRF_ENABLED=False,
        WTF_CSRF_CHECK_DEFAULT=False,
        SERVER_NAME='localhost',
        RATELIMIT_ENABLED=False,
    )
    limiter.enabled = False
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    """Test client."""
    return app.test_client()


@pytest.fixture()
def regular_user(app):
    """Create a regular (non-admin, non-trainer) user."""
    user = User(username='user', password=generate_password_hash('pass123'))
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def admin_user(app):
    """Create an admin user."""
    user = User(username='admin', password=generate_password_hash('admin123'), is_admin=True)
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def trainer_user(app):
    """Create a trainer user."""
    user = User(username='trainer', password=generate_password_hash('trainer123'), is_trainer=True)
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def logged_in_client(client, regular_user):
    """Client logged in as regular user."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(regular_user.id)
    return client


@pytest.fixture()
def admin_client(client, admin_user):
    """Client logged in as admin."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(admin_user.id)
    return client


@pytest.fixture()
def trainer_client(client, trainer_user):
    """Client logged in as trainer."""
    with client.session_transaction() as sess:
        sess['_user_id'] = str(trainer_user.id)
    return client


@pytest.fixture()
def sample_plan(app, regular_user):
    """Create a training plan with exercises and sessions."""
    plan = TrainingPlan(title='Testplan', description='Beschreibung', user_id=regular_user.id)
    db.session.add(plan)
    db.session.flush()

    exercise = Exercise(name='Bankdrücken', description='Brust', muscle_group='Brust', user_id=regular_user.id)
    db.session.add(exercise)
    db.session.flush()
    plan.exercises.append(exercise)

    cardio = Exercise(name='Laufen', exercise_type='ausdauer', user_id=regular_user.id)
    db.session.add(cardio)
    db.session.flush()
    plan.exercises.append(cardio)

    import datetime
    for i in range(3):
        s = ExerciseSession(
            exercise_id=exercise.id,
            weight=60 + i * 5,
            repetitions=10,
            user_id=regular_user.id,
            timestamp=datetime.datetime.utcnow() - datetime.timedelta(days=i),
        )
        db.session.add(s)

    db.session.commit()
    return plan
