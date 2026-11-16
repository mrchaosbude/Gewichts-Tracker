"""Phase 2: delete own account, full export, import, edit sessions."""
import datetime
import io
import json
import zipfile

import pytest
from flask import g
from werkzeug.security import generate_password_hash

from app import (
    BodyWeight,
    Exercise,
    ExerciseSession,
    PlannedTraining,
    ProgressPhoto,
    TrainingPlan,
    User,
    db,
)

PNG_BYTES = b'\x89PNG\r\n\x1a\n' + b'\x00' * 32


def _login(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = user.get_id()
    g.pop('_login_user', None)


@pytest.fixture()
def owner(app, tmp_path):
    """User with a plan (strength + cardio + separator), sessions, weights, plan day and a photo."""
    app.config['UPLOAD_FOLDER'] = str(tmp_path / 'photos')
    (tmp_path / 'photos').mkdir()
    user = User(username='besitzer', password=generate_password_hash('mein-passwort'), email='b@example.com')
    db.session.add(user)
    db.session.flush()
    plan = TrainingPlan(title='Push', description='Brust', user_id=user.id)
    bench = Exercise(name='Bankdrücken', muscle_group='Brust', video_url='https://example.com/v', user_id=user.id)
    run = Exercise(name='Laufen', exercise_type='ausdauer', user_id=user.id)
    sep = Exercise(name='Finisher', is_separator=True, user_id=user.id)
    db.session.add_all([plan, bench, run, sep])
    db.session.flush()
    plan.exercises.extend([bench, run, sep])
    db.session.flush()
    db.session.execute(db.text('UPDATE plan_exercises SET position = 0, superset_group = 2 WHERE exercise_id = :e'), {'e': bench.id})
    db.session.execute(db.text('UPDATE plan_exercises SET position = 1 WHERE exercise_id = :e'), {'e': run.id})
    db.session.execute(db.text('UPDATE plan_exercises SET position = 2 WHERE exercise_id = :e'), {'e': sep.id})
    t0 = datetime.datetime(2026, 1, 5, 18, 0)
    db.session.add_all([
        ExerciseSession(exercise_id=bench.id, user_id=user.id, weight=62.5, repetitions=8, timestamp=t0, notes='gut', perceived_exertion=8),
        ExerciseSession(exercise_id=bench.id, user_id=user.id, weight=65, repetitions=6, timestamp=t0 + datetime.timedelta(days=2)),
        ExerciseSession(exercise_id=run.id, user_id=user.id, duration_minutes=30, distance_km=5.2, timestamp=t0),
        BodyWeight(user_id=user.id, weight=81.4, timestamp=t0, notes='morgens'),
        PlannedTraining(user_id=user.id, date=datetime.date(2026, 1, 9), label='Pull'),
        ProgressPhoto(user_id=user.id, filename=f'{user.id}_foto.png', timestamp=t0, notes='Start', body_weight=81.4),
    ])
    (tmp_path / 'photos' / f'{user.id}_foto.png').write_bytes(PNG_BYTES)
    db.session.commit()
    return user


def _export_zip(client):
    resp = client.get('/export/full')
    assert resp.status_code == 200
    payload = resp.data
    resp.close()
    return zipfile.ZipFile(io.BytesIO(payload)), payload


class TestFullExport:
    def test_contains_everything(self, client, owner):
        _login(client, owner)
        archive, _ = _export_zip(client)
        data = json.loads(archive.read('data.json'))
        assert data['format'] == 'gewichts-tracker-export' and data['version'] == 1
        assert [p['title'] for p in data['training_plans']] == ['Push']
        by_name = {e['name']: e for e in data['exercises']}
        assert len(by_name['Bankdrücken']['sessions']) == 2
        assert by_name['Bankdrücken']['sessions'][0]['weight'] == 62.5
        assert by_name['Laufen']['sessions'][0]['duration_minutes'] == 30
        assert by_name['Finisher']['is_separator'] is True
        assert data['training_plans'][0]['exercises'][0]['superset_group'] == 2
        assert data['body_weights'][0]['weight'] == 81.4
        assert data['planned_trainings'] == [{'date': '2026-01-09', 'label': 'Pull'}]
        photo_name = data['progress_photos'][0]['file']
        assert archive.read(photo_name) == PNG_BYTES
        assert 'password' not in json.dumps(data)

    def test_requires_login_and_excludes_other_users(self, client, owner, regular_user, sample_plan):
        assert client.get('/export/full').status_code in (302, 401)
        _login(client, owner)
        data = json.loads(_export_zip(client)[0].read('data.json'))
        assert 'Testplan' not in json.dumps(data)


class TestImport:
    def _import(self, client, payload, name='export.zip'):
        return client.post('/account/import', data={'export_file': (io.BytesIO(payload), name)},
                           content_type='multipart/form-data')

    def test_roundtrip_into_other_account(self, client, owner, regular_user):
        _login(client, owner)
        _, payload = _export_zip(client)
        _login(client, regular_user)
        assert self._import(client, payload).status_code == 302

        plan = TrainingPlan.query.filter_by(user_id=regular_user.id).one()
        assert plan.title == 'Push'
        names = {e.name: e for e in plan.exercises}
        assert set(names) == {'Bankdrücken', 'Laufen', 'Finisher'}
        assert names['Bankdrücken'].user_id == regular_user.id
        assert names['Bankdrücken'].video_url == 'https://example.com/v'
        assert names['Laufen'].exercise_type == 'ausdauer'
        sessions = ExerciseSession.query.filter_by(user_id=regular_user.id).order_by(ExerciseSession.timestamp).all()
        assert [(s.weight, s.repetitions, s.duration_minutes) for s in sessions if s.exercise_id == names['Bankdrücken'].id] == [(62.5, 8, None), (65.0, 6, None)]
        assert sessions[0].timestamp == datetime.datetime(2026, 1, 5, 18, 0)
        row = db.session.execute(db.text('SELECT superset_group, position FROM plan_exercises WHERE exercise_id = :e'),
                                 {'e': names['Bankdrücken'].id}).one()
        assert tuple(row) == (2, 0)
        assert BodyWeight.query.filter_by(user_id=regular_user.id).one().weight == 81.4
        assert PlannedTraining.query.filter_by(user_id=regular_user.id).one().label == 'Pull'
        photo = ProgressPhoto.query.filter_by(user_id=regular_user.id).one()
        assert photo.filename.startswith(f'{regular_user.id}_') and photo.filename != f'{owner.id}_foto.png'
        # Daten des ursprünglichen Besitzers sind unberührt
        assert ExerciseSession.query.filter_by(user_id=owner.id).count() == 3

    def test_reimport_does_not_duplicate_weights_and_renames_plan(self, client, owner):
        _login(client, owner)
        _, payload = _export_zip(client)
        self._import(client, payload)
        assert BodyWeight.query.filter_by(user_id=owner.id).count() == 1
        assert PlannedTraining.query.filter_by(user_id=owner.id).count() == 1
        assert ProgressPhoto.query.filter_by(user_id=owner.id).count() == 1
        assert sorted(p.title for p in TrainingPlan.query.filter_by(user_id=owner.id)) == ['Push', 'Push (Import)']

    def test_accepts_old_training_data_json(self, client, owner, regular_user):
        _login(client, owner)
        old_export = client.get('/export/training-data').data
        _login(client, regular_user)
        assert self._import(client, old_export, 'training-data.json').status_code == 302
        assert ExerciseSession.query.filter_by(user_id=regular_user.id).count() == 3

    @pytest.mark.parametrize('data', [
        {'format': 'gewichts-tracker-export', 'version': 99},
        {'training_plans': 'kein-array'},
        {'training_plans': [{'title': 'X', 'exercises': [{'key': 5}]}]},
        {'training_plans': [{'title': 'X', 'exercises': [{'name': 'A', 'sessions': [{'weight': 'abc', 'repetitions': 3}]}]}]},
        {'training_plans': [{'title': 'X', 'exercises': [{'name': 'A', 'sessions': [{'weight': 1e999, 'repetitions': 3}]}]}]},
        {'training_plans': [{'title': 'X', 'exercises': [{'name': 'A', 'exercise_type': 'boese'}]}]},
        {'body_weights': [{'weight': 5000}]},
        {'planned_trainings': [{'date': 'morgen'}]},
        ['keine', 'map'],
    ])
    def test_invalid_data_changes_nothing(self, client, regular_user, data):
        _login(client, regular_user)
        resp = self._import(client, json.dumps(data).encode(), 'x.json')
        assert resp.status_code == 302
        assert TrainingPlan.query.count() == 0 and Exercise.query.count() == 0
        assert ExerciseSession.query.count() == 0 and BodyWeight.query.count() == 0

    def test_unsafe_content_is_neutralised(self, client, app, tmp_path, regular_user):
        app.config['UPLOAD_FOLDER'] = str(tmp_path / 'p')
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as archive:
            archive.writestr('data.json', json.dumps({
                'training_plans': [{'title': 'T', 'exercises': [{'name': 'A', 'video_url': 'javascript:alert(1)'}]}],
                'progress_photos': [
                    {'file': '../../evil.png', 'timestamp': '2026-01-01T10:00:00'},
                    {'file': 'photos/html.png', 'timestamp': '2026-01-02T10:00:00'},
                ],
            }))
            archive.writestr('../../evil.png', PNG_BYTES)
            archive.writestr('photos/html.png', b'<script>alert(1)</script>')
        _login(client, regular_user)
        self._import(client, buf.getvalue())
        # ungültiges Bild -> gesamter Import wird verworfen, nichts landet auf der Platte
        assert Exercise.query.count() == 0 and ProgressPhoto.query.count() == 0
        assert not (tmp_path / 'p').exists() or list((tmp_path / 'p').iterdir()) == []
        assert not (tmp_path / 'evil.png').exists()

    def test_garbage_file(self, client, regular_user):
        _login(client, regular_user)
        assert self._import(client, b'PK\x03\x04kaputt').status_code == 302
        assert self._import(client, b'\xff\xfe kein json', 'x.json').status_code == 302
        assert TrainingPlan.query.count() == 0


class TestDeleteAccount:
    def _delete(self, client, password, username):
        return client.post('/account/delete', data={'del-current_password': password, 'del-confirm_username': username})

    def test_deletes_everything(self, client, app, tmp_path, owner):
        _login(client, owner)
        uid = owner.id
        resp = self._delete(client, 'mein-passwort', 'besitzer')
        assert resp.status_code == 302
        assert db.session.get(User, uid) is None
        for model in (TrainingPlan, Exercise, ExerciseSession, BodyWeight, PlannedTraining, ProgressPhoto):
            assert model.query.count() == 0, model
        assert list((tmp_path / 'photos').iterdir()) == []
        g.pop('_login_user', None)
        assert client.get('/dashboard').status_code in (302, 401)

    @pytest.mark.parametrize('password,username', [('falsch', 'besitzer'), ('mein-passwort', 'anderer')])
    def test_needs_password_and_username(self, client, owner, password, username):
        _login(client, owner)
        assert self._delete(client, password, username).status_code == 400
        assert db.session.get(User, owner.id) is not None

    def test_last_admin_cannot_delete_himself(self, client, owner):
        owner.is_admin = True
        db.session.commit()
        _login(client, owner)
        assert self._delete(client, 'mein-passwort', 'besitzer').status_code == 400
        assert db.session.get(User, owner.id) is not None
        db.session.add(User(username='zweiter', password='x', is_admin=True))
        db.session.commit()
        assert self._delete(client, 'mein-passwort', 'besitzer').status_code == 302

    def test_shared_legacy_exercise_survives(self, client, owner, regular_user):
        shared = Exercise.query.filter_by(name='Bankdrücken').one()
        other_plan = TrainingPlan(title='Fremd', user_id=regular_user.id)
        db.session.add(other_plan)
        other_plan.exercises.append(shared)
        db.session.commit()
        _login(client, owner)
        self._delete(client, 'mein-passwort', 'besitzer')
        assert Exercise.query.filter_by(name='Bankdrücken').count() == 1
        assert Exercise.query.filter_by(name='Laufen').count() == 0

    def test_api_delete(self, client, owner):
        _login(client, owner)
        assert client.delete('/api/account', json={'current_password': 'falsch'}).status_code == 403
        assert client.delete('/api/account', json={'current_password': 'mein-passwort'}).status_code == 200
        assert User.query.count() == 0


class TestEditSession:
    def test_edit_strength_session(self, client, owner):
        _login(client, owner)
        sess = ExerciseSession.query.filter_by(weight=62.5).one()
        assert client.get(f'/session/{sess.id}/edit').status_code == 200
        resp = client.post(f'/session/{sess.id}/edit', data={
            'timestamp': '2026-01-06T07:30', 'weight': '67.5', 'repetitions': '5', 'perceived_exertion': '9', 'notes': ''})
        assert resp.status_code == 302
        sess = db.session.get(ExerciseSession, sess.id)
        assert (sess.weight, sess.repetitions, sess.perceived_exertion, sess.notes) == (67.5, 5, 9, None)
        assert sess.timestamp == datetime.datetime(2026, 1, 6, 7, 30)

    def test_edit_cardio_session(self, client, owner):
        _login(client, owner)
        sess = ExerciseSession.query.filter(ExerciseSession.duration_minutes.isnot(None)).one()
        client.post(f'/session/{sess.id}/edit', data={'timestamp': '2026-01-05T18:00', 'duration_minutes': '45', 'distance_km': ''})
        sess = db.session.get(ExerciseSession, sess.id)
        assert (sess.duration_minutes, sess.distance_km, sess.weight) == (45, None, None)

    @pytest.mark.parametrize('data', [
        {'timestamp': '2026-01-06T07:30', 'weight': '', 'repetitions': '5'},
        {'timestamp': '2026-01-06T07:30', 'weight': '60', 'repetitions': '0'},
        {'timestamp': 'gestern', 'weight': '60', 'repetitions': '5'},
        {'timestamp': '2026-01-06T07:30', 'weight': '60', 'repetitions': '5', 'perceived_exertion': '11'},
    ])
    def test_rejects_invalid(self, client, owner, data):
        _login(client, owner)
        sess = ExerciseSession.query.filter_by(weight=62.5).one()
        assert client.post(f'/session/{sess.id}/edit', data=data).status_code == 200
        assert db.session.get(ExerciseSession, sess.id).repetitions == 8

    def test_foreign_session_is_forbidden(self, client, owner, regular_user):
        sess = ExerciseSession.query.filter_by(weight=62.5).one()
        _login(client, regular_user)
        assert client.get(f'/session/{sess.id}/edit').status_code == 403
        assert client.post(f'/session/{sess.id}/edit', data={'timestamp': '2026-01-06T07:30', 'weight': '1', 'repetitions': '1'}).status_code == 403
        assert client.put(f'/api/sessions/{sess.id}', json={'weight': 1}).status_code == 403
        assert db.session.get(ExerciseSession, sess.id).weight == 62.5

    def test_api_update(self, client, owner):
        _login(client, owner)
        sess = ExerciseSession.query.filter_by(weight=62.5).one()
        resp = client.put(f'/api/sessions/{sess.id}', json={'weight': 70, 'notes': 'neu', 'timestamp': '2026-02-01T10:00:00'})
        assert resp.status_code == 200 and resp.get_json()['weight'] == 70
        assert client.put(f'/api/sessions/{sess.id}', json={'repetitions': None}).status_code == 400
        assert client.put(f'/api/sessions/{sess.id}', json={'weight': 'x'}).status_code == 400
        sess = db.session.get(ExerciseSession, sess.id)
        assert (sess.weight, sess.repetitions, sess.notes) == (70, 8, 'neu')


class TestRequestSizeLimit:
    def test_large_body_only_allowed_for_import(self, client, regular_user):
        _login(client, regular_user)
        big = b'x' * (10 * 1024 * 1024 + 10)
        resp = client.post('/api/login', data=big, content_type='application/json')
        assert resp.status_code == 413
        resp = client.post('/account/import', data={'export_file': (io.BytesIO(big), 'x.json')},
                           content_type='multipart/form-data')
        assert resp.status_code == 302  # angenommen, aber als ungültig abgelehnt


class TestPagesRender:
    def test_account_and_exercise_pages_show_new_controls(self, client, owner):
        _login(client, owner)
        page = client.get('/account').get_data(as_text=True)
        assert '/export/full' in page and '/account/import' in page and '/account/delete' in page
        bench = Exercise.query.filter_by(name='Bankdrücken').one()
        sess = ExerciseSession.query.filter_by(weight=62.5).one()
        detail = client.get(f'/exercise/{bench.id}/detail').get_data(as_text=True)
        assert f'/session/{sess.id}/edit' in detail
