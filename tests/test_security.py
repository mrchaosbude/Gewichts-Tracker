"""Regression tests for the security fixes (private photos, URL scheme checks, account deletion)."""
import io

import pytest
from flask import g
from werkzeug.security import generate_password_hash

from app import (
    BodyWeight,
    Exercise,
    ExerciseSession,
    ProgressPhoto,
    TrainingPlan,
    User,
    db,
    limiter,
    migrate_legacy_photo_uploads,
    parse_training_plan_markdown,
    sanitize_external_url,
)

PNG_BYTES = b'\x89PNG\r\n\x1a\n' + b'\x00' * 32


def _login(client, user):
    with client.session_transaction() as sess:
        sess['_user_id'] = user.get_id()
    # Die app-Fixture hält einen App-Kontext offen; Flask-Login cached den User in g.
    g.pop('_login_user', None)


def _upload(client, data=PNG_BYTES, name='progress.png'):
    return client.post(
        '/progress_photos',
        data={'photo': (io.BytesIO(data), name)},
        content_type='multipart/form-data',
        follow_redirects=True,
    )


class TestSanitizeUrl:
    @pytest.mark.parametrize('url', [
        'javascript:alert(1)',
        'JaVaScRiPt:alert(1)',
        'javascript://example.com/%0aalert(1)',
        'data:text/html,<script>alert(1)</script>',
        'vbscript:msgbox(1)',
        ' java\tscript:alert(1)',
        'https://exa mple.com',
        '//evil.example',
        'youtube.com/watch?v=1',
        '',
        None,
        123,
    ])
    def test_rejects_unsafe(self, url):
        assert sanitize_external_url(url) is None

    @pytest.mark.parametrize('url', ['https://youtube.com/watch?v=abc', 'http://example.com/a?b=c#d'])
    def test_accepts_http(self, url):
        assert sanitize_external_url(url) == url

    def test_relative_only_when_allowed(self):
        assert sanitize_external_url('/page/1') is None
        assert sanitize_external_url('/page/1', allow_relative=True) == '/page/1'
        assert sanitize_external_url('//evil.example', allow_relative=True) is None
        assert sanitize_external_url('/\\evil.example', allow_relative=True) is None


class TestVideoUrlXss:
    def test_form_rejects_javascript_url(self, logged_in_client, sample_plan):
        resp = logged_in_client.post(
            f'/training_plan/{sample_plan.id}/add_exercise',
            data={'name': 'Böse Übung', 'exercise_type': 'kraft', 'video_url': 'javascript:alert(document.cookie)'},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert Exercise.query.filter_by(name='Böse Übung').first() is None

    def test_form_accepts_https_url(self, logged_in_client, sample_plan):
        logged_in_client.post(
            f'/training_plan/{sample_plan.id}/add_exercise',
            data={'name': 'Gute Übung', 'exercise_type': 'kraft', 'video_url': 'https://youtube.com/watch?v=1'},
        )
        assert Exercise.query.filter_by(name='Gute Übung').one().video_url == 'https://youtube.com/watch?v=1'

    def test_stored_javascript_url_is_not_rendered(self, logged_in_client, sample_plan):
        exercise = sample_plan.exercises[0]
        exercise.video_url = 'javascript:alert(1)'  # Altbestand in der DB
        db.session.commit()
        resp = logged_in_client.get(f'/exercise/{exercise.id}/detail')
        assert resp.status_code == 200
        assert b'javascript:alert' not in resp.data

    def test_shared_plan_copy_drops_javascript_url(self, client, sample_plan, admin_user):
        sample_plan.exercises[0].video_url = 'javascript:alert(1)'
        sample_plan.share_token = 'tok-123'
        db.session.commit()
        _login(client, admin_user)
        resp = client.post('/shared/tok-123')
        assert resp.status_code == 302
        copied = TrainingPlan.query.filter_by(user_id=admin_user.id).one()
        assert all(ex.video_url is None for ex in copied.exercises)

    def test_markdown_import_flags_javascript_url(self):
        parsed = parse_training_plan_markdown('# Plan\n\n## Übung\nYoutube: javascript:alert(1)\n')
        assert parsed['success'] is False
        assert parsed['exercises'][0]['video_url'] == ''


class TestPrivateProgressPhotos:
    def test_photo_not_reachable_without_login_or_as_other_user(self, client, app, tmp_path, regular_user, admin_user):
        app.config['UPLOAD_FOLDER'] = str(tmp_path)
        _login(client, regular_user)
        assert _upload(client).status_code == 200
        photo = ProgressPhoto.query.filter_by(user_id=regular_user.id).one()

        owner = client.get(f'/progress_photos/{photo.id}/file')
        assert owner.status_code == 200
        assert owner.data == PNG_BYTES
        assert 'no-store' in owner.headers['Cache-Control']
        owner.close()

        # Der alte öffentliche Pfad liefert nichts mehr
        assert client.get(f'/static/uploads/photos/{photo.filename}').status_code == 404

        _login(client, admin_user)  # selbst ein Admin ist nicht der Besitzer
        assert client.get(f'/progress_photos/{photo.id}/file').status_code == 404

        anon = app.test_client()
        g.pop('_login_user', None)
        assert anon.get(f'/progress_photos/{photo.id}/file').status_code in (302, 401)

    def test_filename_is_unguessable_and_api_url_is_private(self, logged_in_client, app, tmp_path, regular_user):
        app.config['UPLOAD_FOLDER'] = str(tmp_path)
        resp = logged_in_client.post(
            '/api/progress_photos',
            data={'photo': (io.BytesIO(PNG_BYTES), 'x.png')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 201
        body = resp.get_json()
        assert body['url'] == f"/progress_photos/{body['id']}/file"
        random_part = body['filename'].split('_', 1)[1].split('.')[0]
        assert len(random_part) == 32
        listing = logged_in_client.get('/api/progress_photos').get_json()
        assert listing[0]['url'] == body['url']

    def test_rejects_non_image_content(self, logged_in_client, app, tmp_path, regular_user):
        app.config['UPLOAD_FOLDER'] = str(tmp_path)
        _upload(logged_in_client, data=b'<html><script>alert(1)</script></html>', name='evil.png')
        assert ProgressPhoto.query.count() == 0
        assert list(tmp_path.iterdir()) == []
        resp = logged_in_client.post(
            '/api/progress_photos',
            data={'photo': (io.BytesIO(b'not an image'), 'evil.jpg')},
            content_type='multipart/form-data',
        )
        assert resp.status_code == 400

    def test_legacy_photos_are_moved_out_of_static(self, app, tmp_path):
        legacy = tmp_path / 'static_uploads'
        target = tmp_path / 'private'
        legacy.mkdir()
        (legacy / '1_abcd1234.jpg').write_bytes(b'\xff\xd8\xff')
        (legacy / 'notes.txt').write_text('bleibt liegen')
        assert migrate_legacy_photo_uploads(str(legacy), str(target)) == 1
        assert (target / '1_abcd1234.jpg').exists()
        assert not (legacy / '1_abcd1234.jpg').exists()
        assert (legacy / 'notes.txt').exists()


class TestAccountDeletion:
    def test_admin_delete_removes_personal_data(self, admin_client, app, tmp_path, regular_user, sample_plan):
        app.config['UPLOAD_FOLDER'] = str(tmp_path)
        uid = regular_user.id
        (tmp_path / f'{uid}_x.png').write_bytes(PNG_BYTES)
        db.session.add(ProgressPhoto(user_id=uid, filename=f'{uid}_x.png'))
        db.session.add(BodyWeight(user_id=uid, weight=80))
        db.session.commit()
        assert ExerciseSession.query.filter_by(user_id=uid).count() == 3

        resp = admin_client.post(f'/admin/user/{uid}/delete')
        assert resp.status_code == 302
        assert db.session.get(User, uid) is None
        assert ProgressPhoto.query.filter_by(user_id=uid).count() == 0
        assert BodyWeight.query.filter_by(user_id=uid).count() == 0
        assert ExerciseSession.query.filter_by(user_id=uid).count() == 0
        assert list(tmp_path.iterdir()) == []


class TestApiAuthHardening:
    def test_api_login_is_rate_limited(self, client, app):
        db.session.add(User(username='victim', password=generate_password_hash('correct-horse')))
        db.session.commit()
        limiter.enabled = True
        limiter.reset()
        try:
            codes = [
                client.post('/api/login', json={'username': 'victim', 'password': f'wrong{i}'}).status_code
                for i in range(12)
            ]
        finally:
            limiter.reset()
            limiter.enabled = False
        assert codes[:10] == [401] * 10
        assert codes[10:] == [429, 429]

    def test_api_login_non_string_password_is_not_a_500(self, client, regular_user):
        resp = client.post('/api/login', json={'username': 'user', 'password': 12345})
        assert resp.status_code == 401

    def test_security_headers_present(self, client):
        resp = client.get('/login')
        assert resp.headers['X-Content-Type-Options'] == 'nosniff'
        assert resp.headers['X-Frame-Options'] == 'SAMEORIGIN'
