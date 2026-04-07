"""Tests for progress photo upload validation."""
import io

from app import ProgressPhoto


class TestProgressPhotos:
    def test_progress_photo_invalid_body_weight(self, logged_in_client, app, tmp_path, regular_user):
        app.config['UPLOAD_FOLDER'] = str(tmp_path)
        resp = logged_in_client.post(
            '/progress_photos',
            data={
                'photo': (io.BytesIO(b'fake-image'), 'progress.jpg'),
                'body_weight': 'abc',
            },
            content_type='multipart/form-data',
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert ProgressPhoto.query.filter_by(user_id=regular_user.id).count() == 0
        assert list(tmp_path.iterdir()) == []
